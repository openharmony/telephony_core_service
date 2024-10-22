/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tel_event_queue.h"

#include "tel_event_handler.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
enum class TelPriority : uint32_t { IMMEDIATE = 0, HIGH, LOW };
}

TelEventQueue::TelEventQueue(const std::string &name) : name_(name)
{
    TELEPHONY_LOGI("%{public}s create", name_.c_str());
    name_ = std::string(name_.c_str());
    queue_ = std::make_shared<ffrt::queue>(name_.c_str());
}

TelEventQueue::~TelEventQueue()
{
    TELEPHONY_LOGI("%{public}s destroy", name_.c_str());
    RemoveAllEvents();
    ClearCurrentTask(true);
    if (!queue_) {
        return;
    }
    if (!curTask_) {
        return;
    }
    TELEPHONY_LOGD("%{public}s need to wait", name_.c_str());
    queue_->wait(curTask_);
    curTask_ = ffrt::task_handle();
    queue_ = nullptr;
}

AppExecFwk::InnerEvent::TimePoint TelEventQueue::GetCurHandleTime()
{
    std::lock_guard<std::mutex> lock(memberCtx_);
    return curHandleTime_;
}

void TelEventQueue::SetCurHandleTime(AppExecFwk::InnerEvent::TimePoint handleTime)
{
    std::lock_guard<std::mutex> lock(memberCtx_);
    curHandleTime_ = handleTime;
}

void TelEventQueue::Submit(AppExecFwk::InnerEvent::Pointer &event, AppExecFwk::EventQueue::Priority priority)
{
    InsertEventsInner(event, priority);
    if (GetHandleTime() < GetCurHandleTime()) {
        GetNextQueueId();
        ClearCurrentTask(false);
        SubmitInner(queueId_.load());
    }
}

uint32_t TelEventQueue::ToTelPriority(AppExecFwk::EventQueue::Priority priority)
{
    if (priority == AppExecFwk::EventQueue::Priority::IMMEDIATE) {
        return static_cast<uint32_t>(TelPriority::IMMEDIATE);
    }
    if (priority == AppExecFwk::EventQueue::Priority::HIGH) {
        return static_cast<uint32_t>(TelPriority::HIGH);
    }
    return static_cast<uint32_t>(TelPriority::LOW);
}

void TelEventQueue::InsertEventsInner(AppExecFwk::InnerEvent::Pointer &event, AppExecFwk::EventQueue::Priority priority)
{
    if (event == nullptr) {
        return;
    }
    std::unique_lock<std::mutex> lock(eventCtx_);
    auto &events = eventLists_[ToTelPriority(priority)].events;
    auto f = [](const AppExecFwk::InnerEvent::Pointer &first, const AppExecFwk::InnerEvent::Pointer &second) {
        if (!first || !second) {
            return false;
        }
        return first->GetHandleTime() < second->GetHandleTime();
    };
    auto it = std::upper_bound(events.begin(), events.end(), event, f);
    auto innerEventId = event->GetInnerEventId();
    events.insert(it, std::move(event));
    eventStats_.CalculationInsertQueueEvents();
    eventStats_.PrintEventStats(name_);
    TELEPHONY_LOGD(
        "%{public}s InsertEventsInner eventId %{public}d finish", name_.c_str(), static_cast<int32_t>(innerEventId));
}

void TelEventQueue::ClearCurrentTask(bool isNeedEnd)
{
    std::lock_guard<std::mutex> lock(taskCtx_);
    if (!curTask_ || !queue_) {
        return;
    }
    queue_->cancel(curTask_);
    if (isNeedEnd) {
        GetNextQueueId();
        return;
    }
    curTask_ = ffrt::task_handle();
    TELEPHONY_LOGD("%{public}s cancel current task", name_.c_str());
}

void TelEventQueue::SubmitInner(int32_t queueId)
{
    if (!queue_) {
        TELEPHONY_LOGE("%{public}s queue is nullptr", name_.c_str());
        return;
    }
    auto handleTime = GetHandleTime();
    if (handleTime == AppExecFwk::InnerEvent::TimePoint::max()) {
        TELEPHONY_LOGD("%{public}s SubmitInner has no task", name_.c_str());
        return;
    }
    int64_t delayTime = 0;
    AppExecFwk::InnerEvent::TimePoint now = AppExecFwk::InnerEvent::Clock::now();
    if (handleTime > now) {
        delayTime = std::chrono::duration_cast<std::chrono::microseconds>(handleTime - now).count();
    }
    SubmitToFFRT(queueId, handleTime, delayTime);
}

int32_t TelEventQueue::GetNextQueueId()
{
    if (queueId_ >= INT32_MAX) {
        queueId_ = 1;
    }
    return queueId_++;
}

void TelEventQueue::SubmitToFFRT(int32_t queueId, AppExecFwk::InnerEvent::TimePoint handleTime, int64_t delayTime)
{
    std::lock_guard<std::mutex> lock(taskCtx_);
    if (queueId != queueId_.load()) {
        TELEPHONY_LOGD("%{public}s task no need to submit", name_.c_str());
        SetCurHandleTime(AppExecFwk::InnerEvent::TimePoint::max());
        return;
    }
    SetCurHandleTime(handleTime);
    curTask_ = queue_->submit_h(
        [this, queueId = queueId]() {
            bool isNeedSubmit = true;
            auto event = PopEvent(queueId, isNeedSubmit);
            std::shared_ptr<TelEventHandler> handler = nullptr;
            if (event) {
                handler = std::static_pointer_cast<TelEventHandler>(event->GetOwner());
            }
            if (event && handler) {
                TELEPHONY_LOGD("%{public}s ProcessEvent eventId %{public}d", name_.c_str(),
                    static_cast<uint32_t>(event->GetInnerEventId()));
                handler->ProcessEvent(event);
            }
            if (!isNeedSubmit) {
                TELEPHONY_LOGD("%{public}s task no need to submit", name_.c_str());
                return;
            }
            SubmitInner(queueId);
        },
        ffrt::task_attr().delay(delayTime));
}

void TelEventQueue::RemoveEvent(uint32_t innerEventId)
{
    std::lock_guard<std::mutex> lock(eventCtx_);
    auto filter = [innerEventId](const AppExecFwk::InnerEvent::Pointer &p) {
        if (p == nullptr) {
            return false;
        }
        return p->GetInnerEventId() == innerEventId;
    };
    for (uint32_t i = 0; i < EVENT_QUEUE_NUM; ++i) {
        eventLists_[i].events.remove_if(filter);
    }
    if (IsEmpty()) {
        SetCurHandleTime(AppExecFwk::InnerEvent::TimePoint::max());
    }
    eventStats_.CalculationRemovedEvents(1);
    TELEPHONY_LOGD("%{public}s remove eventId %{public}d finish", name_.c_str(), innerEventId);
}

bool TelEventQueue::HasInnerEvent(uint32_t innerEventId)
{
    std::lock_guard<std::mutex> lock(eventCtx_);
    auto filter = [innerEventId](
                      const AppExecFwk::InnerEvent::Pointer &p) { return p->GetInnerEventId() == innerEventId; };
    for (uint32_t i = 0; i < EVENT_QUEUE_NUM; ++i) {
        std::list<AppExecFwk::InnerEvent::Pointer>::iterator iter =
            std::find_if(eventLists_[i].events.begin(), eventLists_[i].events.end(), filter);
        if (iter != eventLists_[i].events.end()) {
            return true;
        }
    }
    return false;
}

void TelEventQueue::RemoveAllEvents()
{
    std::lock_guard<std::mutex> lock(eventCtx_);
    int removeCount = 0;
    for (uint32_t i = 0; i < EVENT_QUEUE_NUM; ++i) {
        removeCount += eventLists_[i].events.size();
        eventLists_[i].events.clear();
    }
    SetCurHandleTime(AppExecFwk::InnerEvent::TimePoint::max());
    eventStats_.CalculationRemovedEvents(removeCount);
    TELEPHONY_LOGD("%{public}s RemoveAllEvents finish", name_.c_str());
}

bool TelEventQueue::IsEmpty()
{
    for (uint32_t i = 0; i < EVENT_QUEUE_NUM; ++i) {
        if (!eventLists_[i].events.empty()) {
            return false;
        }
    }
    return true;
}

AppExecFwk::InnerEvent::Pointer TelEventQueue::PopEvent(int32_t queueId, bool &isNeedSubmit)
{
    std::lock_guard<std::mutex> lock(eventCtx_);
    if (IsEmpty() || queueId != queueId_.load()) {
        isNeedSubmit = false;
        SetCurHandleTime(AppExecFwk::InnerEvent::TimePoint::max());
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    uint32_t priorityIndex = GetPriorityIndex();
    AppExecFwk::InnerEvent::Pointer event = std::move(eventLists_[priorityIndex].events.front());
    eventLists_[priorityIndex].events.pop_front();
    eventStats_.CalculationSubmitToFFRTEvents();
    if (IsEmpty()) {
        isNeedSubmit = false;
        SetCurHandleTime(AppExecFwk::InnerEvent::TimePoint::max());
    }
    return event;
}

AppExecFwk::InnerEvent::TimePoint TelEventQueue::GetHandleTime()
{
    std::lock_guard<std::mutex> lock(eventCtx_);
    if (IsEmpty()) {
        return AppExecFwk::InnerEvent::TimePoint::max();
    }
    return eventLists_[GetPriorityIndex()].events.front()->GetHandleTime();
}

uint32_t TelEventQueue::GetPriorityIndex()
{
    AppExecFwk::InnerEvent::TimePoint now = AppExecFwk::InnerEvent::Clock::now();
    AppExecFwk::InnerEvent::TimePoint needWakeUpTime = AppExecFwk::InnerEvent::TimePoint::max();
    uint32_t priorityIndex = 0;
    for (uint32_t i = 0; i < EVENT_QUEUE_NUM; ++i) {
        if (eventLists_[i].events.empty()) {
            continue;
        }
        auto handleTime = eventLists_[i].events.front()->GetHandleTime();
        if (handleTime <= now) {
            priorityIndex = i;
            break;
        }
        if (handleTime < needWakeUpTime) {
            needWakeUpTime = handleTime;
            priorityIndex = i;
        }
    }
    return priorityIndex;
}

void TelEventQueue::EventStats::CalculationInsertQueueEvents()
{
    if (totalHandledEvents >= INT32_MAX) {
        totalHandledEvents = 0;
    }
    if (currentQueueEvents >= INT32_MAX) {
        currentQueueEvents = 0;
    }
    totalHandledEvents++;
    currentQueueEvents++;
}

void TelEventQueue::EventStats::CalculationSubmitToFFRTEvents()
{
    if (submitedToFFRTEvents >= INT32_MAX) {
        submitedToFFRTEvents = 0;
    }
    if (crruentQueueEvents <= 0) {
        currentQueueEvents = 1;
    }
    submitedToFFRTEvents++;
    currentQueueEvents--;
}

void TelEventQueue::EventStats::CalculationRemovedEvents(int count)
{
    if (removedEvents + count >= INT32_MAX) {
        removedEvents = 0;
    }
    removedEvents += count;
}

void TelEventQueue::EventStats::PrintEventStats(std::string &name)
{
    AppExecFwk::InnerEvent::TimePoint now = AppExecFwk::InnerEvent::Clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - lastPrintTime_);
    if (duration.count() < PRINT_INTELVAL_MINUTES) {
        return;
    }
    lastPrintTime_ = now;
    TELEPHONY_LOGI(
        "%{public}s, totalHandled %{public}d, currentQueue %{public}d, submitedToFFRT %{public}d, removed %{public}d",
        name_.c_str(),
        totalHandledEvents.load(),
        currentQueueEvents.load(),
        submitedToFFRTEvents.load(),
        removedEvents.load()
    );
}

} // namespace Telephony
} // namespace OHOS