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

void TelEventQueue::Submit(AppExecFwk::InnerEvent::Pointer &event, AppExecFwk::EventQueue::Priority priority)
{
    InsertEventsInner(event, priority);
    if (GetHandleTime() != curHandleTime_) {
        queueId_++;
        ClearCurrentTask();
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
    TELEPHONY_LOGD(
        "%{public}s InsertEventsInner eventId %{public}d finish", name_.c_str(), static_cast<int32_t>(innerEventId));
}

void TelEventQueue::ClearCurrentTask()
{
    if (!curTask_ || !queue_) {
        return;
    }
    TELEPHONY_LOGI("%{public}s cancel current task", name_.c_str());
    queue_->cancel(curTask_);
    curTask_ = ffrt::task_handle();
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
    auto innerEventId = static_cast<uint32_t>(GetEvent()->GetInnerEventId());
    if (queueId != queueId_.load()) {
        TELEPHONY_LOGD("%{public}s task no need to submit", name_.c_str());
        return;
    }
    curHandleTime_ = handleTime;
    curTask_ = queue_->submit_h(
        [this, queueId = queueId, innerEventId = innerEventId]() {
            if (queueId != queueId_.load()) {
                TELEPHONY_LOGD("%{public}s task no need to process", name_.c_str());
                return;
            }
            auto event = PopEvent();
            if (!event || event->GetOwner() == nullptr) {
                TELEPHONY_LOGE("%{public}s handler not exit", name_.c_str());
                SubmitInner(queueId);
                return;
            }
            TELEPHONY_LOGD(
                "%{public}s ProcessEvent eventId %{public}d", name_.c_str(), static_cast<uint32_t>(innerEventId));
            static_cast<TelEventHandler *>(event->GetOwner().get())->ProcessEvent(event);
            SubmitInner(queueId);
        },
        ffrt::task_attr().delay(delayTime));
    TELEPHONY_LOGD("%{public}s SubmitInner eventId %{public}u delayTime %{public}d finish", name_.c_str(), innerEventId,
        static_cast<int32_t>(delayTime));
}

void TelEventQueue::RemoveEvent(uint32_t innerEventId)
{
    std::lock_guard<std::mutex> lock(eventCtx_);
    auto filter = [innerEventId](
                      const AppExecFwk::InnerEvent::Pointer &p) { return p->GetInnerEventId() == innerEventId; };
    for (uint32_t i = 0; i < EVENT_QUEUE_NUM; ++i) {
        eventLists_[i].events.remove_if(filter);
    }
    if (IsEmpty()) {
        curHandleTime_ = AppExecFwk::InnerEvent::TimePoint::max();
    }
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
    for (uint32_t i = 0; i < EVENT_QUEUE_NUM; ++i) {
        eventLists_[i].events.clear();
    }
    curHandleTime_ = AppExecFwk::InnerEvent::TimePoint::max();
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

AppExecFwk::InnerEvent::Pointer TelEventQueue::PopEvent()
{
    std::lock_guard<std::mutex> lock(eventCtx_);
    if (IsEmpty()) {
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    uint32_t priorityIndex = GetPriorityIndex();
    AppExecFwk::InnerEvent::Pointer event = std::move(eventLists_[priorityIndex].events.front());
    eventLists_[priorityIndex].events.pop_front();
    return event;
}

AppExecFwk::InnerEvent::Pointer &TelEventQueue::GetEvent()
{
    std::lock_guard<std::mutex> lock(eventCtx_);
    if (IsEmpty()) {
        return nullPointer_;
    }
    return eventLists_[GetPriorityIndex()].events.front();
}

AppExecFwk::InnerEvent::TimePoint TelEventQueue::GetHandleTime()
{
    auto &event = GetEvent();
    if (!event) {
        return AppExecFwk::InnerEvent::TimePoint::max();
    }
    return event->GetHandleTime();
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

} // namespace Telephony
} // namespace OHOS