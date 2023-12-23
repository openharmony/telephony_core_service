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

#include "tel_event_handler.h"

#include "tel_event_queue.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

void TelFFRTUtils::Submit(const TelTask &task)
{
    ffrt::submit(task);
}

void TelFFRTUtils::Submit(TelTask &&task)
{
    ffrt::submit(task);
}

void TelFFRTUtils::SubmitSync(const TelTask &task)
{
    ffrt::submit(task);
    ffrt::wait();
}

void TelFFRTUtils::SubmitSync(TelTask &&task)
{
    ffrt::submit(task);
    ffrt::wait();
}

void TelFFRTUtils::SleepFor(uint32_t timeoutMs)
{
    ffrt::this_task::sleep_for(std::chrono::milliseconds(timeoutMs));
}

TelEventHandler::TelEventHandler(const std::string &name)
{
    queue_ = std::make_shared<TelEventQueue>(name);
}

bool TelEventHandler::SendEvent(AppExecFwk::InnerEvent::Pointer &event, int64_t delayTime, Priority priority)
{
    if (!event) {
        TELEPHONY_LOGE("Could not send an invalid event");
        return false;
    }

    AppExecFwk::InnerEvent::TimePoint now = AppExecFwk::InnerEvent::Clock::now();
    if (delayTime > 0) {
        event->SetHandleTime(now + std::chrono::milliseconds(delayTime));
    } else {
        event->SetHandleTime(now);
    }
    event->SetOwner(shared_from_this());
    if (!queue_) {
        TELEPHONY_LOGE("queue is nullptr");
        return false;
    }
    queue_->Submit(event, priority);
    return true;
}

bool TelEventHandler::SendExecuteNowEvent(AppExecFwk::InnerEvent::Pointer &event)
{
    if (!event) {
        TELEPHONY_LOGE("Could not send an invalid event");
        return false;
    }
    event->SetHandleTime(AppExecFwk::InnerEvent::TimePoint::min());
    event->SetOwner(shared_from_this());
    if (!queue_) {
        TELEPHONY_LOGE("queue is nullptr");
        return false;
    }
    queue_->Submit(event, Priority::IMMEDIATE);
    return true;
}

void TelEventHandler::RemoveEvent(uint32_t innerEventId)
{
    if (!queue_) {
        TELEPHONY_LOGE("queue is nullptr");
        return;
    }
    queue_->RemoveEvent(innerEventId);
}

bool TelEventHandler::HasInnerEvent(uint32_t innerEventId)
{
    if (!queue_) {
        TELEPHONY_LOGE("queue is nullptr");
        return false;
    }
    return queue_->HasInnerEvent(innerEventId);
}

void TelEventHandler::RemoveAllEvents()
{
    if (!queue_) {
        TELEPHONY_LOGE("queue is nullptr");
        return;
    }
    queue_->RemoveAllEvents();
}

} // namespace Telephony
} // namespace OHOS