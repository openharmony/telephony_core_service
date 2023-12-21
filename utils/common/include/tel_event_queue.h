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

#ifndef TELEPHONY_EVENT_QUEUE_H
#define TELEPHONY_EVENT_QUEUE_H

#include "event_handler.h"
#include "ffrt.h"

namespace OHOS {
namespace Telephony {
class TelEventQueue {
public:
    explicit TelEventQueue(const std::string &name);
    void Submit(AppExecFwk::InnerEvent::Pointer &event, AppExecFwk::EventQueue::Priority priority);
    void RemoveEvent(uint32_t innerEventId);
    bool HasInnerEvent(uint32_t innerEventId);
    void RemoveAllEvents();

private:
    struct EventList {
        std::list<AppExecFwk::InnerEvent::Pointer> events;
    };

private:
    void InsertEventsInner(AppExecFwk::InnerEvent::Pointer &event, AppExecFwk::EventQueue::Priority priority);
    bool HasEvent();
    AppExecFwk::InnerEvent::Pointer PopEvent();
    AppExecFwk::InnerEvent::Pointer &GetEvent();
    void SubmitInner(int32_t queueId);
    bool IsEmpty();
    uint32_t ToTelPriority(AppExecFwk::EventQueue::Priority priority);
    uint32_t GetPriorityIndex();
    AppExecFwk::InnerEvent::TimePoint GetHandleTime();
    void ClearCurrentTask();

private:
    static const uint32_t EVENT_QUEUE_NUM = 3;
    std::array<EventList, EVENT_QUEUE_NUM> eventLists_;
    AppExecFwk::InnerEvent::TimePoint curHandleTime_ { AppExecFwk::InnerEvent::TimePoint::max() };
    std::mutex eventCtx_;
    ffrt::task_handle curTask_;
    std::string name_;
    std::atomic_int queueId_ { 0 };
    std::shared_ptr<ffrt::queue> queue_ = nullptr;
    AppExecFwk::InnerEvent::Pointer nullPointer_ = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_EVENT_QUEUE_H