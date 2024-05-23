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

#ifndef TELEPHONY_EVENT_HANDLER_H
#define TELEPHONY_EVENT_HANDLER_H

#include "event_handler.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class TelEventQueue;
using TelTask = std::function<void()>;
class TelFFRTUtils final {
public:
    /**
     * Submit an FFRT asynchronous task.
     *
     * @param task TelTask.
     */
    static void Submit(const TelTask &task);
    /**
     * Submit an FFRT asynchronous task.
     *
     * @param task TelTask.
     */
    static void Submit(TelTask &&task);

    /**
     * Submit an FFRT synchronization task.
     *
     * @param task TelTask.
     */
    static void SubmitSync(const TelTask &task);

    /**
     * Submit an FFRT synchronization task.
     *
     * @param task TelTask.
     */
    static void SubmitSync(TelTask &&task);

    /**
     * FFRT task wait for some time.
     *
     * @param task TelTask.
     */
    static void SleepFor(uint32_t timeoutMs);
};

class TelEventHandler : public AppExecFwk::EventHandler {
public:
    explicit TelEventHandler(const std::string &name);

    /**
     * Send an event.
     *
     * @param event Event which should be handled.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully. If returns false, event should be released manually.
     */
    bool SendEvent(AppExecFwk::InnerEvent::Pointer &event, int64_t delayTime = 0, Priority priority = Priority::LOW);

    /**
     * Process the event. Developers should override this method.
     *
     * @param event The event should be processed.
     */
    virtual void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}

    /**
     * Send an event.
     *
     * @param event Event which should be handled.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully. If returns false, event should be released manually.
     */
    inline bool SendEvent(AppExecFwk::InnerEvent::Pointer &event, Priority priority)
    {
        return SendEvent(event, 0, priority);
    }

    /**
     * Send an event.
     *
     * @param event Event which should be handled.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendEvent(AppExecFwk::InnerEvent::Pointer &&event, int64_t delayTime = 0,
        AppExecFwk::EventQueue::Priority priority = Priority::LOW)
    {
        return SendEvent(event, delayTime, priority);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event, default is 0.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendEvent(uint32_t innerEventId, int64_t param, int64_t delayTime)
    {
        return SendEvent(AppExecFwk::InnerEvent::Get(innerEventId, param), delayTime);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendEvent(
        uint32_t innerEventId, int64_t delayTime = 0, AppExecFwk::EventQueue::Priority priority = Priority::LOW)
    {
        return SendEvent(AppExecFwk::InnerEvent::Get(innerEventId, 0), delayTime, priority);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendEvent(uint32_t innerEventId, Priority priority)
    {
        return SendEvent(AppExecFwk::InnerEvent::Get(innerEventId, 0), 0, priority);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param object Shared pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendEvent(uint32_t innerEventId, const std::shared_ptr<T> &object, int64_t delayTime = 0)
    {
        return SendEvent(AppExecFwk::InnerEvent::Get(innerEventId, object), delayTime);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param object Weak pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendEvent(uint32_t innerEventId, const std::weak_ptr<T> &object, int64_t delayTime = 0)
    {
        return SendEvent(AppExecFwk::InnerEvent::Get(innerEventId, object), delayTime);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendEvent(uint32_t innerEventId, std::unique_ptr<T, D> &object, int64_t delayTime = 0)
    {
        return SendEvent(AppExecFwk::InnerEvent::Get(innerEventId, object), delayTime);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendEvent(uint32_t innerEventId, std::unique_ptr<T, D> &&object, int64_t delayTime = 0)
    {
        return SendEvent(AppExecFwk::InnerEvent::Get(innerEventId, object), delayTime);
    }

    /**
     * Send an immediate event.
     *
     * @param event Event which should be handled.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendImmediateEvent(AppExecFwk::InnerEvent::Pointer &event)
    {
        return SendEvent(event, 0, Priority::IMMEDIATE);
    }

    /**
     * Remove sent events.
     *
     * @param innerEventId The id of the event.
     */
    void RemoveEvent(uint32_t innerEventId);

    /**
     * Check whether an event with the given ID can be found among the events that have been sent but not processed.
     *
     * @param innerEventId The id of the event.
     */
    bool HasInnerEvent(uint32_t innerEventId);

    /**
     * Remove all sent events.
     */
    void RemoveAllEvents();

    /**
     * Send an event ,the event should execute now.
     *
     * @param event Event which should be handled.
     * @return Returns true if event has been sent successfully.
     */
    bool SendExecuteNowEvent(AppExecFwk::InnerEvent::Pointer &event);

    /**
     * Send an event.
     *
     * @param handler The instance of the EventHandler.
     * @param ParamTypes params for send event.
     * @return Returns true if event has been sent successfully.
     */
    template<typename... ParamTypes>
    static bool SendTelEvent(std::shared_ptr<AppExecFwk::EventHandler> handler, ParamTypes &&... _args)
    {
        if (handler == nullptr) {
            TELEPHONY_LOGE("handler is nullptr");
            return false;
        }
        if (handler->GetEventRunner() == nullptr && handler.get() != nullptr) {
            return static_cast<TelEventHandler *>(handler.get())->SendEvent(std::forward<ParamTypes>(_args)...);
        }
        return handler->SendEvent(std::forward<ParamTypes>(_args)...);
    }

private:
    void ClearFfrt(bool isNeedEnd);
    std::shared_ptr<TelEventQueue> queue_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_EVENT_HANDLER_H