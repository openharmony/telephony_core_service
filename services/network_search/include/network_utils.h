/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <string>
#include <vector>
#include <memory>
#include <any>
#include <mutex>

#include "securec.h"
#include "i_network_search.h"
#include "radio_event.h"
#include "network_search_types.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
struct NetworkSearchCallbackInfo {
    int32_t param_;
    sptr<INetworkSearchCallback> networkSearchItem_;

    NetworkSearchCallbackInfo(int32_t param, sptr<INetworkSearchCallback> callback)
    {
        param_ = param;
        networkSearchItem_ = callback;
    }
};

class NetworkUtils {
public:
    static PreferredNetworkMode GetNetworkModeFromRaf(int32_t raf);
    static int32_t GetRafFromNetworkMode(PreferredNetworkMode PreferredNetworkMode);

    static int64_t GetCallbackIndex64bit();
    static std::shared_ptr<NetworkSearchCallbackInfo> FindNetworkSearchCallback(int64_t index);
    static bool RemoveCallbackFromMap(int64_t index);
    static bool AddNetworkSearchCallBack(int64_t index, std::shared_ptr<NetworkSearchCallbackInfo> &callback);

    template<typename... Args>
    static std::string FormatString(const std::string &format, Args... args);

private:
    static std::unordered_map<int64_t, std::shared_ptr<NetworkSearchCallbackInfo>> networkSearchCacheMap_;
    static std::mutex callbackMapMutex_;
    static std::atomic<int64_t> callbackIndex64bit_;
    static const int64_t MAX_INDEX = 100000000;
};

/**
 * @brief format string
 *
 * @tparam Args Variable parameter type
 * @param format A format string
 * @param args Arguments referenced by the format specifiers in the format string
 * @return std::string A formatted string. max size 100.
 */
template<typename... Args>
std::string NetworkUtils::FormatString(const std::string &format, Args... args)
{
    const size_t size = 100;
    std::unique_ptr<char[]> buf = std::make_unique<char[]>(size);
    if (buf == nullptr) {
        return "";
    }
    if (snprintf_s(buf.get(), size, size, format.c_str(), args...) < 0) {
        return "";
    }
    return std::string(buf.get());
}

class NetworkSearchManager;
class ITelRilManager;
struct RadioCapabilityInfo;
class EventSender {
public:
    EventSender(std::shared_ptr<ITelRilManager> &telRilManager,
        const std::weak_ptr<NetworkSearchManager> &networkSearchManager)
        : telRilManager_(telRilManager), networkSearchManager_(networkSearchManager)
    {}
    virtual ~EventSender() = default;

    /**
     * @brief Mode of getting event .HandlerId is necessary , index and param are optional.see details in
     * AppExecFwk::InnerEvent::Get().
     *
     */
    enum class EventGetMode {
        /**
         * @brief AppExecFwk::InnerEvent::Get(radioEvent)
         *
         */
        GET_EVENT_BY_HANDLERID,
        /**
         * @brief AppExecFwk::InnerEvent::Get(radioEvent,index)
         *
         */
        GET_EVENT_BY_INDEX,
        /**
         * @brief AppExecFwk::InnerEvent::Get(radioEvent,param)
         *
         */
        GET_EVENT_BY_PARAM,
    };

    /**
     * @brief send event to RilBaseManager
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @return true success
     * @return false fail
     */
    bool SendBase(int32_t slotId, RadioEvent radioEvent);

    /**
     * @brief send event to RilBaseManager
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param param used for get event and call function
     * @return true success
     * @return false fail
     */
    bool SendBase(int32_t slotId, RadioEvent radioEvent, int32_t param);

    /**
     * @brief send event to RilBaseManager
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param param used for call function
     * @return true success
     * @return false fail
     */
    bool SendBase(int32_t slotId, RadioEvent radioEvent, RadioCapabilityInfo &param);

    /**
     * @brief send event to RilBaseManager
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param firstParam used for get event and call function
     * @param secondParam used for call function
     * @return true success
     * @return false fail
     */
    bool SendBase(int32_t slotId, RadioEvent radioEvent, int32_t firstParam, int32_t secondParam);

    /**
     * @brief send event to RilBaseManager
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param firstParam used for get event and call function
     * @param secondParam used for call function
     * @return true success
     * @return false fail
     */
    bool SendBase(int32_t slotId, RadioEvent radioEvent, int32_t firstParam, std::string secondParam);

    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param callback pointer to callback interface
     * @return true success
     * @return false fail
     */
    bool SendCallback(int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback);

    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param callback pointer to callback interface
     * @param param used for get event and call function
     * @return true success
     * @return false fail
     */
    bool SendCallback(
        int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback, int32_t param);

    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param callback pointer to callback interface
     * @param param used for get event and call function
     * @return true success
     * @return false fail
     */
    bool SendCallback(int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback,
        RadioCapabilityInfo &param);

    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param callback pointer to callback interface
     * @param param used for get event and call function
     * @return true success
     * @return false fail
     */
    bool SendCallbackEx(
        int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback, int32_t param);

    /**
     * @brief send event to RilBaseManager with callback
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param callback pointer to callback interface
     * @param firstParam used for get event and param of fun
     * @param secondParam param of fun
     * @return true success
     * @return false fail
     */
    bool SendCallback(int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback,
        int32_t firstParam, int32_t secondParam);

    /**
     * @brief
     *
     * @param radioEvent see RadioEvent
     * @param callback pointer to callback interface
     * @param firstParam param of fun
     * @param secondParam param of fun
     * @return true success
     * @return false fail
     */
    bool SendCallback(int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback,
        int32_t firstParam, std::string secondParam);

private:
    /**
     * @brief Get the Ril Function Pointer From Map
     *
     * @tparam T function pointer type. see RilFunc_Event, RilFunc_Int_Event,
     * RilFunc_Int_Int_Event, RilFunc_Int_String_Event
     * @param radioEvent see RadioEvent
     * @return T function pointer . if not found , it is nullptr
     */
    template<typename T>
    T GetFunctionOfEvent(RadioEvent radioEvent);

    /**
     * @brief Send event to model of TelRilManager
     *
     * @tparam eventGetMode see EventGetType.
     * @tparam T pointer  type of class ITelRilManager's function. see
     * RilFunc_Event,RilFunc_Int_Event,RilFunc_Int_Int_Event,RilFunc_Int_String_Event,RilFunc_Capability_Event.
     * @tparam Args Variable parameters types.
     * @param parameters tuple of input parameters.
     * @param args parameters for function calling.
     * @return true success
     * @return false fail
     */
    template<EventGetMode eventGetMode, typename T, typename... Args>
    bool Send(std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, T> &parameters,
        Args... args);

    /**
     * @brief Get the Event object
     *
     * @param slotId sim card id
     * @param radioEvent see RadioEvent
     * @param param parameter of class NetworkSearchCallbackInfo
     * @param callback strong pointer class to class INetworkSearchCallback
     * @return AppExecFwk::InnerEvent::Pointer
     */
    AppExecFwk::InnerEvent::Pointer GetEvent(
        int32_t slotId, RadioEvent radioEvent, int32_t param, const sptr<INetworkSearchCallback> &callback);
    AppExecFwk::InnerEvent::Pointer GetEvent(int32_t slotId, RadioEvent radioEvent, int32_t param);
    AppExecFwk::InnerEvent::Pointer GetEvent(int32_t slotId, RadioEvent radioEvent);

    /**
     * @brief map of function pointer
     *
     */
    static const std::map<RadioEvent, std::any> mapFunctions_;
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
};

template<typename T>
T EventSender::GetFunctionOfEvent(RadioEvent radioEvent)
{
    auto itFunc = mapFunctions_.find(radioEvent);
    if (itFunc != mapFunctions_.end()) {
        TELEPHONY_LOGI("GetFunctionOfEvent find");
        return std::any_cast<T>(itFunc->second);
    }
    TELEPHONY_LOGI("GetFunctionOfEvent nullptr");
    return nullptr;
}

template<EventSender::EventGetMode eventGetMode, typename T, typename... Args>
bool EventSender::Send(
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, T> &parameters, Args... args)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("EventSender::Send telRilManager is null.");
        return false;
    }
    int32_t slotId = 0;
    int32_t param = 0;
    RadioEvent radioEvent = RadioEvent::RADIO_STATE_CHANGED;
    const sptr<INetworkSearchCallback> *callback = nullptr;
    T rilFuncPointer = nullptr;
    std::tie(slotId, radioEvent, param, callback, rilFuncPointer) = parameters;

    if (rilFuncPointer == nullptr) {
        TELEPHONY_LOGE("EventSender::Send rilFuncPointer is null.");
        return false;
    }
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    switch (eventGetMode) {
        case EventGetMode::GET_EVENT_BY_HANDLERID: {
            event = GetEvent(slotId, radioEvent);
            break;
        }
        case EventGetMode::GET_EVENT_BY_INDEX: {
            if (callback == nullptr) {
                return false;
            }
            event = GetEvent(slotId, radioEvent, param, *callback);
            break;
        }
        case EventGetMode::GET_EVENT_BY_PARAM: {
            event = GetEvent(slotId, radioEvent, param);
            break;
        }
        default:
            TELEPHONY_LOGE("EventSender::Send eventGetMode error.");
            return false;
    }
    if (event == nullptr) {
        TELEPHONY_LOGE("EventSender::Send event is null.");
        return false;
    }
    (telRilManager_.get()->*rilFuncPointer)(slotId, args..., event);
    return true;
}
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_UTILS_H