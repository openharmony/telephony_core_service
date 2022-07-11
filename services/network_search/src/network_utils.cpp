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

#include "network_utils.h"

#include <cinttypes>

#include "hril_network_parcel.h"
#include "network_search_manager.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief function pointer of class ITelRilManager.
 *
 */
using RilFunc_Event = int32_t (ITelRilManager::*)(int32_t, const AppExecFwk::InnerEvent::Pointer &);
using RilFunc_Int_Event = int32_t (ITelRilManager::*)(int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &);
using RilFunc_Int_Int_Event = int32_t (ITelRilManager::*)(
    int32_t, int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &);
using RilFunc_Int_String_Event = int32_t (ITelRilManager::*)(
    int32_t, int32_t, std::string, const AppExecFwk::InnerEvent::Pointer &);
using RilFunc_Capability_Event = int32_t (ITelRilManager::*)(
    int32_t, RadioCapabilityInfo &, const AppExecFwk::InnerEvent::Pointer &);

// group
const int32_t GSM = RAF_GSM;
const int32_t CDMA = RAF_1XRTT;
const int32_t EVDO = RAF_EVDO | RAF_EHRPD;
const int32_t HS = RAF_WCDMA | RAF_HSPA | RAF_HSPAP;
const int32_t WCDMA = HS;
const int32_t LTE = RAF_LTE | RAF_LTE_CA;
const int32_t NR = RAF_NR;
// nG
const int32_t RAF_2G = GSM | CDMA;
const int32_t RAF_3G = WCDMA | EVDO | RAF_TD_SCDMA;
const int32_t RAF_4G = LTE;
const int32_t RAF_5G = NR;
// auto mode , support all radio mode
const int32_t RAF_AUTO = RAF_2G | RAF_3G | RAF_4G | RAF_5G;

static const std::map<int32_t, PreferredNetworkMode> mapNetworkModeFromRaf = {
    { RAF_AUTO, PreferredNetworkMode::CORE_NETWORK_MODE_AUTO },
    { GSM, PreferredNetworkMode::CORE_NETWORK_MODE_GSM },
    { WCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_WCDMA },
    { LTE, PreferredNetworkMode::CORE_NETWORK_MODE_LTE },
    { LTE | WCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA },
    { LTE | WCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA_GSM },
    { CDMA, PreferredNetworkMode::CORE_NETWORK_MODE_CDMA },
    { WCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_WCDMA_GSM },
    { EVDO, PreferredNetworkMode::CORE_NETWORK_MODE_EVDO },
    { EVDO | CDMA, PreferredNetworkMode::CORE_NETWORK_MODE_EVDO_CDMA },
    { WCDMA | GSM | EVDO | CDMA, PreferredNetworkMode::CORE_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA },
    { LTE | EVDO | CDMA, PreferredNetworkMode::CORE_NETWORK_MODE_LTE_EVDO_CDMA },
    { LTE | WCDMA | GSM | EVDO | CDMA, PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA },
    { RAF_TD_SCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA },
    { RAF_TD_SCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_GSM },
    { RAF_TD_SCDMA | WCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_WCDMA },
    { RAF_TD_SCDMA | WCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM },
    { LTE | RAF_TD_SCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA },
    { LTE | RAF_TD_SCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_GSM },
    { LTE | RAF_TD_SCDMA | WCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA },
    { LTE | RAF_TD_SCDMA | WCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM },
    { RAF_TD_SCDMA | WCDMA | GSM | EVDO | CDMA, PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA },
    { LTE | RAF_TD_SCDMA | WCDMA | GSM | EVDO | CDMA,
        PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA },
    { NR, PreferredNetworkMode::CORE_NETWORK_MODE_NR },
    { NR | LTE, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE },
    { NR | LTE | WCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA },
    { NR | LTE | WCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM },
    { NR | LTE | EVDO | CDMA, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_EVDO_CDMA },
    { NR | LTE | WCDMA | GSM | EVDO | CDMA, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA },
    { NR | LTE | RAF_TD_SCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA },
    { NR | LTE | RAF_TD_SCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_GSM },
    { NR | LTE | RAF_TD_SCDMA | WCDMA, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA },
    { NR | LTE | RAF_TD_SCDMA | WCDMA | GSM, PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM },
    { NR | LTE | RAF_TD_SCDMA | GSM | EVDO | CDMA,
        PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA },
};

PreferredNetworkMode NetworkUtils::GetNetworkModeFromRaf(int32_t raf)
{
    auto iter = mapNetworkModeFromRaf.find(raf);
    if (iter != mapNetworkModeFromRaf.end()) {
        return iter->second;
    }
    return PreferredNetworkMode::CORE_NETWORK_MODE_AUTO;
}

static const std::map<PreferredNetworkMode, int32_t> mapRafFromNetworkMode = {
    { PreferredNetworkMode::CORE_NETWORK_MODE_AUTO, RAF_AUTO },
    { PreferredNetworkMode::CORE_NETWORK_MODE_GSM, GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_WCDMA, WCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE, LTE },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA, LTE | WCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA_GSM, LTE | WCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_WCDMA_GSM, WCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_CDMA, CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_EVDO, EVDO },
    { PreferredNetworkMode::CORE_NETWORK_MODE_EVDO_CDMA, EVDO | CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA, WCDMA | GSM | EVDO | CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_EVDO_CDMA, LTE | EVDO | CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA, LTE | WCDMA | GSM | EVDO | CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA, RAF_TD_SCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_GSM, RAF_TD_SCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_WCDMA, RAF_TD_SCDMA | WCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM, RAF_TD_SCDMA | WCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA, LTE | RAF_TD_SCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_GSM, LTE | RAF_TD_SCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA, LTE | RAF_TD_SCDMA | WCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM, LTE | RAF_TD_SCDMA | WCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA, RAF_TD_SCDMA | WCDMA | GSM | EVDO | CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA,
        LTE | RAF_TD_SCDMA | WCDMA | GSM | EVDO | CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR, NR },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE, NR | LTE },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA, NR | LTE | WCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM, NR | LTE | WCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_EVDO_CDMA, NR | LTE | EVDO | CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA, NR | LTE | WCDMA | GSM | EVDO | CDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA, NR | LTE | RAF_TD_SCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_GSM, NR | LTE | RAF_TD_SCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA, NR | LTE | RAF_TD_SCDMA | WCDMA },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM, NR | LTE | RAF_TD_SCDMA | WCDMA | GSM },
    { PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA,
        NR | LTE | RAF_TD_SCDMA | GSM | EVDO | CDMA },
};

std::unordered_map<int64_t, std::shared_ptr<NetworkSearchCallbackInfo>> NetworkUtils::networkSearchCacheMap_;
std::mutex NetworkUtils::callbackMapMutex_;
std::atomic<int64_t> NetworkUtils::callbackIndex64bit_ = MIN_INDEX;
int32_t NetworkUtils::GetRafFromNetworkMode(PreferredNetworkMode PreferredNetworkMode)
{
    auto iter = mapRafFromNetworkMode.find(PreferredNetworkMode);
    if (iter != mapRafFromNetworkMode.end()) {
        return iter->second;
    }
    return RAF_UNKNOWN;
}

std::vector<std::string> NetworkUtils::Split(const std::string &input, const std::string &flag)
{
    std::vector<std::string> vec;
    if (input.empty()) {
        TELEPHONY_LOGE("input is null");
        return vec;
    }
    std::string::size_type start = 0;
    std::string::size_type pos = 0;
    while ((pos = input.find(flag, start)) != std::string::npos) {
        vec.push_back(input.substr(start, pos - start));
        start = pos + flag.size();
    }
    if (start != input.size()) {
        vec.push_back(input.substr(start, input.size() - start));
    }
    return vec;
}

bool NetworkUtils::AddNetworkSearchCallBack(int64_t index, std::shared_ptr<NetworkSearchCallbackInfo> &callback)
{
    TELEPHONY_LOGI("NetworkUtils::AddNetworkSearchCallBack index=(%{public}" PRId64 ")", index);
    if (callback != nullptr) {
        std::lock_guard<std::mutex> guard(callbackMapMutex_);
        auto result = networkSearchCacheMap_.emplace(index, callback);
        return result.second;
    }
    TELEPHONY_LOGE("NetworkUtils::AddNetworkSearchCallBack callback is null!");
    return false;
}

int64_t NetworkUtils::GetCallbackIndex64bit()
{
    if (callbackIndex64bit_ > MAX_INDEX || callbackIndex64bit_ < MIN_INDEX) {
        callbackIndex64bit_ = MIN_INDEX;
    }
    return ++callbackIndex64bit_;
}

std::shared_ptr<NetworkSearchCallbackInfo> NetworkUtils::FindNetworkSearchCallback(int64_t index)
{
    TELEPHONY_LOGI("NetworkUtils::FindNetworkSearchCallback index=%{public}" PRId64 "", index);

    std::lock_guard<std::mutex> guard(callbackMapMutex_);
    auto iter = networkSearchCacheMap_.find(index);
    if (iter != networkSearchCacheMap_.end()) {
        std::shared_ptr<NetworkSearchCallbackInfo> callback = iter->second;
        return callback;
    }
    return nullptr;
}

bool NetworkUtils::RemoveCallbackFromMap(int64_t index)
{
    TELEPHONY_LOGI("NetworkUtils::RemoveCallbackFromMap index=%{public}" PRId64 "", index);
    std::lock_guard<std::mutex> guard(callbackMapMutex_);
    return (networkSearchCacheMap_.erase(index));
}

const std::map<RadioEvent, std::any> EventSender::mapFunctions_ = {
    { RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE, &ITelRilManager::GetNetworkSelectionMode },
    { RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, &ITelRilManager::SetNetworkSelectionMode },
    { RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE, &ITelRilManager::GetPreferredNetwork },
    { RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE, &ITelRilManager::SetPreferredNetwork },
    { RadioEvent::RADIO_SET_STATUS, &ITelRilManager::SetRadioState },
    { RadioEvent::RADIO_GET_STATUS, &ITelRilManager::GetRadioState },
    { RadioEvent::RADIO_GET_IMEI, &ITelRilManager::GetImei },
    { RadioEvent::RADIO_GET_MEID, &ITelRilManager::GetMeid },
    { RadioEvent::RADIO_NETWORK_SEARCH_RESULT, &ITelRilManager::GetNetworkSearchInformation },
    { RadioEvent::RADIO_GET_RADIO_CAPABILITY, &ITelRilManager::GetRadioCapability },
    { RadioEvent::RADIO_GET_VOICE_TECH, &ITelRilManager::GetVoiceRadioTechnology },
    { RadioEvent::RADIO_OPERATOR, &ITelRilManager::GetOperatorInfo },
};

AppExecFwk::InnerEvent::Pointer EventSender::GetEvent(int32_t slotId, RadioEvent radioEvent, int32_t param)
{
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager");
        return event;
    }

    auto inner = nsm->FindManagerInner(slotId);
    if (inner != nullptr) {
        event = AppExecFwk::InnerEvent::Get(static_cast<int32_t>(radioEvent), param);
        if (event == nullptr) {
            return event;
        }
        event->SetOwner(inner->networkSearchHandler_);
        return event;
    }
    return event;
}

AppExecFwk::InnerEvent::Pointer EventSender::GetEvent(int32_t slotId, RadioEvent radioEvent)
{
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager");
        return event;
    }

    auto inner = nsm->FindManagerInner(slotId);
    if (inner != nullptr) {
        event = AppExecFwk::InnerEvent::Get(static_cast<int32_t>(radioEvent));
        if (event == nullptr) {
            return event;
        }
        event->SetOwner(inner->networkSearchHandler_);
        return event;
    }
    return event;
}

AppExecFwk::InnerEvent::Pointer EventSender::GetEvent(
    int32_t slotId, RadioEvent radioEvent, int32_t param, const sptr<INetworkSearchCallback> &callback)
{
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager");
        return event;
    }

    auto inner = nsm->FindManagerInner(slotId);
    if (inner != nullptr) {
        int64_t index = NetworkUtils::GetCallbackIndex64bit();
        std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
            std::make_shared<NetworkSearchCallbackInfo>(param, callback);
        if (callbackInfo == nullptr) {
            TELEPHONY_LOGE("EventSender::GetEvent callbackInfo is null!! slotId:%{public}d", slotId);
            return event;
        }
        if (!NetworkUtils::AddNetworkSearchCallBack(index, callbackInfo)) {
            TELEPHONY_LOGE("EventSender::GetEvent AddNetworkSearchCallBack Error!! slotId:%{public}d", slotId);
            return event;
        }
        event = AppExecFwk::InnerEvent::Get(static_cast<int32_t>(radioEvent), index);
        if (event == nullptr) {
            NetworkUtils::RemoveCallbackFromMap(index);
            return event;
        }
        event->SetOwner(inner->networkSearchHandler_);
        return event;
    }
    return event;
}

bool EventSender::SendBase(int32_t slotId, RadioEvent radioEvent)
{
    auto fun = GetFunctionOfEvent<RilFunc_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Event> parameters(
        slotId, radioEvent, 0, nullptr, fun);
    return Send<EventGetMode::GET_EVENT_BY_HANDLERID, RilFunc_Event>(parameters);
}

bool EventSender::SendBase(int32_t slotId, RadioEvent radioEvent, int32_t param)
{
    auto fun = GetFunctionOfEvent<RilFunc_Int_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_Event> parameters(
        slotId, radioEvent, param, nullptr, fun);
    return Send<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Int_Event, int32_t>(parameters, param);
}

bool EventSender::SendBase(int32_t slotId, RadioEvent radioEvent, RadioCapabilityInfo &param)
{
    auto fun = GetFunctionOfEvent<RilFunc_Capability_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Capability_Event> parameters(
        slotId, radioEvent, 0, nullptr, fun);
    return Send<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Capability_Event, RadioCapabilityInfo &>(parameters, param);
}

bool EventSender::SendBase(int32_t slotId, RadioEvent radioEvent, int32_t firstParam, int32_t secondParam)
{
    auto fun = GetFunctionOfEvent<RilFunc_Int_Int_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_Int_Event> parameters(
        slotId, radioEvent, firstParam, nullptr, fun);
    return Send<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Int_Int_Event, int32_t, int32_t>(
        parameters, firstParam, secondParam);
}

bool EventSender::SendBase(int32_t slotId, RadioEvent radioEvent, int32_t firstParam, std::string secondParam)
{
    auto fun = GetFunctionOfEvent<RilFunc_Int_String_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_String_Event> parameters(
        slotId, radioEvent, firstParam, nullptr, fun);
    return Send<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Int_String_Event, int32_t, std::string>(
        parameters, firstParam, secondParam);
}

bool EventSender::SendCallback(int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback)
{
    auto fun = GetFunctionOfEvent<RilFunc_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Event> parameters(
        slotId, radioEvent, 0, callback, fun);
    return Send<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Event>(parameters);
}

bool EventSender::SendCallback(
    int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback, int32_t param)
{
    auto fun = GetFunctionOfEvent<RilFunc_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Event> parameters(
        slotId, radioEvent, param, callback, fun);
    return Send<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Event>(parameters);
}

bool EventSender::SendCallback(
    int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback, RadioCapabilityInfo &param)
{
    auto fun = GetFunctionOfEvent<RilFunc_Capability_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Capability_Event> parameters(
        slotId, radioEvent, 0, callback, fun);
    return Send<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Capability_Event, RadioCapabilityInfo &>(parameters, param);
}

bool EventSender::SendCallbackEx(
    int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback, int32_t param)
{
    auto fun = GetFunctionOfEvent<RilFunc_Int_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_Event> parameters(
        slotId, radioEvent, param, callback, fun);
    return Send<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Int_Event, int32_t>(parameters, param);
}

bool EventSender::SendCallback(int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback,
    int32_t firstParam, int32_t secondParam)
{
    auto fun = GetFunctionOfEvent<RilFunc_Int_Int_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_Int_Event> parameters(
        slotId, radioEvent, firstParam, callback, fun);
    return Send<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Int_Int_Event, int32_t, int32_t>(
        parameters, firstParam, secondParam);
}

bool EventSender::SendCallback(int32_t slotId, RadioEvent radioEvent, const sptr<INetworkSearchCallback> *callback,
    int32_t firstParam, std::string secondParam)
{
    auto fun = GetFunctionOfEvent<RilFunc_Int_String_Event>(radioEvent);
    std::tuple<int32_t, RadioEvent, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_String_Event> parameters(
        slotId, radioEvent, firstParam, callback, fun);
    return Send<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Int_String_Event, int32_t, std::string>(
        parameters, firstParam, secondParam);
}
} // namespace Telephony
} // namespace OHOS
