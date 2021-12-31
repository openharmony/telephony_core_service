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

#include "network_search_manager.h"

#include <securec.h>
#include <string_ex.h>
#include <cinttypes>

#include "core_manager.h"
#include "mcc_pool.h"
#include "tel_profile_util.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkSearchManager::NetworkSearchManager(std::shared_ptr<ITelRilManager> telRilManager,
    std::shared_ptr<ISimStateManager> simStateManager, std::shared_ptr<ISimFileManager> simFileManager)
    : telRilManager_(telRilManager), simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("NetworkSearchManager");
    InitRilFunctionPointerMap();
}

void NetworkSearchManager::Init()
{
    if (state_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGE("NetworkSearchManager::Init HandleRunningState started.");
        return;
    }
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init telRilManager_ is null.");
        return;
    }
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init simStateManager_ is null.");
        return;
    }
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init simFileManager_ is null.");
        return;
    }
    eventLoop_ = AppExecFwk::EventRunner::Create("NetworkSearchManager");
    if (eventLoop_.get() == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager failed to create EventRunner");
        return;
    }
    observerHandler_ = std::make_unique<ObserverHandler>();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new ObserverHandler");
        return;
    }
    networkSearchState_ = std::make_shared<NetworkSearchState>(shared_from_this());
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchState");
        return;
    }
    networkSearchState_->Init();
    networkSearchHandler_ = std::make_shared<NetworkSearchHandler>(
        eventLoop_, shared_from_this(), telRilManager_, simFileManager_, simStateManager_);
    if (networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchHandler");
        return;
    }
    networkSearchHandler_->Init();
    DelayedSingleton<NetworkSearchNotify>::GetInstance().get()->ConnectService();
    networkSearchResult_ = std::make_unique<NetworkSearchResult>();
    if (networkSearchResult_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchResult");
        return;
    }
    eventLoop_->Run();
    state_ = HandleRunningState::STATE_RUNNING;
    TELEPHONY_LOGI("NetworkSearchManager::Init eventLoop_->Run()");
    SetRadioState(static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
    GetImsRegStatus();
}

std::shared_ptr<NetworkSearchState> NetworkSearchManager::GetNetworkSearchState() const
{
    return networkSearchState_;
}

std::shared_ptr<ISimFileManager> NetworkSearchManager::GetSimFileManager() const
{
    return simFileManager_;
}

std::shared_ptr<ITelRilManager> NetworkSearchManager::GetRilManager() const
{
    return telRilManager_;
}

std::shared_ptr<ISimStateManager> NetworkSearchManager::GetSimStateManager() const
{
    return simStateManager_;
}

void NetworkSearchManager::SetRadioState(bool isOn, int32_t rst)
{
    TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d", isOn);
    int32_t fun = static_cast<int32_t>(isOn);
    SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_SET_STATUS, fun, rst);
}

bool NetworkSearchManager::SetRadioState(bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback)
{
    AirplaneMode_ = isOn ? false : true;
    TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d", isOn);
    int32_t fun = static_cast<int32_t>(isOn);
    return SendEventToRilCallback(ObserverHandler::ObserverHandlerId::RADIO_SET_STATUS, &callback, fun, rst);
}

void NetworkSearchManager::RegisterCoreNotify(
    const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t what)
{
    TELEPHONY_LOGI("NetworkSearchManager::RegisterCoreNotify  %{public}d", what);
    if (observerHandler_ != nullptr) {
        observerHandler_->RegObserver(what, handler);
    }
}

void NetworkSearchManager::UnRegisterCoreNotify(
    const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t what)
{
    TELEPHONY_LOGI("NetworkSearchManager::UnRegisterCoreNotify %{public}d", what);
    if (observerHandler_ != nullptr) {
        observerHandler_->Remove(what, handler);
    }
}

void NetworkSearchManager::NotifyPsRoamingOpenChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRoamingOpenChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_PS_ROAMING_OPEN);
    }
}

void NetworkSearchManager::NotifyPsRoamingCloseChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRoamingCloseChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_PS_ROAMING_CLOSE);
    }
}

void NetworkSearchManager::NotifyPsRatChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRatChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_PS_RAT_CHANGED);
    }
}

void NetworkSearchManager::NotifyPsConnectionAttachedChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsConnectionAttachedChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_PS_CONNECTION_ATTACHED);
    }
}

void NetworkSearchManager::NotifyPsConnectionDetachedChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsConnectionDetachedChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_PS_CONNECTION_DETACHED);
    }
}

void NetworkSearchManager::NotifyImsRegStateChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyImsRegStateChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_IMS_REG_STATUS_UPDATE);
    }
}

int32_t NetworkSearchManager::GetPsRadioTech(int32_t slotId) const
{
    if (networkSearchState_ != nullptr && networkSearchHandler_ != nullptr) {
        auto event = static_cast<int32_t>(networkSearchState_->GetNetworkStatus()->GetPsRadioTech());
        TELEPHONY_LOGI("NetworkSearchManager::GetPsRadioTech result=%{public}d", event);
        return event;
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech Failed");
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetCsRadioTech(int32_t slotId) const
{
    if (networkSearchState_ != nullptr && networkSearchHandler_ != nullptr) {
        auto event = static_cast<int32_t>(networkSearchState_->GetNetworkStatus()->GetCsRadioTech());
        TELEPHONY_LOGI("NetworkSearchManager::GetCsRadioTech result=%{public}d", event);
        return event;
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech Failed");
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetPsRegState(int32_t slotId) const
{
    if (networkSearchState_ != nullptr && networkSearchHandler_ != nullptr) {
        auto event = static_cast<int32_t>(networkSearchState_->GetNetworkStatus()->GetPsRegStatus());
        TELEPHONY_LOGI("NetworkSearchManager::GetPsRegState result=%{public}d", event);
        return event;
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRegState Failed");
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetPsRoamingState(int32_t slotId) const
{
    if (networkSearchState_ != nullptr && networkSearchHandler_ != nullptr) {
        auto event = static_cast<int32_t>(networkSearchState_->GetNetworkStatus()->GetPsRoamingStatus());
        TELEPHONY_LOGI("NetworkSearchManager::GetPsRoamingState result=%{public}d", event);
        return event;
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRoamingState Failed");
    return TELEPHONY_ERROR;
}

std::u16string NetworkSearchManager::GetOperatorNumeric(int32_t slotId) const
{
    TELEPHONY_LOGI("NetworkSearchManager::GetOperatorNumeric start");
    std::u16string str;
    if (networkSearchHandler_ != nullptr) {
        auto event = networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
        str = Str8ToStr16(event);
        TELEPHONY_LOGI("NetworkSearchManager::GetOperatorNumeric result=%{public}s", event.c_str());
    }
    return str;
}

std::u16string NetworkSearchManager::GetOperatorName(int32_t slotId) const
{
    std::u16string str;
    if (networkSearchState_ != nullptr) {
        auto event = networkSearchState_->GetNetworkStatus()->GetLongOperatorName();
        str = Str8ToStr16(event);
        TELEPHONY_LOGI("NetworkSearchManager::GetOperatorName result=%{public}s", event.c_str());
    }
    return str;
}

sptr<NetworkState> NetworkSearchManager::GetNetworkStatus(int32_t slotId) const
{
    if (networkSearchState_ != nullptr) {
        auto networkState = networkSearchState_->GetNetworkStatus().release();
        return networkState;
    } else {
        return nullptr;
    }
}
void NetworkSearchManager::SetRadioStateValue(ModemPowerState radioState)
{
    radioState_ = radioState;
}

void NetworkSearchManager::SetNetworkSelectionValue(SelectionMode selection)
{
    selection_ = selection;
}

ModemPowerState NetworkSearchManager::GetRadioStateValue() const
{
    return radioState_;
}

int32_t NetworkSearchManager::GetRadioState() const
{
    if (telRilManager_ != nullptr) {
        auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_STATUS);
        if (event != nullptr) {
            event->SetOwner(networkSearchHandler_);
            telRilManager_->GetRadioState(event);
        }
    }
    return static_cast<int32_t>(radioState_);
}

bool NetworkSearchManager::GetRadioState(const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetRadioState...");
    return SendEventToRilCallback(ObserverHandler::ObserverHandlerId::RADIO_GET_STATUS, &callback);
}

std::vector<sptr<SignalInformation>> NetworkSearchManager::GetSignalInfoList(int32_t slotId) const
{
    std::vector<sptr<SignalInformation>> vec;
    if (networkSearchHandler_ != nullptr) {
        networkSearchHandler_->GetSignalInfo(vec);
    }
    return vec;
}

bool NetworkSearchManager::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    return SendEventToRilCallback(ObserverHandler::ObserverHandlerId::RADIO_NETWORK_SEARCH_RESULT, &callback);
}

void NetworkSearchManager::SetNetworkSearchResultValue(
    int32_t listSize, std::vector<NetworkInformation> &operatorInfo)
{
    if (networkSearchResult_ != nullptr) {
        networkSearchResult_->SetNetworkSearchResultValue(listSize, operatorInfo);
    }
}

sptr<NetworkSearchResult> NetworkSearchManager::GetNetworkSearchInformationValue() const
{
    sptr<NetworkSearchResult> networkSearchResult = new (std::nothrow) NetworkSearchResult;
    if (networkSearchResult == nullptr) {
        TELEPHONY_LOGE("GetNetworkSearchInformationValue failed to create new NetWorkSearchResult");
        return nullptr;
    }
    if (networkSearchResult_ == nullptr) {
        TELEPHONY_LOGE("GetNetworkSearchInformationValue networkSearchResult_ is null");
        return nullptr;
    }

    int32_t listSize = networkSearchResult_->GetNetworkSearchInformationSize();
    std::vector<NetworkInformation> operatorInfoList = networkSearchResult_->GetNetworkSearchInformation();
    networkSearchResult->SetNetworkSearchResultValue(listSize, operatorInfoList);
    return networkSearchResult;
}

int32_t NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId)
{
    SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_NETWORK_SELECTION_MODE);
    return static_cast<int32_t>(selection_);
}

bool NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    return SendEventToRilCallback(ObserverHandler::ObserverHandlerId::RADIO_GET_NETWORK_SELECTION_MODE, &callback);
}

bool NetworkSearchManager::SetNetworkSelectionMode(
    int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation, bool resumeSelection)
{
    TELEPHONY_LOGI("NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d", selectMode);
    std::string plmnNumeric = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
    }
    return SendEventToRilBase(
        ObserverHandler::ObserverHandlerId::RADIO_SET_NETWORK_SELECTION_MODE, selectMode, plmnNumeric);
}

bool NetworkSearchManager::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d", selectMode);
    std::string plmnNumeric = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
    }
    return SendEventToRilCallback(
        ObserverHandler::ObserverHandlerId::RADIO_SET_NETWORK_SELECTION_MODE, &callback, selectMode, plmnNumeric);
}

bool NetworkSearchManager::AddNetworkSearchCallBack(
    int64_t id, std::shared_ptr<NetworkSearchCallbackInfo> &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager::AddNetworkSearchCallBack index=(%{public}" PRId64 ")", id);
    if (callback != nullptr) {
        std::lock_guard<std::mutex> guard(callbackMapMutex_);
        auto result = networkSearchCacheMap_.emplace(id, callback);
        return result.second;
    }
    TELEPHONY_LOGE("NetworkSearchManager::AddNetworkSearchCallBack callback is null!");
    return false;
}

std::shared_ptr<NetworkSearchCallbackInfo> NetworkSearchManager::FindNetworkSearchCallback(int64_t index)
{
    TELEPHONY_LOGI("NetworkSearchManager::FindNetworkSearchCallback index=%{public}" PRId64 "", index);
    std::lock_guard<std::mutex> guard(callbackMapMutex_);
    auto iter = networkSearchCacheMap_.find(index);
    if (iter != networkSearchCacheMap_.end()) {
        std::shared_ptr<NetworkSearchCallbackInfo> callback = iter->second;
        return callback;
    }
    return nullptr;
}

bool NetworkSearchManager::RemoveCallbackFromMap(int64_t index)
{
    TELEPHONY_LOGI("NetworkSearchManager::RemoveCallbackFromMap index=%{public}" PRId64 "", index);
    std::lock_guard<std::mutex> guard(callbackMapMutex_);
    return (networkSearchCacheMap_.erase(index) != 0);
}

int64_t NetworkSearchManager::GetCallbackIndex64bit()
{
    if (callbackIndex64bit_ > MAX_INDEX) {
        callbackIndex64bit_ = 0;
    }
    return ++callbackIndex64bit_;
}

std::u16string NetworkSearchManager::GetIsoCountryCodeForNetwork(int32_t slotId) const
{
    std::string iso = "";
    if (networkSearchHandler_ != nullptr) {
        std::string plmn = networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
        int32_t len = plmn.length();
        if (len >= MCC_LEN) {
            std::string mcc = plmn.substr(0, MCC_LEN);
            int32_t value = 0;
            bool succ = StrToInt(mcc, value);
            if (succ) {
                iso = MccPool::MccCountryCode(value);
            } else {
                TELEPHONY_LOGE("GetIsoCountryCodeForNetwork parse Failed!!");
            }
            TELEPHONY_LOGI("NetworkSearchManager::GetIsoCountryCodeForNetwork mcc=%{public}s code=%{public}d",
                mcc.c_str(), value);
        }
    }
    return Str8ToStr16(iso);
}

bool NetworkSearchManager::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    return SendEventToRilCallback(ObserverHandler::ObserverHandlerId::RADIO_GET_PREFERRED_NETWORK_MODE, &callback);
}

bool NetworkSearchManager::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    return SendEventToRilCallback2(
        ObserverHandler::ObserverHandlerId::RADIO_SET_PREFERRED_NETWORK_MODE, &callback, networkMode);
}

bool NetworkSearchManager::GetPreferredNetwork(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager GetPreferredNetwork");
    return SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_PREFERRED_NETWORK_MODE);
}

bool NetworkSearchManager::SetPreferredNetwork(int32_t slotId, int32_t networkMode)
{
    TELEPHONY_LOGI("NetworkSearchManager SetPreferredNetwork networkMode:%{public}d", networkMode);
    return SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_SET_PREFERRED_NETWORK_MODE, networkMode);
}
void NetworkSearchManager::SavePreferredNetworkValue(int32_t slotId, int32_t networkMode)
{
    TELEPHONY_LOGI("NetworkSearchManager SavePreferredNetworkValue slotId:%{public}d, networkMode:%{public}d",
        slotId, networkMode);
    TelProfileUtil *utils = DelayedSingleton<TelProfileUtil>::GetInstance().get();
    std::string str_key = KEY_DEFAULT_PREFERRED_NETWORK_MODE;
    str_key.append(std::to_string(slotId));
    int32_t result = utils->SaveInt(str_key, networkMode);
    if (result == NativePreferences::E_OK) {
        utils->Refresh();
    }
}

int32_t NetworkSearchManager::GetPreferredNetworkValue(int32_t slotId) const
{
    TelProfileUtil *utils = DelayedSingleton<TelProfileUtil>::GetInstance().get();
    std::string str_key = KEY_DEFAULT_PREFERRED_NETWORK_MODE;
    str_key.append(std::to_string(slotId));
    int32_t networkMode = utils->ObtainInt(str_key, 0);
    TELEPHONY_LOGI("NetworkSearchManager GetPreferredNetworkValue slotId:%{public}d, networkMode:%{public}d",
        slotId, networkMode);
    return networkMode;
}

void NetworkSearchManager::UpdatePhone(RadioTech csRadioTech) const
{
    if (networkSearchHandler_ != nullptr) {
        networkSearchHandler_->UpdatePhone(csRadioTech);
    }
}

bool NetworkSearchManager::GetImsRegStatus()
{
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager GetImsRegStatus networkSearchState is null");
        return false;
    }
    SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_IMS_REG_STATUS);
    return networkSearchState_->GetImsStatus();
}

bool NetworkSearchManager::SetPsAttachStatus(
    int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback)
{
    return SendEventToRilCallback2(
        ObserverHandler::ObserverHandlerId::RADIO_SET_PS_ATTACH_STATUS, &callback, psAttachStatus);
}

void NetworkSearchManager::SetImei(std::u16string imei)
{
    imei_ = imei;
}

std::u16string NetworkSearchManager::GetImei(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetImei start");
    SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_IMEI);
    return imei_;
}

std::vector<sptr<CellInformation>> NetworkSearchManager::GetCellInfoList(int32_t slotId)
{
    std::vector<sptr<CellInformation>> vec;
    if (networkSearchHandler_ != nullptr) {
        networkSearchHandler_->GetCellInfoList(vec);
    }
    return vec;
}

bool NetworkSearchManager::SendUpdateCellLocationRequest()
{
    if (networkSearchHandler_ == nullptr || GetRadioStateValue() == ModemPowerState::CORE_SERVICE_POWER_OFF) {
        return false;
    } else {
        networkSearchHandler_->SendUpdateCellLocationRequest();
    }
    return true;
}

void NetworkSearchManager::UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac)
{
    if (networkSearchHandler_ != nullptr) {
        networkSearchHandler_->UpdateCellLocation(techType, cellId, lac);
    }
}

AppExecFwk::InnerEvent::Pointer NetworkSearchManager::GetEvent(
    ObserverHandler::ObserverHandlerId handlerId, int32_t param, const sptr<INetworkSearchCallback> &callback)
{
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    int64_t index = GetCallbackIndex64bit();
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        std::make_shared<NetworkSearchCallbackInfo>(param, callback);
    if (callbackInfo == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::GetEvent callbackInfo is null!!");
        return event;
    }
    if (!AddNetworkSearchCallBack(index, callbackInfo)) {
        TELEPHONY_LOGE("NetworkSearchManager::GetEvent AddNetworkSearchCallBack Error!!");
        return event;
    }
    event = AppExecFwk::InnerEvent::Get(static_cast<int32_t>(handlerId), index);
    if (event == nullptr) {
        RemoveCallbackFromMap(index);
        return event;
    }
    event->SetOwner(networkSearchHandler_);
    return event;
}

bool NetworkSearchManager::SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer1>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer1>
        parameters(handlerId, 0, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_HANDLERID, RilFuncPointer1>(parameters);
}

bool NetworkSearchManager::SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId, int32_t param)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer2>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer2>
        parameters(handlerId, param, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFuncPointer2, int32_t>(parameters, param);
}

bool NetworkSearchManager::SendEventToRilBase(
    ObserverHandler::ObserverHandlerId handlerId, int32_t param1, int32_t param2)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer3>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer3>
        parameters(handlerId, param1, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFuncPointer3, int32_t, int32_t>(
        parameters, param1, param2);
}

bool NetworkSearchManager::SendEventToRilBase(
    ObserverHandler::ObserverHandlerId handlerId, int32_t param1, std::string param2)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer4>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer4>
        parameters(handlerId, param1, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFuncPointer4, int32_t, std::string>(
        parameters, param1, param2);
}

bool NetworkSearchManager::SendEventToRilCallback(
    ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer1>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer1>
        parameters(handlerId, 0, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFuncPointer1>(parameters);
}

bool NetworkSearchManager::SendEventToRilCallback(
    ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback, int32_t param)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer1>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer1>
        parameters(handlerId, param, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFuncPointer1>(parameters);
}

bool NetworkSearchManager::SendEventToRilCallback2(
    ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback, int32_t param)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer2>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer2>
        parameters(handlerId, param, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFuncPointer2, int32_t>(parameters, param);
}

bool NetworkSearchManager::SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
    const sptr<INetworkSearchCallback> *callback, int32_t param1, int32_t param2)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer3>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer3>
        parameters(handlerId, param1, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFuncPointer3, int32_t, int32_t>(
        parameters, param1, param2);
}

bool NetworkSearchManager::SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
    const sptr<INetworkSearchCallback> *callback, int32_t param1, std::string param2)
{
    auto fun = GetRilFunctionPointer<RilFuncPointer4>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFuncPointer4>
        parameters(handlerId, param1, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFuncPointer4, int32_t, std::string>(
        parameters, param1, param2);
}

void NetworkSearchManager::InitRilFunctionPointerMap()
{
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_GET_NETWORK_SELECTION_MODE] =
        &ITelRilManager::GetNetworkSelectionMode;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_SET_NETWORK_SELECTION_MODE] =
        &ITelRilManager::SetNetworkSelectionMode;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_GET_PREFERRED_NETWORK_MODE] =
        &ITelRilManager::GetPreferredNetwork;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_SET_PREFERRED_NETWORK_MODE] =
        &ITelRilManager::SetPreferredNetwork;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_SET_STATUS] = &ITelRilManager::SetRadioState;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_GET_STATUS] = &ITelRilManager::GetRadioState;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_GET_IMS_REG_STATUS] =
        &ITelRilManager::GetImsRegStatus;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_GET_IMEI] = &ITelRilManager::GetImei;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_NETWORK_SEARCH_RESULT] =
        &ITelRilManager::GetNetworkSearchInformation;
    mapRilFunctionPointer_[ObserverHandler::ObserverHandlerId::RADIO_SET_PS_ATTACH_STATUS] =
        &ITelRilManager::SetPsAttachStatus;
}
} // namespace Telephony
} // namespace OHOS
