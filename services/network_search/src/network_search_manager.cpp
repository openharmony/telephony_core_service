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
const std::string NetworkSearchManager::RESOURCE_HAP_BUNDLE_NAME = "com.example.myapplication";
const std::string NetworkSearchManager::RESOURCE_INDEX_PATH = "/data/accounts/account_0/applications/" +
    RESOURCE_HAP_BUNDLE_NAME + "/" + RESOURCE_HAP_BUNDLE_NAME + "/assets/entry/resources.index";

const std::map<ObserverHandler::ObserverHandlerId, std::any> NetworkSearchManager::mapRilFunctionPointer_ = {
    {ObserverHandler::ObserverHandlerId::RADIO_GET_NETWORK_SELECTION_MODE, &ITelRilManager::GetNetworkSelectionMode},
    {ObserverHandler::ObserverHandlerId::RADIO_SET_NETWORK_SELECTION_MODE, &ITelRilManager::SetNetworkSelectionMode},
    {ObserverHandler::ObserverHandlerId::RADIO_GET_PREFERRED_NETWORK_MODE, &ITelRilManager::GetPreferredNetwork},
    {ObserverHandler::ObserverHandlerId::RADIO_SET_PREFERRED_NETWORK_MODE, &ITelRilManager::SetPreferredNetwork},
    {ObserverHandler::ObserverHandlerId::RADIO_SET_STATUS, &ITelRilManager::SetRadioState},
    {ObserverHandler::ObserverHandlerId::RADIO_GET_STATUS, &ITelRilManager::GetRadioState},
    {ObserverHandler::ObserverHandlerId::RADIO_GET_IMS_REG_STATUS, &ITelRilManager::GetImsRegStatus},
    {ObserverHandler::ObserverHandlerId::RADIO_GET_IMEI, &ITelRilManager::GetImei},
    {ObserverHandler::ObserverHandlerId::RADIO_GET_MEID, &ITelRilManager::GetMeid},
    {ObserverHandler::ObserverHandlerId::RADIO_NETWORK_SEARCH_RESULT, &ITelRilManager::GetNetworkSearchInformation},
    {ObserverHandler::ObserverHandlerId::RADIO_SET_PS_ATTACH_STATUS, &ITelRilManager::SetPsAttachStatus},
    {ObserverHandler::ObserverHandlerId::RADIO_GET_RADIO_CAPABILITY, &ITelRilManager::GetRadioCapability},
    {ObserverHandler::ObserverHandlerId::RADIO_SET_RADIO_CAPABILITY, &ITelRilManager::SetRadioCapability},
    {ObserverHandler::ObserverHandlerId::RADIO_GET_VOICE_TECH, &ITelRilManager::GetVoiceRadioTechnology},
};

// RadioAccessFamily defines
const int32_t RAF_UNKNOWN = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_UNKNOWN);
const int32_t RAF_GSM = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_GSM);
const int32_t RAF_1XRTT = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_1XRTT);
const int32_t RAF_WCDMA = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_WCDMA);
const int32_t RAF_HSPA = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_HSPA);
const int32_t RAF_HSPAP = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_HSPAP);
const int32_t RAF_TD_SCDMA = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_TD_SCDMA);
const int32_t RAF_EVDO = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_EVDO);
const int32_t RAF_EHRPD = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_EHRPD);
const int32_t RAF_LTE = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_LTE);
const int32_t RAF_LTE_CA = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_LTE_CA);
const int32_t RAF_NR = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_NR);
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

static const std::map<int32_t, PreferredNetwork> mapNetworkModeFromRaf = {
    {RAF_AUTO, PreferredNetwork::CORE_NETWORK_MODE_AUTO},
    {GSM, PreferredNetwork::CORE_NETWORK_MODE_GSM},
    {WCDMA, PreferredNetwork::CORE_NETWORK_MODE_WCDMA},
    {LTE, PreferredNetwork::CORE_NETWORK_MODE_LTE},
    {LTE | WCDMA, PreferredNetwork::CORE_NETWORK_MODE_LTE_WCDMA},
    {LTE | WCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_LTE_WCDMA_GSM},
    {CDMA, PreferredNetwork::CORE_NETWORK_MODE_CDMA},
    {WCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_WCDMA_GSM},
    {EVDO, PreferredNetwork::CORE_NETWORK_MODE_EVDO},
    {EVDO | CDMA, PreferredNetwork::CORE_NETWORK_MODE_EVDO_CDMA},
    {WCDMA | GSM | EVDO | CDMA, PreferredNetwork::CORE_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA},
    {LTE | EVDO | CDMA, PreferredNetwork::CORE_NETWORK_MODE_LTE_EVDO_CDMA},
    {LTE | WCDMA | GSM | EVDO | CDMA, PreferredNetwork::CORE_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA},
    {RAF_TD_SCDMA, PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA},
    {RAF_TD_SCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA_GSM},
    {RAF_TD_SCDMA | WCDMA, PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA_WCDMA},
    {RAF_TD_SCDMA | WCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM},
    {LTE | RAF_TD_SCDMA, PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA},
    {LTE | RAF_TD_SCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA_GSM},
    {LTE | RAF_TD_SCDMA | WCDMA, PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA},
    {LTE | RAF_TD_SCDMA | WCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM},
    {RAF_TD_SCDMA | WCDMA | GSM | EVDO | CDMA, PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA},
    {LTE | RAF_TD_SCDMA | WCDMA | GSM | EVDO | CDMA,
        PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA},
    {NR, PreferredNetwork::CORE_NETWORK_MODE_NR},
    {NR | LTE, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE},
    {NR | LTE | WCDMA, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_WCDMA},
    {NR | LTE | WCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM},
    {NR | LTE | EVDO | CDMA, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_EVDO_CDMA},
    {NR | LTE | WCDMA | GSM | EVDO | CDMA, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA},
    {NR | LTE | RAF_TD_SCDMA, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA},
    {NR | LTE | RAF_TD_SCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_GSM},
    {NR | LTE | RAF_TD_SCDMA | WCDMA, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA},
    {NR | LTE | RAF_TD_SCDMA | WCDMA | GSM, PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM},
    {NR | LTE | RAF_TD_SCDMA | GSM | EVDO | CDMA,
        PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA},
};

static PreferredNetwork GetNetworkModeFromRaf(int32_t raf)
{
    auto iter = mapNetworkModeFromRaf.find(raf);
    if (iter != mapNetworkModeFromRaf.end()) {
        return iter->second;
    }
    return PreferredNetwork::CORE_NETWORK_MODE_AUTO;
}

static const std::map<PreferredNetwork, int32_t> mapRafFromNetworkMode = {
    {PreferredNetwork::CORE_NETWORK_MODE_AUTO, RAF_AUTO},
    {PreferredNetwork::CORE_NETWORK_MODE_GSM, GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_WCDMA, WCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE, LTE},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_WCDMA, LTE | WCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_WCDMA_GSM, LTE | WCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_WCDMA_GSM, WCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_CDMA, CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_EVDO, EVDO},
    {PreferredNetwork::CORE_NETWORK_MODE_EVDO_CDMA, EVDO | CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA, WCDMA | GSM | EVDO | CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_EVDO_CDMA, LTE | EVDO | CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA, LTE | WCDMA | GSM | EVDO | CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA, RAF_TD_SCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA_GSM, RAF_TD_SCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA_WCDMA, RAF_TD_SCDMA | WCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM, RAF_TD_SCDMA | WCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA, LTE | RAF_TD_SCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA_GSM, LTE | RAF_TD_SCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA, LTE | RAF_TD_SCDMA | WCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM, LTE | RAF_TD_SCDMA | WCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA, RAF_TD_SCDMA | WCDMA | GSM | EVDO | CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA,
        LTE | RAF_TD_SCDMA | WCDMA | GSM | EVDO | CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_NR, NR},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE, NR | LTE},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_WCDMA, NR | LTE | WCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM, NR | LTE | WCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_EVDO_CDMA, NR | LTE | EVDO | CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA, NR | LTE | WCDMA | GSM | EVDO | CDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA, NR | LTE | RAF_TD_SCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_GSM, NR | LTE | RAF_TD_SCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA, NR | LTE | RAF_TD_SCDMA | WCDMA},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM, NR | LTE | RAF_TD_SCDMA | WCDMA | GSM},
    {PreferredNetwork::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA,
        NR | LTE | RAF_TD_SCDMA | GSM | EVDO | CDMA},
};

static int32_t GetRafFromNetworkMode(PreferredNetwork preferredNetwork)
{
    auto iter = mapRafFromNetworkMode.find(preferredNetwork);
    if (iter != mapRafFromNetworkMode.end()) {
        return iter->second;
    }
    return RAF_UNKNOWN;
}

NetworkSearchManager::NetworkSearchManager(std::shared_ptr<ITelRilManager> telRilManager,
    std::shared_ptr<ISimStateManager> simStateManager, std::shared_ptr<ISimFileManager> simFileManager)
    : telRilManager_(telRilManager), simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("NetworkSearchManager");
}

bool NetworkSearchManager::InitPointer()
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init telRilManager_ is null.");
        return false;
    }
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init simStateManager_ is null.");
        return false;
    }
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init simFileManager_ is null.");
        return false;
    }
    eventLoop_ = AppExecFwk::EventRunner::Create("NetworkSearchManager");
    if (eventLoop_.get() == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager failed to create EventRunner");
        return false;
    }
    observerHandler_ = std::make_unique<ObserverHandler>();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new ObserverHandler");
        return false;
    }
    networkSearchState_ = std::make_shared<NetworkSearchState>(shared_from_this());
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchState");
        return false;
    }
    networkSearchHandler_ = std::make_shared<NetworkSearchHandler>(
        eventLoop_, shared_from_this(), telRilManager_, simFileManager_, simStateManager_);
    if (networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchHandler");
        return false;
    }
    networkSearchResult_ = std::make_unique<NetworkSearchResult>();
    if (networkSearchResult_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchResult");
        return false;
    }
    return true;
}

void NetworkSearchManager::Init()
{
    if (state_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGE("NetworkSearchManager::Init HandleRunningState started.");
        return;
    }
    if (!InitPointer()) {
        return;
    }
    networkSearchState_->Init();
    networkSearchHandler_->Init();

    eventLoop_->Run();
    state_ = HandleRunningState::STATE_RUNNING;
    TELEPHONY_LOGI("NetworkSearchManager::Init eventLoop_->Run()");

    // Prevent running crash and query the radio status at startup
    SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_STATUS);
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
    TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d", isOn);
    AirplaneMode_ = isOn ? false : true;
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

void NetworkSearchManager::RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularDataCallBack_= callback;
}

void NetworkSearchManager::UnRegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularDataCallBack_ = nullptr;
}

void NetworkSearchManager::RegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularCallCallBack_ = callback;
}

void NetworkSearchManager::UnRegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularCallCallBack_ = nullptr;
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

void NetworkSearchManager::NotifyEmergencyOpenChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyEmergencyOpenChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_EMERGENCY_STATE_OPEN);
    }
}

void NetworkSearchManager::NotifyEmergencyCloseChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyEmergencyCloseChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_EMERGENCY_STATE_CLOSE);
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

void NetworkSearchManager::NotifyNrStateChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyNrStateChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_NR_STATE_CHANGED);
    }
}

void NetworkSearchManager::NotifyNrFrequencyChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyNrFrequencyChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::ObserverHandlerId::RADIO_NR_FREQUENCY_CHANGED);
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

int32_t NetworkSearchManager::GetCsRegState(int32_t slotId) const
{
    if (networkSearchState_ != nullptr && networkSearchHandler_ != nullptr) {
        auto event = static_cast<int32_t>(networkSearchState_->GetNetworkStatus()->GetCsRegStatus());
        TELEPHONY_LOGI("NetworkSearchManager::GetCsRegState result=%{public}d", event);
        return event;
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRegState Failed");
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

int32_t NetworkSearchManager::GetRadioState() const
{
    return radioState_;
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
    int32_t modemRaf = radioCapability_.ratfamily;
    int32_t raf = GetRafFromNetworkMode(static_cast<PreferredNetwork>(networkMode));
    if (modemRaf == RAF_UNKNOWN || raf == RAF_UNKNOWN) {
        TELEPHONY_LOGE(
            "SetPreferredNetwork failed RadioAccessFamily is unknown!%{public}d %{public}d", modemRaf, raf);
        return false;
    }
    int32_t filterRaf = modemRaf & raf;
    PreferredNetwork filterMode = GetNetworkModeFromRaf(filterRaf);
    return SendEventToRilCallback2(ObserverHandler::ObserverHandlerId::RADIO_SET_PREFERRED_NETWORK_MODE, &callback,
        static_cast<int32_t>(filterMode));
}

bool NetworkSearchManager::GetPreferredNetwork(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager GetPreferredNetwork");
    return SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_PREFERRED_NETWORK_MODE);
}

bool NetworkSearchManager::SetPreferredNetwork(int32_t slotId, int32_t networkMode)
{
    TELEPHONY_LOGI("NetworkSearchManager SetPreferredNetwork networkMode:%{public}d", networkMode);
    int32_t modemRaf = radioCapability_.ratfamily;
    int32_t raf = GetRafFromNetworkMode(static_cast<PreferredNetwork>(networkMode));
    if (modemRaf == RAF_UNKNOWN || raf == RAF_UNKNOWN) {
        TELEPHONY_LOGE(
            "SetPreferredNetwork failed RadioAccessFamily is unknown!%{public}d %{public}d", modemRaf, raf);
        return false;
    }
    int32_t filterRaf = modemRaf & raf;
    PreferredNetwork filterMode = GetNetworkModeFromRaf(filterRaf);
    return SendEventToRilBase(
        ObserverHandler::ObserverHandlerId::RADIO_SET_PREFERRED_NETWORK_MODE, static_cast<int32_t>(filterMode));
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

void NetworkSearchManager::UpdatePhone(RadioTech csRadioTech)
{
    if (networkSearchHandler_ != nullptr) {
        networkSearchHandler_->UpdatePhone(csRadioTech);
        if (networkSearchHandler_->GetPhoneType() == PhoneType::PHONE_TYPE_IS_CDMA) {
            SetImei(u"");
        } else {
            SetMeid(u"");
        }
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
    if (networkSearchHandler_ == nullptr || GetRadioState() == CORE_SERVICE_POWER_OFF) {
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

sptr<CellLocation> NetworkSearchManager::GetCellLocation(int32_t slotId) const
{
    if (networkSearchHandler_ != nullptr) {
        return networkSearchHandler_->GetCellLocation();
    }
    return nullptr;
}

void NetworkSearchManager::SetMeid(std::u16string meid)
{
    meid_ = meid;
}

std::u16string NetworkSearchManager::GetMeid(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetMeid start");
    SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_MEID);
    return meid_;
}

std::u16string NetworkSearchManager::GetUniqueDeviceId(int32_t slotId) const
{
    TELEPHONY_LOGI("NetworkSearchManager::GetUniqueDeviceId start");
    if (!imei_.empty()) {
        return imei_;
    }
    if (!meid_.empty()) {
        return meid_;
    }
    return std::u16string();
}

PhoneType NetworkSearchManager::GetPhoneType() const
{
    if (networkSearchHandler_ != nullptr) {
        return networkSearchHandler_->GetPhoneType();
    }
    return PhoneType::PHONE_TYPE_IS_NONE;
}

void NetworkSearchManager::GetVoiceTech()
{
    SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_VOICE_TECH);
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
    auto fun = GetRilFunctionPointer<RilFunc_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Event>
        parameters(handlerId, 0, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_HANDLERID, RilFunc_Event>(parameters);
}

bool NetworkSearchManager::SendEventToRilBase(ObserverHandler::ObserverHandlerId handlerId, int32_t param)
{
    auto fun = GetRilFunctionPointer<RilFunc_Int_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_Event>
        parameters(handlerId, param, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Int_Event, int32_t>(parameters, param);
}

bool NetworkSearchManager::SendEventToRilBase(
    ObserverHandler::ObserverHandlerId handlerId, RadioCapabilityInfo &param)
{
    auto fun = GetRilFunctionPointer<RilFunc_Capability_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *,
        RilFunc_Capability_Event>
        parameters(handlerId, 0, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Capability_Event, RadioCapabilityInfo &>(
        parameters, param);
}

bool NetworkSearchManager::SendEventToRilBase(
    ObserverHandler::ObserverHandlerId handlerId, int32_t firstParam, int32_t secondParam)
{
    auto fun = GetRilFunctionPointer<RilFunc_Int_Int_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_Int_Event>
        parameters(handlerId, firstParam, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Int_Int_Event, int32_t, int32_t>(
        parameters, firstParam, secondParam);
}

bool NetworkSearchManager::SendEventToRilBase(
    ObserverHandler::ObserverHandlerId handlerId, int32_t firstParam, std::string secondParam)
{
    auto fun = GetRilFunctionPointer<RilFunc_Int_String_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *,
        RilFunc_Int_String_Event>
        parameters(handlerId, firstParam, nullptr, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Int_String_Event, int32_t, std::string>(
        parameters, firstParam, secondParam);
}

bool NetworkSearchManager::SendEventToRilCallback(
    ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback)
{
    auto fun = GetRilFunctionPointer<RilFunc_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Event>
        parameters(handlerId, 0, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Event>(parameters);
}

bool NetworkSearchManager::SendEventToRilCallback(
    ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback, int32_t param)
{
    auto fun = GetRilFunctionPointer<RilFunc_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Event>
        parameters(handlerId, param, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_PARAM, RilFunc_Event>(parameters);
}

bool NetworkSearchManager::SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
    const sptr<INetworkSearchCallback> *callback, RadioCapabilityInfo &param)
{
    auto fun = GetRilFunctionPointer<RilFunc_Capability_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *,
        RilFunc_Capability_Event>
        parameters(handlerId, 0, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Capability_Event, RadioCapabilityInfo &>(
        parameters, param);
}

bool NetworkSearchManager::SendEventToRilCallback2(
    ObserverHandler::ObserverHandlerId handlerId, const sptr<INetworkSearchCallback> *callback, int32_t param)
{
    auto fun = GetRilFunctionPointer<RilFunc_Int_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_Event>
        parameters(handlerId, param, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Int_Event, int32_t>(parameters, param);
}

bool NetworkSearchManager::SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
    const sptr<INetworkSearchCallback> *callback, int32_t firstParam, int32_t secondParam)
{
    auto fun = GetRilFunctionPointer<RilFunc_Int_Int_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *, RilFunc_Int_Int_Event>
        parameters(handlerId, firstParam, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Int_Int_Event, int32_t, int32_t>(
        parameters, firstParam, secondParam);
}

bool NetworkSearchManager::SendEventToRilCallback(ObserverHandler::ObserverHandlerId handlerId,
    const sptr<INetworkSearchCallback> *callback, int32_t firstParam, std::string secondParam)
{
    auto fun = GetRilFunctionPointer<RilFunc_Int_String_Event>(handlerId);
    std::tuple<ObserverHandler::ObserverHandlerId, int32_t, const sptr<INetworkSearchCallback> *,
        RilFunc_Int_String_Event>
        parameters(handlerId, firstParam, callback, fun);
    return SendEventToRil<EventGetMode::GET_EVENT_BY_INDEX, RilFunc_Int_String_Event, int32_t, std::string>(
        parameters, firstParam, secondParam);
}

bool NetworkSearchManager::IsNrSupported()
{
    GetRadioCapability(CoreManager::DEFAULT_SLOT_ID);
    return (radioCapability_.ratfamily & static_cast<int32_t>(RAF_NR)) == static_cast<int32_t>(RAF_NR);
}

int32_t NetworkSearchManager::GetRadioCapability(int32_t slotId)
{
    SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_GET_RADIO_CAPABILITY);
    return radioCapability_.ratfamily;
}

bool NetworkSearchManager::SetRadioCapability(int32_t slotId, RadioCapabilityInfo &radioCapability)
{
    return SendEventToRilBase(ObserverHandler::ObserverHandlerId::RADIO_SET_RADIO_CAPABILITY, radioCapability);
}

NrMode NetworkSearchManager::GetNrOptionMode(int32_t slotId) const
{
    return nrMode_;
}

void NetworkSearchManager::SetNrOptionMode(NrMode mode)
{
    nrMode_ = mode;
}

void NetworkSearchManager::SetFrequencyType(FrequencyType type)
{
    freqType_ = type;
}

FrequencyType NetworkSearchManager::GetFrequencyType(int32_t slotId) const
{
    return freqType_;
}

NrState NetworkSearchManager::GetNrState(int32_t slotId) const
{
    if (networkSearchState_ != nullptr && networkSearchHandler_ != nullptr) {
        auto event = networkSearchState_->GetNetworkStatus()->GetNrState();
        TELEPHONY_LOGI("NetworkSearchManager::GetNrState result=%{public}d", event);
        return event;
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetNrState Failed");
    return NrState::NR_STATE_NOT_SUPPORT;
}

void NetworkSearchManager::DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive)
{
    if (networkSearchHandler_ != nullptr) {
        networkSearchHandler_->DcPhysicalLinkActiveUpdate(isActive);
    }
}
} // namespace Telephony
} // namespace OHOS
