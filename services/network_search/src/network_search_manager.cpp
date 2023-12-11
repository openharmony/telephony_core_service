/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include <parameters.h>
#include <string_ex.h>
#include <securec.h>
#include <cinttypes>

#include "core_service_errors.h"
#include "enum_convert.h"
#include "mcc_pool.h"
#include "network_search_types.h"
#include "parameter.h"
#include "telephony_common_utils.h"
#include "telephony_config.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
const size_t MCC_LEN = 3;
const int32_t SERVICE_TYPE_UNKNOWN = -1;
const int32_t SERVICE_TYPE_LTE = 0;
const int32_t SERVICE_TYPE_NR = 1;
const int32_t SERVICE_ABILITY_OFF = 0;
const int32_t SERVICE_ABILITY_ON = 1;
const int32_t SYS_PARAMETER_SIZE = 256;
const int32_t INVALID_DELAY_TIME = 0;
constexpr const char *NO_DELAY_TIME__CONFIG = "0";
constexpr const char *CFG_TECH_UPDATE_TIME = "persist.radio.cfg.update.time";

NetworkSearchManager::NetworkSearchManager(
    std::shared_ptr<ITelRilManager> telRilManager, std::shared_ptr<ISimManager> simManager)
    : telRilManager_(telRilManager), simManager_(simManager)
{
    TELEPHONY_LOGI("NetworkSearchManager");
}

NetworkSearchManager::~NetworkSearchManager()
{
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        std::shared_ptr<NetworkSearchManagerInner> inner = FindManagerInner(slotId);
        if (inner != nullptr) {
            inner->UnRegisterSetting();
            inner->UnRegisterDeviceStateObserver();
        }
    }
}

bool NetworkSearchManager::InitPointer(std::shared_ptr<NetworkSearchManagerInner> &inner, int32_t slotId)
{
    if (inner == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::InitPointer failed . inner is null");
        return false;
    }
    std::string name = "NetworkSearchManager_";
    name.append(std::to_string(slotId));
    inner->eventLoop_ = AppExecFwk::EventRunner::Create(name.c_str());
    if (inner->eventLoop_.get() == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager failed to create EventRunner slotId:%{public}d", slotId);
        return false;
    }
    inner->observerHandler_ = std::make_unique<ObserverHandler>();
    if (inner->observerHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new ObserverHandler slotId:%{public}d", slotId);
        return false;
    }
    inner->networkSearchState_ = std::make_shared<NetworkSearchState>(shared_from_this(), slotId);
    if (inner->networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchState slotId:%{public}d", slotId);
        return false;
    }
    inner->networkSearchHandler_ = std::make_shared<NetworkSearchHandler>(
        inner->eventLoop_, shared_from_this(), telRilManager_, simManager_, slotId);
    if (inner->networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchHandler slotId:%{public}d", slotId);
        return false;
    }
    inner->networkSearchResult_ = std::make_unique<NetworkSearchResult>();
    if (inner->networkSearchResult_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchResult slotId:%{public}d", slotId);
        return false;
    }
    inner->deviceStateHandler_ = std::make_shared<DeviceStateHandler>(shared_from_this(), telRilManager_, slotId);
    if (inner->deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new DeviceStateHandler slotId:%{public}d", slotId);
        return false;
    }

    return true;
}

bool NetworkSearchManagerInner::RegisterSetting()
{
    settingAutoTimeObserver_ = new AutoTimeObserver(networkSearchHandler_);
    airplaneModeObserver_ = new AirplaneModeObserver(networkSearchHandler_);
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingAutoTimeObserver_ == nullptr || airplaneModeObserver_ == nullptr || settingHelper == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::RegisterSetting is null.");
        return false;
    }

    Uri autoTimeUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIME_URI);
    Uri airplaneModeUri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    settingHelper->RegisterSettingsObserver(autoTimeUri, settingAutoTimeObserver_);
    settingHelper->RegisterSettingsObserver(airplaneModeUri, airplaneModeObserver_);
    return true;
}

bool NetworkSearchManagerInner::UnRegisterSetting()
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::UnRegisterSetting is null.");
        return false;
    }

    Uri autoTimeUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIME_URI);
    Uri airplaneModeUri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    settingHelper->UnRegisterSettingsObserver(autoTimeUri, settingAutoTimeObserver_);
    settingHelper->UnRegisterSettingsObserver(airplaneModeUri, airplaneModeObserver_);
    return true;
}

bool NetworkSearchManagerInner::RegisterDeviceStateObserver()
{
    deviceStateObserver_ = std::make_shared<DeviceStateObserver>();
    deviceStateObserver_->StartEventSubscriber(deviceStateHandler_);
    return true;
}

bool NetworkSearchManagerInner::UnRegisterDeviceStateObserver()
{
    if (deviceStateObserver_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::UnRegisterDeviceStateObserver deviceStateObserver_ is null.");
        return false;
    }
    deviceStateObserver_->StopEventSubscriber();
    return true;
}

bool NetworkSearchManager::OnInit()
{
    TELEPHONY_LOGI("NetworkSearchManager::Init");
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init telRilManager_ is null.");
        return false;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init simManager_ is null.");
        return false;
    }
    eventSender_ = std::make_unique<EventSender>(telRilManager_, shared_from_this());
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("failed to create new EventSender");
        return false;
    }
    ClearManagerInner();
    bool mode = false;
    if (GetAirplaneMode(mode) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("NetworkSearchManager::Init GetAirplaneMode fail");
    }
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        std::shared_ptr<NetworkSearchManagerInner> inner = FindManagerInner(slotId);
        if (inner == nullptr) {
            inner = std::make_shared<NetworkSearchManagerInner>();
            AddManagerInner(slotId, inner);
        }
        if (inner != nullptr && eventSender_ != nullptr) {
            if (inner->state_ == HandleRunningState::STATE_RUNNING) {
                TELEPHONY_LOGE("NetworkSearchManager::Init HandleRunningState is running. slotId:%{public}d", slotId);
                continue;
            }
            if (!InitPointer(inner, slotId)) {
                ClearManagerInner();
                return false;
            }
            if (!inner->Init()) {
                ClearManagerInner();
                return false;
            }
            SetLocalAirplaneMode(slotId, mode);
            TELEPHONY_LOGI("NetworkSearchManager::Init airplaneMode:%{public}d slotId:%{public}d", mode, slotId);
            // Prevent running crash and query the radio status at startup
            eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_STATUS);
        }
    }
    delayTime_ = GetDelayNotifyTime();
    TELEPHONY_LOGI("NetworkSearchManager::Init success");
    return true;
}

std::shared_ptr<NetworkSearchState> NetworkSearchManager::GetNetworkSearchState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        TELEPHONY_LOGD("NetworkSearchManager::GetNetworkSearchState slotId:%{public}d", slotId);
        return inner->networkSearchState_;
    }
    return nullptr;
}

void NetworkSearchManager::SetRadioState(int32_t slotId, bool isOn, int32_t rst)
{
    TELEPHONY_LOGD("NetworkSearchManager SetRadioState isOn:%{public}d slotId:%{public}d", isOn, slotId);
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return;
    }
    int32_t fun = static_cast<int32_t>(isOn);
    eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_STATUS, fun, rst);
}

int32_t NetworkSearchManager::SetRadioState(int32_t slotId, bool isOn, int32_t rst, NSCALLBACK &callback)
{
    TELEPHONY_LOGD("NetworkSearchManager SetRadioState isOn:%{public}d slotId:%{public}d", isOn, slotId);
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t fun = static_cast<int32_t>(isOn);
    if (!eventSender_->SendCallback(slotId, RadioEvent::RADIO_SET_STATUS, &callback, fun, rst)) {
        TELEPHONY_LOGE("slotId:%{public}d SetRadioState SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

void NetworkSearchManager::RegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what)
{
    TELEPHONY_LOGD("NetworkSearchManager::RegisterCoreNotify %{public}d slotId:%{public}d", what, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->RegObserver(what, handler);
        }
    }
}

void NetworkSearchManager::UnRegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what)
{
    TELEPHONY_LOGD("NetworkSearchManager::UnRegisterCoreNotify %{public}d slotId:%{public}d", what, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->Remove(what, handler);
        }
    }
}

void NetworkSearchManager::RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularDataCallBack_ = callback;
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

void NetworkSearchManager::NotifyPsRoamingOpenChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyPsRoamingOpenChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_ROAMING_OPEN);
        }
    }
}

void NetworkSearchManager::NotifyPsRoamingCloseChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyPsRoamingCloseChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_ROAMING_CLOSE);
        }
    }
}

void NetworkSearchManager::NotifyEmergencyOpenChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyEmergencyOpenChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_EMERGENCY_STATE_OPEN);
        }
    }
}

void NetworkSearchManager::NotifyEmergencyCloseChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyEmergencyCloseChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_EMERGENCY_STATE_CLOSE);
        }
    }
}

void NetworkSearchManager::NotifyPsRatChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyPsRatChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_RAT_CHANGED);
        }
    }
}

void NetworkSearchManager::NotifyPsConnectionAttachedChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyPsConnectionAttachedChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_CONNECTION_ATTACHED);
        }
    }
}

void NetworkSearchManager::NotifyPsConnectionDetachedChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyPsConnectionDetachedChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_CONNECTION_DETACHED);
        }
    }
}

void NetworkSearchManager::NotifyNrStateChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyNrStateChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_NR_STATE_CHANGED);
        }
    }
}

void NetworkSearchManager::NotifyNrFrequencyChanged(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::NotifyNrFrequencyChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_NR_FREQUENCY_CHANGED);
        }
    }
}

void NetworkSearchManager::NotifyFactoryReset(int32_t slotId)
{
    TELEPHONY_LOGD("NotifyFactoryReset slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_FACTORY_RESET);
        }
    }
}

int32_t NetworkSearchManager::GetPsRadioTech(int32_t slotId, int32_t &psRadioTech)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech Failed slotId:%{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if ((inner->networkSearchState_ == nullptr) || (inner->networkSearchState_->GetNetworkStatus() == nullptr)) {
        TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech failed due to nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    psRadioTech = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRadioTech());
    if (TELEPHONY_EXT_WRAPPER.getRadioTechExt_ != nullptr) { 
        TELEPHONY_EXT_WRAPPER.getRadioTechExt_(slotId, psRadioTech); 
    }
    TELEPHONY_LOGD("NetworkSearchManager::GetPsRadioTech result=%{public}d slotId:%{public}d", psRadioTech, slotId);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetCsRadioTech(int32_t slotId, int32_t &csRadioTech)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech Failed slotId:%{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if ((inner->networkSearchState_ == nullptr) || (inner->networkSearchState_->GetNetworkStatus() == nullptr)) {
        TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech failed due to nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    csRadioTech = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetCsRadioTech());
    if (TELEPHONY_EXT_WRAPPER.getRadioTechExt_ != nullptr) { 
        TELEPHONY_EXT_WRAPPER.getRadioTechExt_(slotId, csRadioTech); 
    }
    TELEPHONY_LOGD("NetworkSearchManager::GetCsRadioTech result=%{public}d slotId:%{public}d", csRadioTech, slotId);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetPsRegState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRegStatus());
            TELEPHONY_LOGD("NetworkSearchManager::GetPsRegState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetPsRegState failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRegState Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetCsRegState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetCsRegStatus());
            TELEPHONY_LOGD("NetworkSearchManager::GetCsRegState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetCsRegState failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRegState Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetPsRoamingState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRoamingStatus());
            TELEPHONY_LOGD(
                "NetworkSearchManager::GetPsRoamingState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetPsRoamingState failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRoamingState Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

std::u16string NetworkSearchManager::GetOperatorNumeric(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::GetOperatorNumeric start slotId:%{public}d", slotId);
    std::u16string str;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = inner->networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
            str = Str8ToStr16(event);
            TELEPHONY_LOGD(
                "NetworkSearchManager::GetOperatorNumeric result=%{public}s slotId:%{public}d", event.c_str(), slotId);
        }
    }
    return str;
}

int32_t NetworkSearchManager::GetOperatorName(int32_t slotId, std::u16string &operatorName)
{
    operatorName = u"";
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto longOperatorName = inner->networkSearchState_->GetNetworkStatus()->GetLongOperatorName();
            operatorName = Str8ToStr16(longOperatorName);
            TELEPHONY_LOGD("NetworkSearchManager::GetOperatorName result:%{public}s slotId:%{public}d",
                longOperatorName.c_str(), slotId);
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    return TELEPHONY_ERR_SLOTID_INVALID;
}

int32_t NetworkSearchManager::GetNetworkStatus(int32_t slotId, sptr<NetworkState> &networkState)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr) {
            networkState = inner->networkSearchState_->GetNetworkStatus().release();
            if (TELEPHONY_EXT_WRAPPER.getNetworkStatusExt_ != nullptr) {
                TELEPHONY_EXT_WRAPPER.getNetworkStatusExt_(slotId, networkState);
            }
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    return TELEPHONY_ERR_SLOTID_INVALID;
}

void NetworkSearchManager::SetRadioStateValue(int32_t slotId, ModemPowerState radioState)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->radioState_ = radioState;
    }
}

void NetworkSearchManager::SetNetworkSelectionValue(int32_t slotId, SelectionMode selection)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->selection_ = selection;
    }
}

int32_t NetworkSearchManager::GetRadioState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        return inner->radioState_;
    }
    return ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE;
}

int32_t NetworkSearchManager::GetRadioState(int32_t slotId, NSCALLBACK &callback)
{
    TELEPHONY_LOGD("NetworkSearchManager::GetRadioState... slotId:%{public}d", slotId);
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_STATUS, &callback)) {
        TELEPHONY_LOGE("slotId:%{public}d GetRadioState SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || inner->networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    inner->networkSearchHandler_->GetSignalInfo(signals);
    if (TELEPHONY_EXT_WRAPPER.getSignalInfoListExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.getSignalInfoListExt_(slotId, signals);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetNetworkSearchInformation(int32_t slotId, NSCALLBACK &callback)
{
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!eventSender_->SendCallback(slotId, RadioEvent::RADIO_NETWORK_SEARCH_RESULT, &callback)) {
        TELEPHONY_LOGE("slotId:%{public}d GetNetworkSearchInformation SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

void NetworkSearchManager::SetNetworkSearchResultValue(
    int32_t slotId, int32_t listSize, const std::vector<NetworkInformation> &operatorInfo)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchResult_ != nullptr) {
            inner->networkSearchResult_->SetNetworkSearchResultValue(listSize, operatorInfo);
        }
    }
}

sptr<NetworkSearchResult> NetworkSearchManager::GetNetworkSearchInformationValue(int32_t slotId)
{
    sptr<NetworkSearchResult> networkSearchResult = new (std::nothrow) NetworkSearchResult;
    if (networkSearchResult == nullptr) {
        TELEPHONY_LOGE(
            "GetNetworkSearchInformationValue failed to create new NetWorkSearchResult slotId:%{public}d", slotId);
        return nullptr;
    }

    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchResult_ == nullptr) {
            TELEPHONY_LOGE("GetNetworkSearchInformationValue networkSearchResult_ is null slotId:%{public}d", slotId);
            return nullptr;
        }

        int32_t listSize = inner->networkSearchResult_->GetNetworkSearchInformationSize();
        std::vector<NetworkInformation> operatorInfoList = inner->networkSearchResult_->GetNetworkSearchInformation();
        networkSearchResult->SetNetworkSearchResultValue(listSize, operatorInfoList);
        return networkSearchResult;
    }
    return nullptr;
}

int32_t NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr && eventSender_ != nullptr) {
        eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE);
        return static_cast<int32_t>(inner->selection_);
    }
    return static_cast<int32_t>(SelectionMode::MODE_TYPE_UNKNOWN);
}

int32_t NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId, NSCALLBACK &callback)
{
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    bool ret = eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE, &callback);
    if (!ret) {
        TELEPHONY_LOGE("slotId:%{public}d GetNetworkSelectionMode SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

bool NetworkSearchManager::SetNetworkSelectionMode(
    int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation, bool resumeSelection)
{
    TELEPHONY_LOGD(
        "NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d slotId:%{public}d", selectMode, slotId);
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return false;
    }
    std::string plmnNumeric = "";
    std::string operatorCurrentRadio = "";
    std::string operatorInfo = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
        operatorCurrentRadio = std::to_string(networkInformation->GetRadioTech());
        operatorInfo = plmnNumeric + "," + operatorCurrentRadio;
    }
    return eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, selectMode, operatorInfo);
}

int32_t NetworkSearchManager::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection, NSCALLBACK &callback)
{
    TELEPHONY_LOGD(
        "NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d slotId:%{public}d", selectMode, slotId);
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string plmnNumeric = "";
    std::string operatorCurrentRadio = "";
    std::string operatorInfo = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
        operatorCurrentRadio = std::to_string(networkInformation->GetRadioTech());
        operatorInfo = plmnNumeric + "," + operatorCurrentRadio;
    }
    bool ret = eventSender_->SendCallback(
        slotId, RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, &callback, selectMode, operatorInfo);
    if (!ret) {
        TELEPHONY_LOGE("slotId:%{public}d SetNetworkSelectionMode SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode)
{
    std::string iso = "";
    countryCode = u"";
    auto inner = FindManagerInner(slotId);
    if ((inner == nullptr) || (inner->networkSearchHandler_ == nullptr)) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (inner->networkSearchState_ == nullptr || inner->networkSearchState_->GetNetworkStatus() == nullptr) {
        TELEPHONY_LOGE(
            "NetworkSearchManager::GetIsoCountryCodeForNetwork Failed due to nullptr, slotId:%{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string plmn = inner->networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
    size_t len = plmn.length();
    if (len >= MCC_LEN) {
        std::string mcc = plmn.substr(0, MCC_LEN);
        int32_t value = 0;
        bool succ = StrToInt(mcc, value);
        if (succ) {
            iso = MccPool::MccCountryCode(value);
        } else {
            TELEPHONY_LOGE("GetIsoCountryCodeForNetwork parse Failed!! slotId:%{public}d", slotId);
        }
        TELEPHONY_LOGD(
            "NetworkSearchManager::GetIsoCountryCodeForNetwork mcc=%{public}s code=%{public}d slotId:%{public}d",
            mcc.c_str(), value, slotId);
    }

    countryCode = Str8ToStr16(iso);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetPreferredNetwork(int32_t slotId, NSCALLBACK &callback)
{
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE, &callback)) {
        TELEPHONY_LOGE("slotId:%{public}d GetPreferredNetwork SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::SetPreferredNetwork(int32_t slotId, int32_t networkMode, NSCALLBACK &callback)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("SetPreferredNetwork simManager_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("eventSender_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t modemRaf = simManager_->GetRadioProtocolTech(slotId);
    int32_t raf = NetworkUtils::GetRafFromNetworkMode(static_cast<PreferredNetworkMode>(networkMode));
    if (modemRaf == static_cast<int32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_UNKNOWN)) {
        TELEPHONY_LOGE("SetPreferredNetwork failed modemRaf:%{public}d slotId:%{public}d", modemRaf, slotId);
        return CORE_SERVICE_RADIO_PROTOCOL_TECH_UNKNOWN;
    }
    if (raf == static_cast<int32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_UNKNOWN)) {
        TELEPHONY_LOGE("SetPreferredNetwork failed raf:%{public}d slotId:%{public}d", raf, slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    int32_t filterMode = static_cast<int32_t>(NetworkUtils::GetNetworkModeFromRaf(modemRaf & raf));
    TELEPHONY_LOGI("filterMode:%{public}d slotId:%{public}d", filterMode, slotId);
    SetCachePreferredNetworkValue(slotId, filterMode);
    if (!eventSender_->SendCallbackEx(slotId, RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE, &callback, filterMode)) {
        TELEPHONY_LOGE("slotId:%{public}d SetPreferredNetwork SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetPreferredNetwork(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager GetPreferredNetwork slotId:%{public}d", slotId);
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE)) {
        TELEPHONY_LOGE("slotId:%{public}d GetPreferredNetwork SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::SetCachePreferredNetworkValue(int32_t slotId, int32_t networkMode)
{
    TELEPHONY_LOGD("SetCachePreferredNetworkValue slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    inner->preferredNetworkValue_ = networkMode;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetCachePreferredNetworkValue(int32_t slotId, int32_t &networkMode)
{
    TELEPHONY_LOGD("GetCachePreferredNetworkValue slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    networkMode = inner->preferredNetworkValue_;
    return TELEPHONY_ERR_SUCCESS;
}

bool NetworkSearchManager::SetPreferredNetwork(int32_t slotId, int32_t networkMode)
{
    if (simManager_ == nullptr || eventSender_ == nullptr) {
        TELEPHONY_LOGE("simManager_ or eventSender_ is nullptr");
        return false;
    }

    int32_t modemRaf = simManager_->GetRadioProtocolTech(slotId);
    int32_t raf = NetworkUtils::GetRafFromNetworkMode(static_cast<PreferredNetworkMode>(networkMode));
    if (modemRaf == static_cast<int32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_UNKNOWN) ||
        raf == static_cast<int32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_UNKNOWN)) {
        TELEPHONY_LOGE(
            "SetPreferredNetwork failed modemRaf:%{public}d raf:%{public}d slotId:%{public}d", modemRaf, raf, slotId);
        return false;
    }
    int32_t filterMode = static_cast<int32_t>(NetworkUtils::GetNetworkModeFromRaf(modemRaf & raf));
    TELEPHONY_LOGI("modemRaf:%{public}d, raf:%{public}d, filterMode:%{public}d slotId:%{public}d", modemRaf, raf,
        filterMode, slotId);
    SetCachePreferredNetworkValue(slotId, filterMode);
    return eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE, filterMode);
}

void NetworkSearchManager::SavePreferredNetworkValue(int32_t slotId, int32_t networkMode)
{
    TELEPHONY_LOGD("NetworkSearchManager SavePreferredNetworkValue slotId:%{public}d, networkMode:%{public}d", slotId,
        networkMode);
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE + "_" + std::to_string(slotId);
    std::string value = std::to_string(networkMode);
    if (settingHelper->Update(uri, key, value) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Update %{public}s fail", key.c_str());
    }
}

int32_t NetworkSearchManager::UpdateRadioOn(int32_t slotId)
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_AIRPLANE_MODE;
    int32_t airplaneModeOff = 0;
    std::string value = std::to_string(airplaneModeOff);
    int32_t ret = settingHelper->Update(uri, key, value);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("NetworkSearchManager::UpdateRadioOn Update fail");
        return ret;
    }
    SetRadioState(slotId, CORE_SERVICE_POWER_ON, 0);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED);
    want.SetParam("state", false);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    if (!EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr)) {
        TELEPHONY_LOGE("PublishCommonEvent fail");
        return TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t NetworkSearchManager::GetPreferredNetworkValue(int32_t slotId) const
{
    int32_t networkMode = PREFERRED_NETWORK_TYPE;
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return networkMode;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE + "_" + std::to_string(slotId);
    std::string value = "";
    if (settingHelper->Query(uri, key, value) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGI("Query %{public}s fail", key.c_str());
        return networkMode;
    }

    bool succ = StrToInt(value, networkMode);
    TELEPHONY_LOGD("NetworkSearchManager GetPreferredNetworkValue succ:%{public}d, slotId:%{public}d, "
                   "networkMode:%{public}d",
        slotId, succ, networkMode);
    return networkMode;
}

void NetworkSearchManager::UpdatePhone(int32_t slotId, RadioTech csRadioTech, const RadioTech &psRadioTech)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->UpdatePhone(csRadioTech, psRadioTech);
        }
    }
}

int32_t NetworkSearchManager::GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info)
{
    TELEPHONY_LOGD("slotId:%{public}d, imsSrvType:%{public}d", slotId, imsSrvType);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManagerInner is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (inner->networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("networkSearchState is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return inner->networkSearchState_->GetImsStatus(imsSrvType, info);
}

void NetworkSearchManager::SetImei(int32_t slotId, std::u16string imei)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->imei_ = imei;
    }
}

int32_t NetworkSearchManager::GetImei(int32_t slotId, std::u16string &imei)
{
    TELEPHONY_LOGD("NetworkSearchManager::GetImei start slotId:%{public}d", slotId);
    imei = u"";
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner or eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (inner->imei_.empty()) {
        eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_IMEI);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imei = inner->imei_;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->GetCellInfoList(cellInfo);
            if (TELEPHONY_EXT_WRAPPER.getCellInfoList_ != nullptr) {
                TELEPHONY_EXT_WRAPPER.getCellInfoList_(slotId, cellInfo);
            }
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t NetworkSearchManager::SendUpdateCellLocationRequest(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ == nullptr || GetRadioState(slotId) == CORE_SERVICE_POWER_OFF) {
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        return inner->networkSearchHandler_->SendUpdateCellLocationRequest();
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

void NetworkSearchManager::UpdateCellLocation(int32_t slotId, int32_t techType, int32_t cellId, int32_t lac)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->UpdateCellLocation(techType, cellId, lac);
        }
    }
}

sptr<CellLocation> NetworkSearchManager::GetCellLocation(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            return inner->networkSearchHandler_->GetCellLocation();
        }
    }
    return nullptr;
}

void NetworkSearchManager::SetMeid(int32_t slotId, std::u16string meid)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->meid_ = meid;
    }
}

int32_t NetworkSearchManager::GetMeid(int32_t slotId, std::u16string &meid)
{
    TELEPHONY_LOGD("NetworkSearchManager::GetMeid start slotId:%{public}d", slotId);
    meid = u"";
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner or eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (inner->meid_.empty()) {
        eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_MEID);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    meid = inner->meid_;
    return TELEPHONY_ERR_SUCCESS;
}

void NetworkSearchManager::SetLocateUpdate(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::SetLocateUpdate start slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGI("NetworkSearchManager::SetLocateUpdate inner null slotId:%{public}d", slotId);
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_LOCATION_UPDATE);
    if (event != nullptr && inner->networkSearchHandler_ != nullptr) {
        event->SetOwner(inner->networkSearchHandler_);
        telRilManager_->SetLocateUpdates(slotId, HRilRegNotifyMode::REG_NOTIFY_STAT_LAC_CELLID, event);
    }
}

int32_t NetworkSearchManager::GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId)
{
    TELEPHONY_LOGD("NetworkSearchManager::GetUniqueDeviceId start slotId:%{public}d", slotId);
    deviceId = u"";
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (GetPhoneType(slotId) == PhoneType::PHONE_TYPE_IS_GSM) {
        if (!inner->imei_.empty()) {
            deviceId = inner->imei_;
            return TELEPHONY_ERR_SUCCESS;
        }
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    } else {
        if (!inner->meid_.empty()) {
            deviceId = inner->meid_;
            return TELEPHONY_ERR_SUCCESS;
        }
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t NetworkSearchManager::FactoryReset(int32_t slotId)
{
    bool ret = SetNetworkSelectionMode(slotId, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), nullptr, true);
    if (!ret) {
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t networkMode = PREFERRED_NETWORK_TYPE;
    ret = SetPreferredNetwork(slotId, networkMode);
    if (!ret) {
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    NotifyFactoryReset(slotId);
    return TELEPHONY_ERR_SUCCESS;
}

PhoneType NetworkSearchManager::GetPhoneType(int32_t slotId)
{
    PhoneType phoneType = PhoneType::PHONE_TYPE_IS_NONE;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            phoneType = inner->networkSearchHandler_->GetPhoneType();
        }
    }
    TELEPHONY_LOGI("NetworkSearchManager::GetPhoneType type:%{public}d start slotId:%{public}d", phoneType, slotId);
    return phoneType;
}

void NetworkSearchManager::GetVoiceTech(int32_t slotId)
{
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return;
    }
    eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_VOICE_TECH);
    eventSender_->SendCallback(
        slotId, RadioEvent::RADIO_OPERATOR, nullptr, NetworkSearchManagerInner::SERIAL_NUMBER_EXEMPT);
}

bool NetworkSearchManager::IsNrSupported(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is nullptr");
        return false;
    }
    int32_t modemRaf = simManager_->GetRadioProtocolTech(slotId);
    if (TELEPHONY_EXT_WRAPPER.isNrSupportedNative_ != nullptr) {
        return TELEPHONY_EXT_WRAPPER.isNrSupportedNative_(modemRaf);
    }
    return (static_cast<uint32_t>(modemRaf) & static_cast<uint32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_NR)) ==
        static_cast<uint32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_NR);
}

int32_t NetworkSearchManager::HandleRrcStateChanged(int32_t slotId, int32_t status)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (inner->rrcConnectionStatus_ == status) {
        TELEPHONY_LOGI("slotId:%{public}d rrc state is not change.", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    inner->rrcConnectionStatus_ = status;
    if (status == RRC_CONNECTED_STATUS || status == RRC_IDLE_STATUS) {
        inner->networkSearchHandler_->HandleRrcStateChanged(status);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::RevertLastTechnology(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || inner->networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return inner->networkSearchHandler_->RevertLastTechnology();
}

int32_t NetworkSearchManager::GetRrcConnectionState(int32_t slotId, int32_t &status)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner or eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_RRC_CONNECTION_STATE);
    status = inner->rrcConnectionStatus_;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::UpdateRrcConnectionState(int32_t slotId, int32_t &status)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    status = inner->rrcConnectionStatus_;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetNrOptionMode(int32_t slotId, NrMode &mode)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner or eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_NR_OPTION_MODE);
    mode = inner->nrMode_;
    if (TELEPHONY_EXT_WRAPPER.getNrOptionModeExtend_ != nullptr) { 
        TELEPHONY_EXT_WRAPPER.getNrOptionModeExtend_(slotId, mode);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetNrOptionMode(int32_t slotId, NSCALLBACK &callback)
{
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_NR_OPTION_MODE, &callback)) {
        TELEPHONY_LOGE("slotId:%{public}d GetNrOptionMode SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::UpdateNrOptionMode(int32_t slotId, NrMode mode)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    inner->nrMode_ = mode;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::SetNrOptionMode(int32_t slotId, int32_t mode)
{
    TELEPHONY_LOGD("NetworkSearchManager SetNrOptionMode mode:%{public}d slotId:%{public}d", mode, slotId);
    if (mode < static_cast<int32_t>(NrMode::NR_MODE_UNKNOWN) ||
        mode > static_cast<int32_t>(NrMode::NR_MODE_NSA_AND_SA)) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_NR_OPTION_MODE, mode);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::SetNrOptionMode(int32_t slotId, int32_t mode, NSCALLBACK &callback)
{
    TELEPHONY_LOGD("NetworkSearchManager SetNrOptionMode mode:%{public}d slotId:%{public}d", mode, slotId);
    if (mode < static_cast<int32_t>(NrMode::NR_MODE_UNKNOWN) ||
        mode > static_cast<int32_t>(NrMode::NR_MODE_NSA_AND_SA)) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!eventSender_->SendCallbackEx(slotId, RadioEvent::RADIO_SET_NR_OPTION_MODE, &callback, mode)) {
        TELEPHONY_LOGE("slotId:%{public}d SetNrOptionMode SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

void NetworkSearchManager::SetFrequencyType(int32_t slotId, FrequencyType type)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        inner->freqType_ = type;
    }
}

FrequencyType NetworkSearchManager::GetFrequencyType(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        return inner->freqType_;
    }
    return FrequencyType::FREQ_TYPE_UNKNOWN;
}

NrState NetworkSearchManager::GetNrState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = inner->networkSearchState_->GetNetworkStatus()->GetNrState();
            TELEPHONY_LOGI("NetworkSearchManager::GetNrState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetNrState failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetNrState Failed slotId:%{public}d", slotId);
    return NrState::NR_STATE_NOT_SUPPORT;
}

void NetworkSearchManager::DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            int active = isActive ? 1 : 0;
            auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_DATA_CONNECT_ACTIVE, active);
            inner->networkSearchHandler_->SendEvent(event);
        }
    }
}

int32_t NetworkSearchManager::NotifyCallStatusToNetworkSearch(int32_t slotId, int32_t callStatus)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    switch (callStatus) {
        case static_cast<int32_t>(TelephonyCallState::CALL_STATUS_ACTIVE):
        case static_cast<int32_t>(TelephonyCallState::CALL_STATUS_HOLDING):
        case static_cast<int32_t>(TelephonyCallState::CALL_STATUS_DIALING):
        case static_cast<int32_t>(TelephonyCallState::CALL_STATUS_INCOMING):
        case static_cast<int32_t>(TelephonyCallState::CALL_STATUS_WAITING):
            inner->hasCall_ = true;
            break;
        default:
            inner->hasCall_ = false;
            break;
    }
    TELEPHONY_LOGI("slotId:%{public}d callStatus:%{public}d hasCall:%{public}d", slotId, callStatus, inner->hasCall_);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetDelayNotifyTime()
{
    char param[SYS_PARAMETER_SIZE] = { 0 };
    int32_t delayTime = 0;
    int32_t code = GetParameter(CFG_TECH_UPDATE_TIME, NO_DELAY_TIME__CONFIG, param, SYS_PARAMETER_SIZE);
    std::string time = param;
    if (code <= 0 || !IsValidDecValue(time)) {
        delayTime = std::stoi(NO_DELAY_TIME__CONFIG);
    } else {
        delayTime = std::stoi(time);
    }
    return delayTime;
}

int32_t NetworkSearchManager::HandleNotifyStateChangeWithDelay(int32_t slotId, bool isNeedDelay)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || inner->networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    auto delayEvent = AppExecFwk::InnerEvent::Get(RadioEvent::DELAY_NOTIFY_STATE_CHANGE);
    uint32_t delayEventId = static_cast<uint32_t>(RadioEvent::DELAY_NOTIFY_STATE_CHANGE);
    if (isNeedDelay) {
        if (inner->networkSearchHandler_->HasInnerEvent(delayEventId)) {
            TELEPHONY_LOGI("Has delay event, return. slotId:%{public}d", slotId);
        } else {
            inner->networkSearchHandler_->SendEvent(delayEvent, delayTime_);
            TELEPHONY_LOGI("Need delay, delayTime:%{public}d slotId:%{public}d", delayTime_, slotId);
        }
    } else {
        TELEPHONY_LOGI("Do not need delay, slotId:%{public}d", slotId);
        if (inner->networkSearchHandler_->HasInnerEvent(delayEventId)) {
            TELEPHONY_LOGI("Remove delay event, slotId:%{public}d", slotId);
            inner->networkSearchHandler_->RemoveEvent(delayEventId);
        }
        auto event = AppExecFwk::InnerEvent::Get(RadioEvent::NOTIFY_STATE_CHANGE);
        inner->networkSearchHandler_->SendEvent(event);
    }
    return TELEPHONY_ERR_SUCCESS;
}

bool NetworkSearchManager::IsNeedDelayNotify(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || inner->networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return false;
    }
    if ((inner->networkSearchState_ == nullptr) || (inner->networkSearchState_->GetNetworkStatus() == nullptr)) {
        TELEPHONY_LOGE("NetworkSearchManager::IsNeedDelayNotify failed due to nullptr!");
        return false;
    }
    if (delayTime_ <= INVALID_DELAY_TIME) {
        TELEPHONY_LOGI("The system properties are not configured with a valid delay time.");
        return false;
    }
    int32_t networkCapabilityState = 0;
    GetNetworkCapability(slotId, SERVICE_TYPE_NR, networkCapabilityState);
    if (networkCapabilityState == SERVICE_ABILITY_OFF) {
        TELEPHONY_LOGI("The NR switch is closed.");
        return false;
    }
    RegServiceState regState = RegServiceState::REG_STATE_UNKNOWN;
    inner->networkSearchHandler_->GetRegServiceState(regState);
    if (regState == RegServiceState::REG_STATE_NO_SERVICE) {
        TELEPHONY_LOGI("The reg state is no service.");
        return false;
    }
    RadioTech cfgTech = inner->networkSearchState_->GetNetworkStatus()->GetCfgTech();
    if ((cfgTech != RadioTech::RADIO_TECHNOLOGY_LTE) && (cfgTech != RadioTech::RADIO_TECHNOLOGY_LTE_CA)) {
        TELEPHONY_LOGI("The cfgTech[%{public}d] is not LTE, slotId:%{public}d", cfgTech, slotId);
        return false;
    }
    if (inner->hasCall_) {
        TELEPHONY_LOGI("Has call, slotId:%{public}d", slotId);
        return false;
    }
    RadioTech lastCfgTech = inner->networkSearchState_->GetNetworkStatus()->GetLastCfgTech();
    RadioTech lastPsRadioTech = inner->networkSearchState_->GetNetworkStatus()->GetLastPsRadioTech();
    if ((lastCfgTech == RadioTech::RADIO_TECHNOLOGY_NR) && (lastPsRadioTech != RadioTech::RADIO_TECHNOLOGY_NR) &&
        (cfgTech == RadioTech::RADIO_TECHNOLOGY_LTE || (cfgTech == RadioTech::RADIO_TECHNOLOGY_LTE_CA))) {
        TELEPHONY_LOGI(
            "lastCfgTech:%{public}d lastPsTech:%{public}d slotId:%{public}d", lastCfgTech, lastPsRadioTech, slotId);
        return true;
    }
    return false;
}

int32_t NetworkSearchManager::ProcessNotifyStateChangeEvent(int32_t slotId)
{
    TELEPHONY_LOGI("Start process network state notify event, slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || inner->networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    bool isNeedDelay = IsNeedDelayNotify(slotId);
    if (isNeedDelay) {
        TELEPHONY_LOGI("revert last tech. slotId:%{public}d", slotId);
        inner->networkSearchHandler_->RevertLastTechnology();
    }
    return HandleNotifyStateChangeWithDelay(slotId, isNeedDelay);
}

bool NetworkSearchManager::IsRadioFirstPowerOn(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        return inner->isRadioFirstPowerOn_;
    }
    return false;
}

void NetworkSearchManager::SetRadioFirstPowerOn(int32_t slotId, bool isFirstPowerOn)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        inner->isRadioFirstPowerOn_ = isFirstPowerOn;
    }
}

std::shared_ptr<NetworkSearchManagerInner> NetworkSearchManager::FindManagerInner(int32_t slotId)
{
    {
        std::lock_guard<std::mutex> lock(mutexInner_);
        auto iter = mapManagerInner_.find(slotId);
        if (iter != mapManagerInner_.end()) {
            return iter->second;
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::FindManagerInner not find inner object. slotId:%{public}d", slotId);
    return nullptr;
}

void NetworkSearchManager::ClearManagerInner()
{
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        auto inner = FindManagerInner(slotId);
        if (inner != nullptr) {
            std::lock_guard<std::mutex> lock(inner->mutex_);
            inner->networkSearchHandler_->UnregisterEvents();
        }
    }
    std::lock_guard<std::mutex> lock(mutexInner_);
    mapManagerInner_.clear();
}

void NetworkSearchManager::AddManagerInner(int32_t slotId, const std::shared_ptr<NetworkSearchManagerInner> &inner)
{
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(mutexInner_);
        mapManagerInner_.emplace(slotId, inner);
        TELEPHONY_LOGE("NetworkSearchManager::AddManagerInner %{public}d %{public}zu", slotId, mapManagerInner_.size());
    }
}

bool NetworkSearchManager::RemoveManagerInner(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(mutexInner_);
    bool ret = (mapManagerInner_.erase(slotId) != 0);
    TELEPHONY_LOGE("NetworkSearchManager::RemoveManagerInner %{public}d %{public}zu", slotId, mapManagerInner_.size());
    return ret;
}

void NetworkSearchManager::TriggerSimRefresh(int32_t slotId)
{
    TELEPHONY_LOGD("NetworkSearchManager::TriggerSimRefresh  %{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr && simManager_ != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            simManager_->RegisterCoreNotify(slotId, inner->networkSearchHandler_, RadioEvent::RADIO_IMSI_LOADED_READY);
        }
    }
}

void NetworkSearchManager::TriggerTimezoneRefresh(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->TimezoneRefresh();
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::TriggerTimezoneRefresh slotId:%{public}d", slotId);
}

int32_t NetworkSearchManager::GetAirplaneMode(bool &airplaneMode)
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    std::string value = "";
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_AIRPLANE_MODE;
    if (settingHelper->Query(uri, key, value) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGI("Query airplane mode fail");
        return TELEPHONY_ERR_DATABASE_READ_FAIL;
    }
    airplaneMode = value == "1";
    TELEPHONY_LOGI("Get airplane mode:%{public}d", airplaneMode);
    return TELEPHONY_SUCCESS;
}

int32_t NetworkSearchManager::RegisterImsRegInfoCallback(
    int32_t slotId, ImsServiceType imsSrvType, const std::string &bundleName, const sptr<ImsRegInfoCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] callback is nullptr", slotId);
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    bool isExisted = false;
    std::lock_guard<std::mutex> lock(mutexInner_);
    for (auto iter : listImsRegInfoCallbackRecord_) {
        if ((iter.slotId == slotId) && (iter.imsSrvType == imsSrvType) && (iter.bundleName == bundleName)) {
            isExisted = true;
            break;
        }
    }
    if (isExisted) {
        TELEPHONY_LOGI("[slot%{public}d] Ignore register action, since callback is existent", slotId);
        return TELEPHONY_SUCCESS;
    }

    ImsRegInfoCallbackRecord imsRecord;
    imsRecord.slotId = slotId;
    imsRecord.imsSrvType = imsSrvType;
    imsRecord.bundleName = bundleName;
    imsRecord.imsCallback = callback;
    listImsRegInfoCallbackRecord_.push_back(imsRecord);
    TELEPHONY_LOGD("[slot%{public}d] Register successfully, callback list size is %{public}zu", slotId,
        listImsRegInfoCallbackRecord_.size());
    return TELEPHONY_SUCCESS;
}

int32_t NetworkSearchManager::UnregisterImsRegInfoCallback(
    int32_t slotId, ImsServiceType imsSrvType, const std::string &bundleName)
{
    bool isSuccess = false;
    std::lock_guard<std::mutex> lock(mutexInner_);
    auto iter = listImsRegInfoCallbackRecord_.begin();
    for (; iter != listImsRegInfoCallbackRecord_.end(); ++iter) {
        if ((iter->slotId == slotId) && (iter->imsSrvType == imsSrvType) && (iter->bundleName == bundleName)) {
            listImsRegInfoCallbackRecord_.erase(iter);
            isSuccess = true;
            break;
        }
    }
    if (!isSuccess) {
        TELEPHONY_LOGI("[slot%{public}d] Ignore unregister action, since callback is nonexistent", slotId);
        return TELEPHONY_SUCCESS;
    }
    TELEPHONY_LOGD("[slot%{public}d] Unregister successfully, callback list size is  %{public}zu", slotId,
        listImsRegInfoCallbackRecord_.size());
    return TELEPHONY_SUCCESS;
}

void NetworkSearchManager::NotifyImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info)
{
    TELEPHONY_LOGD(
        "slotId:%{public}d, ImsRegState:%{public}d,  ImsRegTech:%{public}d", slotId, info.imsRegState, info.imsRegTech);
    bool isExisted = false;
    std::lock_guard<std::mutex> lock(mutexInner_);
    for (auto iter : listImsRegInfoCallbackRecord_) {
        if ((iter.slotId == slotId) && (iter.imsSrvType == imsSrvType)) {
            if (iter.imsCallback == nullptr) {
                TELEPHONY_LOGE("imsCallback is nullptr from listImsRegInfoCallbackRecord_");
                continue;
            }
            iter.imsCallback->OnImsRegInfoChanged(slotId, imsSrvType, info);
            isExisted = true;
        }
    }
    if (!isExisted) {
        TELEPHONY_LOGI("this slot id %{public}d, ims service type %{public}d is not registered", slotId, imsSrvType);
    }
}

void NetworkSearchManager::InitSimRadioProtocol(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::InitSimRadioProtocol simManager_ is nullptr");
        return;
    }
    simManager_->GetRadioProtocol(slotId);
}

int32_t NetworkSearchManager::SetLocalAirplaneMode(int32_t slotId, bool state)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("SetLocalAirplaneMode inner is nullptr, slotId:%{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    inner->airplaneMode_ = state;
    TELEPHONY_LOGD("SetLocalAirplaneMode slotId:%{public}d state:%{public}d", slotId, state);
    return TELEPHONY_SUCCESS;
}

int32_t NetworkSearchManager::GetLocalAirplaneMode(int32_t slotId, bool &state)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("GetLocalAirplaneMode inner is nullptr, slotId:%{public}d", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    state = inner->airplaneMode_;
    TELEPHONY_LOGD("GetLocalAirplaneMode slotId:%{public}d state:%{public}d", slotId, state);
    return TELEPHONY_ERR_SUCCESS;
}

void NetworkSearchManager::SetBasebandVersion(int32_t slotId, std::string version)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::SetBasebandVersion slotId:%{public}d", slotId);
        return;
    }
    inner->basebandVersion_ = version;
}

int32_t NetworkSearchManager::GetBasebandVersion(int32_t slotId, std::string &version)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetBasebandVersion start slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr || eventSender_ == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner or eventSender_ is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (inner->basebandVersion_.empty()) {
        eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_BASEBAND_VERSION);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    version = inner->basebandVersion_;
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::GetNetworkCapability(
    int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState)
{
    if (TELEPHONY_EXT_WRAPPER.getNetworkCapabilityExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.getNetworkCapabilityExt_(slotId, networkCapabilityType, networkCapabilityState);
        return TELEPHONY_ERR_SUCCESS;
    }

    TelephonyConfig telephonyConfig;
    bool isNrSupported =
        telephonyConfig.IsCapabilitySupport(static_cast<int32_t>(TelephonyConfig::ConfigType::MODEM_CAP_SUPPORT_NR));
    if (networkCapabilityType == SERVICE_TYPE_NR && !isNrSupported) {
        TELEPHONY_LOGE(
            "switch type and nr capability no match, networkCapabilityType:%{public}d isNrSupported:%{public}d",
            networkCapabilityType, isNrSupported);
        return TELEPHONY_ERR_FAIL;
    }
    int32_t preferredNetwork = GetPreferredNetworkValue(slotId);
    int32_t convertedType = ConvertNetworkModeToCapabilityType(preferredNetwork);
    if (networkCapabilityType == SERVICE_TYPE_NR && convertedType == SERVICE_TYPE_NR) {
        networkCapabilityState = SERVICE_ABILITY_ON;
    } else if (networkCapabilityType == SERVICE_TYPE_LTE &&
               (convertedType == SERVICE_TYPE_NR || convertedType == SERVICE_TYPE_LTE)) {
        networkCapabilityState = SERVICE_ABILITY_ON;
    } else {
        networkCapabilityState = SERVICE_ABILITY_OFF;
    }
    if (TELEPHONY_EXT_WRAPPER.getNetworkCapabilityExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.getNetworkCapabilityExt_(slotId, networkCapabilityType, networkCapabilityState);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::SetNetworkCapability(
    int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilityState)
{
    TelephonyConfig telephonyConfig;
    bool isNrSupported =
        telephonyConfig.IsCapabilitySupport(static_cast<int32_t>(TelephonyConfig::ConfigType::MODEM_CAP_SUPPORT_NR));
    if (networkCapabilityType == SERVICE_TYPE_NR && !isNrSupported) {
        TELEPHONY_LOGE(
            "switch type and nr capability no match, networkCapabilityType:%{public}d isNrSupported:%{public}d",
            networkCapabilityType, isNrSupported);
        return TELEPHONY_ERR_FAIL;
    }
    bool ret = false;
    if ((networkCapabilityType == SERVICE_TYPE_LTE && networkCapabilityState == SERVICE_ABILITY_ON) ||
        (networkCapabilityType == SERVICE_TYPE_NR && networkCapabilityState == SERVICE_ABILITY_OFF)) {
        ret = SetPreferredNetwork(
            slotId, static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA_GSM));
    } else if (networkCapabilityType == SERVICE_TYPE_NR && networkCapabilityState == SERVICE_ABILITY_ON) {
        ret = SetPreferredNetwork(
            slotId, static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM));
    } else if (networkCapabilityType == SERVICE_TYPE_LTE && networkCapabilityState == SERVICE_ABILITY_OFF) {
        ret = SetPreferredNetwork(
            slotId, static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA));
    }
    if (!ret) {
        TELEPHONY_LOGE(
            "set preferred Network failed, networkCapabilityType:%{public}d networkCapabilityState:%{public}d",
            networkCapabilityType, networkCapabilityState);
        return TELEPHONY_ERR_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchManager::ConvertNetworkModeToCapabilityType(int32_t preferredNetwork)
{
    int32_t capabilityType = SERVICE_TYPE_UNKNOWN;
    switch (preferredNetwork) {
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA_GSM):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_EVDO_CDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_GSM):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA):
            capabilityType = SERVICE_TYPE_LTE;
            break;
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_EVDO_CDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_GSM):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM):
        case static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA):
            capabilityType = SERVICE_TYPE_NR;
            break;
        default:
            break;
    }
    return capabilityType;
}
} // namespace Telephony
} // namespace OHOS
