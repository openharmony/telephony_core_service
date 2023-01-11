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

#include <cinttypes>
#include <parameters.h>
#include <securec.h>
#include <string_ex.h>

#include "core_service_errors.h"
#include "mcc_pool.h"
#include "network_search_types.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const std::string KEY_DEFAULT_PREFERRED_NETWORK_MODE = "preferred_network_mode";
const int32_t AIRPLANE_MODE_UNSUPPORT = 0;
const int32_t AIRPLANE_MODE_SUPPORT = 1;
const std::string SUPPORT_AIRPLANE_MODE_PARAM = "persist.sys.support_air_plane_mode";
const int32_t IS_SUPPORT_AIRPLANE_MODE = system::GetIntParameter(SUPPORT_AIRPLANE_MODE_PARAM, AIRPLANE_MODE_UNSUPPORT);
const size_t MCC_LEN = 3;
} // namespace

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
    settingAutoTimezoneObserver_ = new AutoTimezoneObserver(networkSearchHandler_);
    airplaneModeObserver_ = new AirplaneModeObserver(networkSearchHandler_);
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingAutoTimeObserver_ == nullptr || settingAutoTimezoneObserver_ == nullptr ||
        airplaneModeObserver_ == nullptr || settingHelper == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::RegisterSetting is null.");
        return false;
    }

    Uri autoTimeUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIME_URI);
    Uri autoTimezoneUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI);
    Uri airplaneModeUri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    settingHelper->RegisterSettingsObserver(autoTimeUri, settingAutoTimeObserver_);
    settingHelper->RegisterSettingsObserver(autoTimezoneUri, settingAutoTimezoneObserver_);
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
    Uri autoTimezoneUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI);
    Uri airplaneModeUri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    settingHelper->UnRegisterSettingsObserver(autoTimeUri, settingAutoTimeObserver_);
    settingHelper->UnRegisterSettingsObserver(autoTimezoneUri, settingAutoTimezoneObserver_);
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
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        std::shared_ptr<NetworkSearchManagerInner> inner = FindManagerInner(slotId);
        if (inner == nullptr) {
            inner = std::make_shared<NetworkSearchManagerInner>();
            AddManagerInner(slotId, inner);
        }
        if (inner != nullptr) {
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
            TELEPHONY_LOGI("NetworkSearchManager::Init inner init slotId:%{public}d", slotId);
            // Prevent running crash and query the radio status at startup
            eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_STATUS);
        }
    }
    TELEPHONY_LOGI("NetworkSearchManager::Init success");
    return true;
}

std::shared_ptr<NetworkSearchState> NetworkSearchManager::GetNetworkSearchState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        TELEPHONY_LOGI("NetworkSearchManager::GetNetworkSearchState slotId:%{public}d", slotId);
        return inner->networkSearchState_;
    }
    return nullptr;
}

void NetworkSearchManager::SetRadioState(int32_t slotId, bool isOn, int32_t rst)
{
    TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d slotId:%{public}d", isOn, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return;
    }
    int32_t fun = static_cast<int32_t>(isOn);
    eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_STATUS, fun, rst);
}

int32_t NetworkSearchManager::SetRadioState(int32_t slotId, bool isOn, int32_t rst, NSCALLBACK &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d slotId:%{public}d", isOn, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    AirplaneMode_ = isOn ? false : true;
    int32_t fun = static_cast<int32_t>(isOn);
    if (!eventSender_->SendCallback(slotId, RadioEvent::RADIO_SET_STATUS, &callback, fun, rst)) {
        TELEPHONY_LOGE("slotId:%{public}d SetRadioState SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

void NetworkSearchManager::RegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what)
{
    TELEPHONY_LOGI("NetworkSearchManager::RegisterCoreNotify  %{public}d slotId:%{public}d", what, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->RegObserver(what, handler);
        }
    }
}

void NetworkSearchManager::UnRegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what)
{
    TELEPHONY_LOGI("NetworkSearchManager::UnRegisterCoreNotify %{public}d slotId:%{public}d", what, slotId);
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
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRoamingOpenChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_ROAMING_OPEN);
        }
    }
}

void NetworkSearchManager::NotifyPsRoamingCloseChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRoamingCloseChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_ROAMING_CLOSE);
        }
    }
}

void NetworkSearchManager::NotifyEmergencyOpenChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyEmergencyOpenChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_EMERGENCY_STATE_OPEN);
        }
    }
}

void NetworkSearchManager::NotifyEmergencyCloseChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyEmergencyCloseChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_EMERGENCY_STATE_CLOSE);
        }
    }
}

void NetworkSearchManager::NotifyPsRatChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRatChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_RAT_CHANGED);
        }
    }
}

void NetworkSearchManager::NotifyPsConnectionAttachedChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsConnectionAttachedChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_CONNECTION_ATTACHED);
        }
    }
}

void NetworkSearchManager::NotifyPsConnectionDetachedChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsConnectionDetachedChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_CONNECTION_DETACHED);
        }
    }
}

void NetworkSearchManager::NotifyNrStateChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyNrStateChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_NR_STATE_CHANGED);
        }
    }
}

void NetworkSearchManager::NotifyNrFrequencyChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyNrFrequencyChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_NR_FREQUENCY_CHANGED);
        }
    }
}

int32_t NetworkSearchManager::GetPsRadioTech(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRadioTech());
            TELEPHONY_LOGI("NetworkSearchManager::GetPsRadioTech result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech Failed slotId:%{public}d", slotId);
    return static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_INVALID);
}

int32_t NetworkSearchManager::GetCsRadioTech(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetCsRadioTech());
            TELEPHONY_LOGI("NetworkSearchManager::GetCsRadioTech result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech Failed slotId:%{public}d", slotId);
    return static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_INVALID);
}

int32_t NetworkSearchManager::GetPsRegState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRegStatus());
            TELEPHONY_LOGI("NetworkSearchManager::GetPsRegState result=%{public}d slotId:%{public}d", event, slotId);
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
            TELEPHONY_LOGI("NetworkSearchManager::GetCsRegState result=%{public}d slotId:%{public}d", event, slotId);
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
            TELEPHONY_LOGI(
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
    TELEPHONY_LOGI("NetworkSearchManager::GetOperatorNumeric start slotId:%{public}d", slotId);
    std::u16string str;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = inner->networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
            str = Str8ToStr16(event);
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetOperatorNumeric result=%{public}s slotId:%{public}d", event.c_str(), slotId);
        }
    }
    return str;
}

std::u16string NetworkSearchManager::GetOperatorName(int32_t slotId)
{
    std::u16string str;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = inner->networkSearchState_->GetNetworkStatus()->GetLongOperatorName();
            str = Str8ToStr16(event);
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetOperatorName result=%{public}s slotId:%{public}d", event.c_str(), slotId);
        }
    }
    return str;
}

sptr<NetworkState> NetworkSearchManager::GetNetworkStatus(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr) {
            auto networkState = inner->networkSearchState_->GetNetworkStatus().release();
            return networkState;
        }
    }
    return nullptr;
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

bool NetworkSearchManager::GetRadioState(int32_t slotId, NSCALLBACK &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetRadioState... slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return false;
    }
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_STATUS, &callback);
}

std::vector<sptr<SignalInformation>> NetworkSearchManager::GetSignalInfoList(int32_t slotId)
{
    std::vector<sptr<SignalInformation>> vec;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->GetSignalInfo(vec);
        }
    }
    return vec;
}

int32_t NetworkSearchManager::GetNetworkSearchInformation(int32_t slotId, NSCALLBACK &callback)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
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
    if (inner != nullptr) {
        eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE);
        return static_cast<int32_t>(inner->selection_);
    }
    return static_cast<int32_t>(SelectionMode::MODE_TYPE_UNKNOWN);
}

bool NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId, NSCALLBACK &callback)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return false;
    }
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE, &callback);
}

bool NetworkSearchManager::SetNetworkSelectionMode(
    int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation, bool resumeSelection)
{
    TELEPHONY_LOGI(
        "NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d slotId:%{public}d", selectMode, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return false;
    }
    std::string plmnNumeric = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
    }
    return eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, selectMode, plmnNumeric);
}

int32_t NetworkSearchManager::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection, NSCALLBACK &callback)
{
    TELEPHONY_LOGI(
        "NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d slotId:%{public}d", selectMode, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string plmnNumeric = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
    }
    bool ret = eventSender_->SendCallback(
        slotId, RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, &callback, selectMode, plmnNumeric);
    if (!ret) {
        TELEPHONY_LOGE("slotId:%{public}d SetPreferredNetwork SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

std::u16string NetworkSearchManager::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    std::string iso = "";
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return Str8ToStr16(iso);
    }
    if (inner->networkSearchHandler_ == nullptr) {
        return Str8ToStr16(iso);
    }
    if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
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
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetIsoCountryCodeForNetwork mcc=%{public}s code=%{public}d slotId:%{public}d",
                mcc.c_str(), value, slotId);
        }
    } else {
        TELEPHONY_LOGE(
            "NetworkSearchManager::GetIsoCountryCodeForNetwork Failed due to nullptr, slotId:%{public}d", slotId);
    }
    return Str8ToStr16(iso);
}

int32_t NetworkSearchManager::GetPreferredNetwork(int32_t slotId, NSCALLBACK &callback)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("SetPreferredNetwork inner is nullptr");
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
    TELEPHONY_LOGI("SetPreferredNetwork filterMode:%{public}d slotId:%{public}d", filterMode, slotId);
    if (!eventSender_->SendCallbackEx(slotId, RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE, &callback, filterMode)) {
        TELEPHONY_LOGE("slotId:%{public}d SetPreferredNetwork SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

bool NetworkSearchManager::GetPreferredNetwork(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager GetPreferredNetwork slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE)) {
        TELEPHONY_LOGE("slotId:%{public}d GetPreferredNetwork SendCallback failed.", slotId);
        return CORE_SERVICE_SEND_CALLBACK_FAILED;
    }
    return TELEPHONY_ERR_SUCCESS;
}

bool NetworkSearchManager::SetPreferredNetwork(int32_t slotId, int32_t networkMode)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("SetPreferredNetwork simManager_ is nullptr");
        return false;
    }
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("SetPreferredNetwork inner is nullptr");
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
    TELEPHONY_LOGI("SetPreferredNetwork filterMode:%{public}d slotId:%{public}d", filterMode, slotId);
    return eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE, filterMode);
}

void NetworkSearchManager::SavePreferredNetworkValue(int32_t slotId, int32_t networkMode)
{
    TELEPHONY_LOGI("NetworkSearchManager SavePreferredNetworkValue slotId:%{public}d, networkMode:%{public}d", slotId,
        networkMode);
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE + "_" + std::to_string(slotId);
    std::string value = std::to_string(networkMode);
    if (!settingHelper->Update(uri, key, value)) {
        TELEPHONY_LOGE("Update %{public}s fail", key.c_str());
    }
}

int32_t NetworkSearchManager::GetPreferredNetworkValue(int32_t slotId) const
{
    int32_t networkMode = PREFERRED_NETWORK_TYPE;
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return networkMode;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE + "_" + std::to_string(slotId);
    std::string value = "";
    if (!settingHelper->Query(uri, key, value)) {
        TELEPHONY_LOGI("Query %{public}s fail", key.c_str());
        return networkMode;
    }

    bool succ = StrToInt(value, networkMode);
    TELEPHONY_LOGI("NetworkSearchManager GetPreferredNetworkValue succ:%{public}d, slotId:%{public}d, "
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
    TELEPHONY_LOGI("slotId:%{public}d, imsSrvType:%{public}d", slotId, imsSrvType);
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
    TELEPHONY_LOGI("NetworkSearchManager::GetImei start slotId:%{public}d", slotId);
    imei = u"";
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
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
    TELEPHONY_LOGI("NetworkSearchManager::GetMeid start slotId:%{public}d", slotId);
    meid = u"";
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
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
    TELEPHONY_LOGI("NetworkSearchManager::SetLocateUpdate start slotId:%{public}d", slotId);
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
    TELEPHONY_LOGI("NetworkSearchManager::GetUniqueDeviceId start slotId:%{public}d", slotId);
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGE("slotId:%{public}d inner is null", slotId);
        return;
    }
    eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_VOICE_TECH);
    eventSender_->SendBase(slotId, RadioEvent::RADIO_OPERATOR);
}

bool NetworkSearchManager::IsNrSupported(int32_t slotId)
{
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("simManager_ is nullptr");
        return false;
    }
    int32_t modemRaf = simManager_->GetRadioProtocolTech(slotId);
    return (static_cast<uint32_t>(modemRaf) & static_cast<uint32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_NR)) ==
        static_cast<uint32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_NR);
}

int32_t NetworkSearchManager::GetNrOptionMode(int32_t slotId, NrMode &mode)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        mode = inner->nrMode_;
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

void NetworkSearchManager::SetNrOptionMode(int32_t slotId, NrMode mode)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        inner->nrMode_ = mode;
    }
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
    TELEPHONY_LOGI("NetworkSearchManager::TriggerSimRefresh  %{public}d", slotId);
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

bool NetworkSearchManager::GetAirplaneMode()
{
    if (IS_SUPPORT_AIRPLANE_MODE == AIRPLANE_MODE_SUPPORT) {
        TELEPHONY_LOGI("support airplane mode, return true");
        return true;
    }
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return false;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    std::string value = "";
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_AIRPLANE_MODE;
    if (!settingHelper->Query(uri, key, value)) {
        TELEPHONY_LOGI("Query airplane mode fail");
        return false;
    }
    bool airplaneMode = value == "1";
    TELEPHONY_LOGI("Get airplane mode:%{public}d", airplaneMode);
    return airplaneMode;
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
    TELEPHONY_LOGI("[slot%{public}d] Register successfully, callback list size is %{public}zu", slotId,
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
    TELEPHONY_LOGI("[slot%{public}d] Unregister successfully, callback list size is  %{public}zu", slotId,
        listImsRegInfoCallbackRecord_.size());
    return TELEPHONY_SUCCESS;
}

void NetworkSearchManager::NotifyImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info)
{
    TELEPHONY_LOGI(
        "slotId:%{public}d, ImsRegState:%{public}d,  ImsRegTech:%{public}d", slotId, info.imsRegState, info.imsRegTech);
    bool isExisted = false;
    std::lock_guard<std::mutex> lock(mutexInner_);
    for (auto iter : listImsRegInfoCallbackRecord_) {
        if ((iter.slotId == slotId) && (iter.imsSrvType == imsSrvType)) {
            if (iter.imsCallback == nullptr) {
                TELEPHONY_LOGE("imsCallback is nullptr from listImsRegInfoCallbackRecord_");
                return;
            }
            iter.imsCallback->OnImsRegInfoChanged(slotId, imsSrvType, info);
            isExisted = true;
            break;
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
} // namespace Telephony
} // namespace OHOS
