/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "device_state_observer.h"

#include "battery_srv_client.h"
#include "iservice_registry.h"
#include "networkshare_client.h"
#include "networkshare_constants.h"
#include "power_mgr_client.h"
#include "power_mode_info.h"
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using PowerMode = OHOS::PowerMgr::PowerMode;
namespace {
const std::string NET_TYPE = "NetType";
}

void DeviceStateObserver::StartEventSubscriber(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_POWER_SAVE_MODE_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_CHARGING);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISCHARGING);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscriber_ = std::make_shared<DeviceStateEventSubscriber>(subscriberInfo);
    subscriber_->SetEventHandler(deviceStateHandler);
    subscriber_->InitEventMap();
    sharingEventCallback_ = new (std::nothrow) SharingEventCallback(deviceStateHandler);

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(subscriber_, sharingEventCallback_);
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("StartEventSubscriber samgrProxy or statusChangeListener_ is nullptr");
        return;
    }
    int32_t commonEventResult = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
    int32_t powerManagerResult = samgrProxy->SubscribeSystemAbility(POWER_MANAGER_SERVICE_ID, statusChangeListener_);
    int32_t powerManagerBattResult =
        samgrProxy->SubscribeSystemAbility(POWER_MANAGER_BATT_SERVICE_ID, statusChangeListener_);
    int32_t netManagerResult =
        samgrProxy->SubscribeSystemAbility(COMM_NET_TETHERING_MANAGER_SYS_ABILITY_ID, statusChangeListener_);
    TELEPHONY_LOGI(
        "SubscribeSystemAbility COMMON_EVENT_SERVICE_ID(result:%{public}d) POWER_MANAGER_SERVICE_ID(result:%{public}d) "
        "POWER_MANAGER_BATT_SERVICE_ID(result:%{public}d) COMM_NET_TETHERING_MANAGER_SYS_ABILITY_ID(result:%{public}d)",
        commonEventResult, powerManagerResult, powerManagerBattResult, netManagerResult);
}

void DeviceStateObserver::StopEventSubscriber()
{
    if (subscriber_ != nullptr) {
        bool subscribeResult = CommonEventManager::UnSubscribeCommonEvent(subscriber_);
        subscriber_ = nullptr;
        TELEPHONY_LOGI("DeviceStateObserver::StopEventSubscriber subscribeResult = %{public}d", subscribeResult);
    }

    if (sharingEventCallback_ == nullptr) {
        TELEPHONY_LOGE("DeviceStateObserver::StopEventSubscriber sharingEventCallback_ is nullptr");
        return;
    }
    auto networkShareClient = DelayedSingleton<NetManagerStandard::NetworkShareClient>::GetInstance();
    if (networkShareClient == nullptr) {
        TELEPHONY_LOGE("DeviceStateObserver::StopEventSubscriber networkShareClient is nullptr");
        return;
    }
    networkShareClient->UnregisterSharingEvent(sharingEventCallback_);
    sharingEventCallback_ = nullptr;
}

void DeviceStateEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("DeviceStateEventSubscriber::OnReceiveEvent: networkSearchHandler_ is nullptr");
        return;
    }
    std::string action = data.GetWant().GetAction();
    TELEPHONY_LOGI("DeviceStateEventSubscriber::OnReceiveEvent: action = %{public}s", action.c_str());
    switch (GetDeviceStateEventIntValue(action)) {
        case COMMON_EVENT_CONNECTIVITY_CHANGE:
            ProcessWifiState(data);
            break;
        case COMMON_EVENT_SCREEN_ON:
            deviceStateHandler_->ProcessScreenDisplay(true);
            break;
        case COMMON_EVENT_SCREEN_OFF:
            deviceStateHandler_->ProcessScreenDisplay(false);
            break;
        case COMMON_EVENT_POWER_SAVE_MODE_CHANGED:
            ProcessPowerSaveMode(data);
            break;
        case COMMON_EVENT_CHARGING:
            deviceStateHandler_->ProcessChargingState(true);
            break;
        case COMMON_EVENT_DISCHARGING:
            deviceStateHandler_->ProcessChargingState(false);
            break;
        default:
            TELEPHONY_LOGE("DeviceStateEventSubscriber::OnReceiveEvent: invalid event");
            break;
    }
}

void DeviceStateEventSubscriber::ProcessWifiState(const CommonEventData &data)
{
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("DeviceStateEventSubscriber::ProcessWifiState networkSearchHandler_ is nullptr");
        return;
    }
    if (data.GetWant().GetIntParam(NET_TYPE, NetBearType::BEARER_DEFAULT) == NetBearType::BEARER_WIFI) {
        bool isWifiConnected = data.GetCode() == NetConnState::NET_CONN_STATE_CONNECTED;
        deviceStateHandler_->ProcessWifiState(isWifiConnected);
        TELEPHONY_LOGI("DeviceStateEventSubscriber wifi %{public}s", isWifiConnected ? "connected" : "no connected");
    }
}

void DeviceStateEventSubscriber::ProcessPowerSaveMode(const CommonEventData &data)
{
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("DeviceStateEventSubscriber::ProcessPowerSaveMode networkSearchHandler_ is nullptr");
        return;
    }
    PowerMode powerModeCode = static_cast<PowerMode>(data.GetCode());
    switch (powerModeCode) {
        case PowerMode::POWER_SAVE_MODE:
        case PowerMode::EXTREME_POWER_SAVE_MODE:
            deviceStateHandler_->ProcessPowerSaveMode(true);
            break;
        case PowerMode::PERFORMANCE_MODE:
        case PowerMode::NORMAL_MODE:
            deviceStateHandler_->ProcessPowerSaveMode(false);
            break;
        default:
            TELEPHONY_LOGE("DeviceStateEventSubscriber::ProcessPowerSaveMode invalid event");
            break;
    }
    TELEPHONY_LOGI("ProcessPowerSaveMode powerModeCode %{public}d", static_cast<int32_t>(powerModeCode));
}

void DeviceStateEventSubscriber::SetEventHandler(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler)
{
    deviceStateHandler_ = deviceStateHandler;
}

std::shared_ptr<DeviceStateHandler> DeviceStateEventSubscriber::GetEventHandler()
{
    return deviceStateHandler_;
}

DeviceStateEventIntValue DeviceStateEventSubscriber::GetDeviceStateEventIntValue(std::string &event) const
{
    auto iter = deviceStateEventMapIntValues_.find(event);
    if (iter == deviceStateEventMapIntValues_.end()) {
        return COMMON_EVENT_UNKNOWN;
    }
    return iter->second;
}

void DeviceStateEventSubscriber::InitEventMap()
{
    deviceStateEventMapIntValues_ = {
        {CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE, COMMON_EVENT_CONNECTIVITY_CHANGE},
        {CommonEventSupport::COMMON_EVENT_SCREEN_ON, COMMON_EVENT_SCREEN_ON},
        {CommonEventSupport::COMMON_EVENT_SCREEN_OFF, COMMON_EVENT_SCREEN_OFF},
        {CommonEventSupport::COMMON_EVENT_POWER_SAVE_MODE_CHANGED, COMMON_EVENT_POWER_SAVE_MODE_CHANGED},
        {CommonEventSupport::COMMON_EVENT_CHARGING, COMMON_EVENT_CHARGING},
        {CommonEventSupport::COMMON_EVENT_DISCHARGING, COMMON_EVENT_DISCHARGING},
    };
}

DeviceStateObserver::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    std::shared_ptr<DeviceStateEventSubscriber> &sub, sptr<NetManagerStandard::ISharingEventCallback> &callback)
    : sub_(sub), callback_(callback)
{}

void DeviceStateObserver::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    if (sub_ == nullptr) {
        TELEPHONY_LOGE("OnAddSystemAbility sub_ is nullptr");
        return;
    }
    switch (systemAbilityId) {
        case POWER_MANAGER_SERVICE_ID: {
            if (sub_->GetEventHandler() == nullptr) {
                TELEPHONY_LOGE("DeviceStateObserver OnAddSystemAbility eventHandler is nullptr");
                return;
            }
            auto &powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
            sub_->GetEventHandler()->ProcessScreenDisplay(powerMgrClient.IsScreenOn());
            auto powerSaveMode = powerMgrClient.GetDeviceMode();
            sub_->GetEventHandler()->ProcessPowerSaveMode(
                powerSaveMode == PowerMode::POWER_SAVE_MODE || powerSaveMode == PowerMode::EXTREME_POWER_SAVE_MODE);
            break;
        }
        case POWER_MANAGER_BATT_SERVICE_ID: {
            if (sub_->GetEventHandler() == nullptr) {
                TELEPHONY_LOGE("DeviceStateObserver OnAddSystemAbility eventHandler is nullptr");
                return;
            }
            auto &batterySrvClient = PowerMgr::BatterySrvClient::GetInstance();
            sub_->GetEventHandler()->ProcessChargingState(
                batterySrvClient.GetChargingStatus() == PowerMgr::BatteryChargeState::CHARGE_STATE_ENABLE);
            break;
        }
        case COMMON_EVENT_SERVICE_ID: {
            bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(sub_);
            TELEPHONY_LOGI("DeviceStateObserver::OnAddSystemAbility subscribeResult = %{public}d", subscribeResult);
            break;
        }
        case COMM_NET_TETHERING_MANAGER_SYS_ABILITY_ID: {
            auto networkShareClient = DelayedSingleton<NetManagerStandard::NetworkShareClient>::GetInstance();
            if (networkShareClient == nullptr) {
                TELEPHONY_LOGE("DeviceStateObserver OnAddSystemAbility networkShareClient is nullptr");
                return;
            }
            int32_t isSharing = 0;
            networkShareClient->IsSharing(isSharing);
            sub_->GetEventHandler()->ProcessNetSharingState(isSharing == NetManagerStandard::NETWORKSHARE_IS_SHARING);
            networkShareClient->RegisterSharingEvent(callback_);
            break;
        }
        default:
            TELEPHONY_LOGE("systemAbilityId is invalid");
            break;
    }
}

void DeviceStateObserver::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        TELEPHONY_LOGE("systemAbilityId is not COMMON_EVENT_SERVICE_ID");
        return;
    }
    if (sub_ == nullptr) {
        TELEPHONY_LOGE("DeviceStateObserver::OnRemoveSystemAbility sub_ is nullptr");
        return;
    }
    bool subscribeResult = CommonEventManager::UnSubscribeCommonEvent(sub_);
    TELEPHONY_LOGI("DeviceStateObserver::OnRemoveSystemAbility subscribeResult = %{public}d", subscribeResult);
}

SharingEventCallback::SharingEventCallback(
    const std::shared_ptr<DeviceStateHandler> &deviceStateHandler) : handler_(deviceStateHandler)
{}

void SharingEventCallback::OnSharingStateChanged(const bool &isRunning)
{
    if (handler_ == nullptr) {
        TELEPHONY_LOGE("OnSharingStateChanged handler_ is nullptr");
        return;
    }
    TELEPHONY_LOGI("DeviceStateObserver::OnSharingStateChanged: isSharing = %{public}d", isRunning);
    handler_->ProcessNetSharingState(isRunning);
}
} // namespace Telephony
} // namespace OHOS
