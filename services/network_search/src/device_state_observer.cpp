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

#ifdef ABILITY_BATTERY_SUPPORT
#include "battery_srv_client.h"
#endif
#include "iservice_registry.h"
#ifdef ABILITY_NETMANAGER_EXT_SUPPORT
#include "networkshare_client.h"
#include "networkshare_constants.h"
#endif
#ifdef ABILITY_POWER_SUPPORT
#include "power_mgr_client.h"
#include "power_mode_info.h"
#endif
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"
#include "core_manager_inner.h"

namespace OHOS {
namespace Telephony {
#ifdef ABILITY_POWER_SUPPORT
using PowerMode = OHOS::PowerMgr::PowerMode;
#endif
namespace {
const std::string NET_TYPE = "NetType";
}

void DeviceStateObserver::StartEventSubscriber(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler)
{
    subscriber_ = std::make_shared<DeviceStateEventSubscriber>();
#ifdef ABILITY_NETMANAGER_EXT_SUPPORT
    std::unique_lock<ffrt::mutex> lck(callbackMutex_);
    sharingEventCallback_ = new (std::nothrow) SharingEventCallback(deviceStateHandler);

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(sharingEventCallback_);
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
#endif
}

void DeviceStateObserver::StopEventSubscriber()
{
    CoreManagerInner::GetInstance().UnregisterCommonEventCallback(subscriber_);
    subscriber_ = nullptr;

#ifdef ABILITY_NETMANAGER_EXT_SUPPORT
    std::unique_lock<ffrt::mutex> lck(callbackMutex_);
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
#endif
}

void DeviceStateEventSubscriber::OnScreenOn()
{
    if (deviceStateHandler_ == nullptr) {
        return;
    }
    deviceStateHandler_->ProcessScreenDisplay(true);
}

void DeviceStateEventSubscriber::OnScreenOff()
{
    if (deviceStateHandler_ == nullptr) {
        return;
    }
    deviceStateHandler_->ProcessScreenDisplay(false);
}

void DeviceStateEventSubscriber::OnCharging(uint32_t chargeType)
{
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("deviceStateHandler_ is nullptr");
        return;
    }
    deviceStateHandler_->ProcessChargingState(true);
}

void DeviceStateEventSubscriber::OnDischarging(uint32_t chargeType)
{
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("deviceStateHandler_ is nullptr");
        return;
    }
    deviceStateHandler_->ProcessChargingState(false);
}

void DeviceStateEventSubscriber::OnShutdown()
{
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("deviceStateHandler_ is nullptr");
        return;
    }
    deviceStateHandler_->ProcessShutDown();
}

void DeviceStateEventSubscriber::OnConnectivityChange(int32_t netType, int32_t netConnState)
{
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("deviceStateHandler_ is nullptr");
        return;
    }
    if (netType == NetBearType::BEARER_WIFI) {
        bool isWifiConnected = netConnState == NetConnState::NET_CONN_STATE_CONNECTED;
        deviceStateHandler_->ProcessWifiState(isWifiConnected);
        TELEPHONY_LOGI("DeviceStateEventSubscriber wifi %{public}s", isWifiConnected ? "connected" : "no connected");
    }
}

void DeviceStateEventSubscriber::OnPowerSaveModeChanged(uint32_t powerMode)
{
#ifdef ABILITY_POWER_SUPPORT
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("DeviceStateEventSubscriber::OnPowerSaveModeChanged networkSearchHandler_ is nullptr");
        return;
    }
    PowerMode powerModeCode = static_cast<PowerMode>(powerMode);
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
#endif
}

std::shared_ptr<DeviceStateHandler> DeviceStateEventSubscriber::GetEventHandler()
{
    return deviceStateHandler_;
}

#ifdef ABILITY_NETMANAGER_EXT_SUPPORT
DeviceStateObserver::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    std::shared_ptr<DeviceStateEventSubscriber> &sub, sptr<NetManagerStandard::ISharingEventCallback> &callback)
    : sub_(sub), callback_(callback)
{}

void DeviceStateObserver::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    TELEPHONY_LOGI("systemAbilityId is %{public}d", systemAbilityId);
    if (sub_ == nullptr || sub_->GetEventHandler() == nullptr) {
        TELEPHONY_LOGE("sub_ is nullptr or eventHandler is nullptr");
        return;
    }
    switch (systemAbilityId) {
        case POWER_MANAGER_SERVICE_ID: {
#ifdef ABILITY_POWER_SUPPORT
            auto &powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
            sub_->GetEventHandler()->ProcessScreenDisplay(powerMgrClient.IsScreenOn());
            auto powerSaveMode = powerMgrClient.GetDeviceMode();
            sub_->GetEventHandler()->ProcessPowerSaveMode(
                powerSaveMode == PowerMode::POWER_SAVE_MODE || powerSaveMode == PowerMode::EXTREME_POWER_SAVE_MODE);
#endif
            break;
        }
        case POWER_MANAGER_BATT_SERVICE_ID: {
#ifdef ABILITY_BATTERY_SUPPORT
            auto &batterySrvClient = PowerMgr::BatterySrvClient::GetInstance();
            sub_->GetEventHandler()->ProcessChargingState(
                batterySrvClient.GetChargingStatus() == PowerMgr::BatteryChargeState::CHARGE_STATE_ENABLE);
#endif
            break;
        }
        case COMMON_EVENT_SERVICE_ID: {
            CoreManagerInner::GetInstance().RegisterCommonEventCallback(sub_,
                {TelCommonEvent::SCREEN_ON, TelCommonEvent::SCREEN_OFF, TelCommonEvent::CHARGING,
                    TelCommonEvent::DISCHARGING, TelCommonEvent::SHUTDOWN, TelCommonEvent::CONNECTIVITY_CHANGE,
                    TelCommonEvent::POWER_SAVE_MODE_CHANGED});
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
    CoreManagerInner::GetInstance().UnregisterCommonEventCallback(sub_);
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
#endif
} // namespace Telephony
} // namespace OHOS
