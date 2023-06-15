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

#include "device_state_handler.h"

#include "battery_srv_client.h"
#include "network_search_manager.h"
#include "power_mgr_client.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const uint32_t CELL_REQUEST_SHORT_INTERVAL = 2; // This is the minimum interval in seconds for cell requests
const uint32_t CELL_REQUEST_LONG_INTERVAL = 10; // This is the maximum interval in seconds for cell requests
} // namespace

DeviceStateHandler::DeviceStateHandler(
    const std::weak_ptr<NetworkSearchManager> &networkSearchManager,
    const std::weak_ptr<ITelRilManager> &telRilManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), telRilManager_(telRilManager), slotId_(slotId)
{
    isCharging_ = true;
    auto &powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    isScreenOn_ = true;
    auto powerSaveMode = powerMgrClient.GetDeviceMode();
    isPowerSaveModeOn_ = powerSaveMode == PowerMgr::PowerMode::POWER_SAVE_MODE ||
        powerSaveMode == PowerMgr::PowerMode::EXTREME_POWER_SAVE_MODE;
    TELEPHONY_LOGI("DeviceStateHandler isCharging_=%{public}d, isScreenOn_=%{public}d, isPowerSaveModeOn_=%{public}d",
        isCharging_, isScreenOn_, isPowerSaveModeOn_);
}

void DeviceStateHandler::ProcessWifiState(bool isWifiConnected)
{
    isWifiConnected_ = isWifiConnected;
    ProcessDeviceState();
}

void DeviceStateHandler::ProcessScreenDisplay(bool isScreenOn)
{
    isScreenOn_ = isScreenOn;
    if (isScreenOn) {
        GetRrcConnectionState();
    }
    ProcessDeviceState();
}

void DeviceStateHandler::ProcessPowerSaveMode(bool isPowerSaveModeOn)
{
    isPowerSaveModeOn_ = isPowerSaveModeOn;
    SetDeviceState(POWER_SAVE_MODE, isPowerSaveModeOn_);
    ProcessDeviceState();
}

void DeviceStateHandler::ProcessChargingState(bool isCharging)
{
    isCharging_ = isCharging;
    SetDeviceState(CHARGING_STATE, isCharging_);
    ProcessDeviceState();
}

void DeviceStateHandler::ProcessNetSharingState(bool isNetSharingOn)
{
    isNetSharingOn_ = isNetSharingOn;
    ProcessDeviceState();
}

void DeviceStateHandler::ProcessRadioState()
{
    SyncSettings();
}

void DeviceStateHandler::ProcessDeviceState()
{
    uint32_t newCellRequestMinInterval = GetCellRequestMinInterval();
    TELEPHONY_LOGI(
        "ProcessDeviceState isCharging_=%{public}d, isPowerSaveModeOn_=%{public}d, isNetSharingOn_=%{public}d, "
        "isScreenOn_=%{public}d, isWifiConnected_=%{public}d, newCellRequestMinInterval=%{public}d",
        isCharging_, isPowerSaveModeOn_, isNetSharingOn_, isScreenOn_, isWifiConnected_, newCellRequestMinInterval);
    if (cellRequestMinInterval_ != newCellRequestMinInterval) {
        cellRequestMinInterval_ = newCellRequestMinInterval;
        SetCellRequestMinInterval(cellRequestMinInterval_);
    }

    if (isLowData_ != IsLowPowerConsumption()) {
        isLowData_ = !isLowData_;
        SetDeviceState(LOW_DATA_STATE, isLowData_);
    }

    int32_t newFilter = NOTIFICATION_FILTER_NONE;
    if (IsSignalStrengthNotificationExpected()) {
        newFilter |= NOTIFICATION_FILTER_SIGNAL_STRENGTH;
    }

    if (!IsLowPowerConsumption()) {
        newFilter |= NOTIFICATION_FILTER_NETWORK_STATE;
        newFilter |= NOTIFICATION_FILTER_DATA_CALL;
        newFilter |= NOTIFICATION_FILTER_LINK_CAPACITY;
        newFilter |= NOTIFICATION_FILTER_PHYSICAL_CHANNEL_CONFIG;
    }

    SetNotificationFilter(newFilter, false);
}

bool DeviceStateHandler::IsSignalStrengthNotificationExpected() const
{
    return isCharging_ || isScreenOn_;
}

bool DeviceStateHandler::IsLowPowerConsumption() const
{
    return !isCharging_ && !isScreenOn_ && !isNetSharingOn_;
}

uint32_t DeviceStateHandler::GetCellRequestMinInterval() const
{
    if (isScreenOn_ && (!isWifiConnected_ || isCharging_)) {
        return CELL_REQUEST_SHORT_INTERVAL;
    } else {
        return CELL_REQUEST_LONG_INTERVAL;
    }
}

void DeviceStateHandler::SetCellRequestMinInterval(uint32_t minInterval) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("DeviceStateHandler::SetCellRequestMinInterval nsm is null");
        return;
    }
    auto inner = nsm->FindManagerInner(slotId_);
    if (inner == nullptr) {
        TELEPHONY_LOGE("DeviceStateHandler::SetCellRequestMinInterval inner is null");
        return;
    }
    if (inner->networkSearchHandler_ != nullptr) {
        TELEPHONY_LOGD("DeviceStateHandler::SetCellRequestMinInterval %{public}d", minInterval);
        inner->networkSearchHandler_->SetCellRequestMinInterval(minInterval);
    }
}

void DeviceStateHandler::SetNotificationFilter(int32_t newFilter, bool force)
{
    if (!force && newFilter == notificationFilter_) {
        TELEPHONY_LOGE("DeviceStateHandler::SetNotificationFilter is not necessary");
        return;
    }
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_NOTIFICATION_FILTER);
    if (event == nullptr) {
        TELEPHONY_LOGE("DeviceStateHandler::SetNotificationFilter event is null");
        return;
    }
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager != nullptr) {
        TELEPHONY_LOGI("DeviceStateHandler::SetNotificationFilter old filter:%{public}d, new filter:%{public}d,"
            " slotId_:%{public}d", notificationFilter_, newFilter, slotId_);
        telRilManager->SetNotificationFilter(slotId_, newFilter, event);
        notificationFilter_ = newFilter;
    }
}

void DeviceStateHandler::SetDeviceState(int32_t deviceStateType, bool deviceStateOn)
{
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_DEVICE_STATE);
    if (event == nullptr) {
        TELEPHONY_LOGE("DeviceStateHandler::SetDeviceState event is null");
        return;
    }
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager != nullptr) {
        TELEPHONY_LOGD("DeviceStateHandler::SetDeviceState type:%{public}d state:%{public}d, slotId_:%{public}d",
            deviceStateType, deviceStateOn, slotId_);
        telRilManager->SetDeviceState(slotId_, deviceStateType, deviceStateOn, event);
    }
}

void DeviceStateHandler::SyncSettings()
{
    TELEPHONY_LOGI("DeviceStateHandler::SyncSettings isCharging_=%{public}d, isLowData_=%{public}d,"
        " isPowerSaveModeOn_=%{public}d, notificationFilter_=%{public}d",
        isCharging_, isLowData_, isPowerSaveModeOn_, notificationFilter_);
    SetDeviceState(CHARGING_STATE, isCharging_);
    SetDeviceState(LOW_DATA_STATE, isLowData_);
    SetDeviceState(POWER_SAVE_MODE, isPowerSaveModeOn_);
    SetNotificationFilter(notificationFilter_, true);
}

void DeviceStateHandler::GetRrcConnectionState() const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("DeviceStateHandler::GetRrcConnectionState nsm is null");
        return;
    }
    int32_t status = 0;
    nsm->GetRrcConnectionState(slotId_, status);
}
} // namespace Telephony
} // namespace OHOS
