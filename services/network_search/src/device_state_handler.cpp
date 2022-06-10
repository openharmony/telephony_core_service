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

#include "network_search_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const uint32_t CELL_REQUEST_SHORT_INTERVAL = 2; // This is the minimum interval in seconds for cell requests
const uint32_t CELL_REQUEST_LONG_INTERVAL = 10; // This is the maximum interval in seconds for cell requests

DeviceStateHandler::DeviceStateHandler(
    const std::weak_ptr<NetworkSearchManager> &networkSearchManager,
    const std::weak_ptr<ITelRilManager> &telRilManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), telRilManager_(telRilManager), slotId_(slotId)
{}

void DeviceStateHandler::ProcessWifiState(bool isWifiConnected)
{
    isWifiConnected_ = isWifiConnected;
    ProcessDeviceState();
}

void DeviceStateHandler::ProcessScreenDisplay(bool isScreenOn)
{
    isScreenOn_ = isScreenOn;
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
    if (cellRequestMinInterval_ != newCellRequestMinInterval) {
        cellRequestMinInterval_ = newCellRequestMinInterval;
        SetCellRequestMinInterval(cellRequestMinInterval_);
    }

    if (isLowData_ != !IsHighPowerConsumption()) {
        isLowData_ = !isLowData_;
        SetDeviceState(LOW_DATA_STATE, isLowData_);
    }

    int32_t newFilter = NONE;
    if (IsSignalStrengthNotificationExpected()) {
        newFilter |= SIGNAL_STRENGTH;
    }

    if (IsHighPowerConsumption()) {
        newFilter |= NETWORK_STATE;
        newFilter |= DATA_CALL;
        newFilter |= PHYSICAL_CHANNEL_CONFIG;
    }

    SetNotificationFilter(newFilter, false);
}

bool DeviceStateHandler::IsSignalStrengthNotificationExpected() const
{
    return isCharging_ || isScreenOn_;
}

bool DeviceStateHandler::IsHighPowerConsumption() const
{
    return isCharging_ || isScreenOn_ || isNetSharingOn_;
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
        return;
    }
    auto inner = nsm->FindManagerInner(slotId_);
    if (inner == nullptr) {
        return;
    }
    if (inner->networkSearchHandler_ != nullptr) {
        TELEPHONY_LOGI("DeviceStateHandler::SetCellRequestMinInterval %{public}d", minInterval);
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
        TELEPHONY_LOGI("DeviceStateHandler::SetNotificationFilter old filter:%{public}d, new filter:%{public}d",
            notificationFilter_, newFilter);
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
        TELEPHONY_LOGI("DeviceStateHandler::SetDeviceState type:%{public}d state:%{public}d",
            deviceStateType, deviceStateOn);
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
} // namespace Telephony
} // namespace OHOS
