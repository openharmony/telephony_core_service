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

#ifndef NETWORK_SEARCH_INCLUDE_DEVICE_STATE_HANDLER_H
#define NETWORK_SEARCH_INCLUDE_DEVICE_STATE_HANDLER_H

#include <memory>

#include "i_tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class DeviceStateHandler {
public:
    DeviceStateHandler(const std::weak_ptr<NetworkSearchManager> &networkSearchManager,
        const std::weak_ptr<ITelRilManager> &telRilManager, int32_t slotId);
    virtual ~DeviceStateHandler() = default;
    void ProcessWifiState(bool isWifiConnected);
    void ProcessScreenDisplay(bool isScreenOn);
    void ProcessPowerSaveMode(bool isPowerSaveModeOn);
    void ProcessChargingState(bool isCharging);
    void ProcessNetSharingState(bool isNetSharingOn);
    void ProcessRadioState();
    void ProcessShutDown();

private:
    uint32_t GetCellRequestMinInterval() const;
    bool IsLowPowerConsumption() const;
    bool IsSignalStrengthNotificationExpected() const;
    void SetCellRequestMinInterval(uint32_t minInterval) const;
    void ProcessDeviceState();
    void SetNotificationFilter(int32_t newFilter, bool force);
    void SetDeviceState(int32_t deviceStateType, bool deviceStateOn);
    void SyncSettings();
    void GetRrcConnectionState() const;

private:
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    std::weak_ptr<ITelRilManager> telRilManager_;
    int32_t slotId_ = 0;
    int32_t notificationFilter_ = NOTIFICATION_FILTER_ALL;
    uint32_t cellRequestMinInterval_ = 2;
    bool isWifiConnected_ = false;
    bool isLowData_ = false;
    bool isPowerSaveModeOn_ = false;
    bool isCharging_ = false;
    bool isScreenOn_ = false;
    bool isNetSharingOn_ = false;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_DEVICE_STATE_HANDLER_H
