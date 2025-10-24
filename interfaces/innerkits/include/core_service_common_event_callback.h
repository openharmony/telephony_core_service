/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CORE_SERVICE_COMMON_EVENT_CALLBACK_H
#define CORE_SERVICE_COMMON_EVENT_CALLBACK_H

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace OHOS {
namespace Telephony {
enum class TelCommonEvent {
    UNKNOWN_ENENT = -1,
    RADIO_STATE_CHANGE,
    DATA_SHARE_READY,
    USER_SWITCHED,
    SIM_STATE_CHANGED,
    BLUETOOTH_REMOTEDEVICE_NAME_UPDATE,
    SHUTDOWN,
    SCREEN_UNLOCKED,
    SPECIAL_CODE,
    OPERATOR_CONFIG_CHANGED,
    NETWORK_STATE_CHANGED,
    CALL_STATE_CHANGED,
    SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED,
    SCREEN_ON,
    SCREEN_OFF,
    CONNECTIVITY_CHANGE,
    POWER_SAVE_MODE_CHANGED,
    CHARGING,
    DISCHARGING,
    LOCALE_CHANGED,
    AIRPLANE_MODE_CHANGED,
    SET_PRIMARY_SLOT_STATUS,
    SECOND_MOUNTED,
    BUNDLE_SCAN_FINISHED
};

class CoreServiceCommonEventCallback {
public:
    virtual ~CoreServiceCommonEventCallback()
    {}

    virtual void OnRadioStateChange(int32_t slotId, int32_t state)
    {}

    virtual void OnDataShareReady()
    {}

    virtual void OnUserSwitched(int32_t userId)
    {}

    virtual void OnSimStateChanged(int32_t slotId, int32_t simeType, int32_t simState, int32_t lockReason)
    {}

    virtual void OnBluetoothRemoteDeviceNameUpdate(const std::string &deviceAddr, const std::string &remoteName)
    {}

    virtual void OnShutdown()
    {}

    virtual void OnScreenUnlocked()
    {}

    virtual void OnSpecialCode(const std::string &specialCode)
    {}

    virtual void OnOperatorConfigChanged(int32_t slotId, int32_t state)
    {}

    virtual void OnNetworkStateChanged(int32_t slotId, const std::string &networkState)
    {}

    virtual void OnCallStateChanged(int32_t slotId, int32_t state)
    {}

    virtual void OnSimCardDefaultDataSubscriptionChanged(int32_t simId)
    {}

    virtual void OnScreenOn()
    {}

    virtual void OnScreenOff()
    {}

    virtual void OnConnectivityChange(int32_t netType, int32_t netConnState)
    {}

    virtual void OnPowerSaveModeChanged(uint32_t powerMode)
    {}

    virtual void OnCharging(uint32_t chargeType)
    {}

    virtual void OnDischarging(uint32_t chargeType)
    {}

    virtual void OnLocaleChanged()
    {}

    virtual void OnAirplaneModeChanged(bool isAirplaneMode)
    {}

    virtual void OnSetPrimarySlotStatus(bool setDone)
    {}

    virtual void OnSecondMounted()
    {}

    virtual void OnBundleScanFinished()
    {}
};

}  // namespace Telephony
}  // namespace OHOS
#endif