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
#ifndef COMMON_EVENT_SUPPORT_H
#define COMMON_EVENT_SUPPORT_H

#include <string>
#include <vector>
#include <algorithm>

namespace OHOS {
namespace EventFwk {

class CommonEventSupport {
public:
    bool IsSystemEvent(const std::string &event)
    {
        return std::find(commonEventVector_.begin(), commonEventVector_.end(), event) != commonEventVector_.end();
    }

    static inline constexpr const char *COMMON_EVENT_RADIO_STATE_CHANGE = "COMMON_EVENT_RADIO_STATE_CHANGE";
    static inline constexpr const char *COMMON_EVENT_DATA_SHARE_READY = "COMMON_EVENT_DATA_SHARE_READY";
    static inline constexpr const char *COMMON_EVENT_USER_SWITCHED = "COMMON_EVENT_USER_SWITCHED";
    static inline constexpr const char *COMMON_EVENT_INCOMING_CALL_MISSED = "COMMON_EVENT_INCOMING_CALL_MISSED";
    static inline constexpr const char *COMMON_EVENT_SIM_STATE_CHANGED = "COMMON_EVENT_SIM_STATE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_NAME_UPDATE =
        "COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_NAME_UPDATE";
    static inline constexpr const char *COMMON_EVENT_SHUTDOWN = "COMMON_EVENT_SHUTDOWN";
    static inline constexpr const char *COMMON_EVENT_SCREEN_UNLOCKED = "COMMON_EVENT_SCREEN_UNLOCKED";
    static inline constexpr const char *COMMON_EVENT_SPECIAL_CODE = "COMMON_EVENT_SPECIAL_CODE";
    static inline constexpr const char *COMMON_EVENT_OPERATOR_CONFIG_CHANGED = "COMMON_EVENT_OPERATOR_CONFIG_CHANGED";
    static inline constexpr const char *COMMON_EVENT_NETWORK_STATE_CHANGED = "COMMON_EVENT_NETWORK_STATE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_CALL_STATE_CHANGED = "COMMON_EVENT_CALL_STATE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED =
        "COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED";
    static inline constexpr const char *COMMON_EVENT_SCREEN_ON = "COMMON_EVENT_SCREEN_ON";
    static inline constexpr const char *COMMON_EVENT_SCREEN_OFF = "COMMON_EVENT_SCREEN_OFF";
    static inline constexpr const char *COMMON_EVENT_CONNECTIVITY_CHANGE = "COMMON_EVENT_CONNECTIVITY_CHANGE";
    static inline constexpr const char *COMMON_EVENT_POWER_SAVE_MODE_CHANGED = "COMMON_EVENT_POWER_SAVE_MODE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_CHARGING = "COMMON_EVENT_CHARGING";
    static inline constexpr const char *COMMON_EVENT_DISCHARGING = "COMMON_EVENT_DISCHARGING";
    static inline constexpr const char *COMMON_EVENT_AIRPLANE_MODE_CHANGED = "COMMON_EVENT_AIRPLANE_MODE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_NITZ_TIME_CHANGED = "COMMON_EVENT_NITZ_TIME_CHANGED";
    static inline constexpr const char *COMMON_EVENT_NITZ_TIMEZONE_CHANGED = "COMMON_EVENT_NITZ_TIMEZONE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_LOCALE_CHANGED = "COMMON_EVENT_LOCALE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_SPN_INFO_CHANGED = "COMMON_EVENT_SPN_INFO_CHANGED";
    static inline constexpr const char *COMMON_EVENT_SET_PRIMARY_SLOT_STATUS = "COMMON_EVENT_SET_PRIMARY_SLOT_STATUS";
    static inline constexpr const char *COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED =
        "COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED";
    static inline constexpr const char *COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED =
        "COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED";
    static inline constexpr const char *COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED =
        "COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED";
    static inline constexpr const char *COMMON_EVENT_STK_CARD_STATE_CHANGED = "COMMON_EVENT_STK_CARD_STATE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_STK_SESSION_END = "COMMON_EVENT_STK_SESSION_END";
    static inline constexpr const char *COMMON_EVENT_STK_COMMAND = "COMMON_EVENT_STK_COMMAND";
    static inline constexpr const char *COMMON_EVENT_STK_ALPHA_IDENTIFIER = "COMMON_EVENT_STK_ALPHA_IDENTIFIER";
    static inline constexpr const char *COMMON_EVENT_SMS_EMERGENCY_CB_RECEIVE_COMPLETED =
        "COMMON_EVENT_SMS_EMERGENCY_CB_RECEIVE_COMPLETED";
    static inline constexpr const char *COMMON_EVENT_SMS_CB_RECEIVE_COMPLETED = "COMMON_EVENT_SMS_CB_RECEIVE_COMPLETED";
    static inline constexpr const char *COMMON_EVENT_SMS_RECEIVE_COMPLETED = "COMMON_EVENT_SMS_RECEIVE_COMPLETED";
    static inline constexpr const char *COMMON_EVENT_SMS_WAPPUSH_RECEIVE_COMPLETED =
        "COMMON_EVENT_SMS_WAPPUSH_RECEIVE_COMPLETED";
    static inline constexpr const char *COMMON_EVENT_BATTERY_LOW = "COMMON_EVENT_BATTERY_LOW";
    static inline constexpr const char *COMMON_EVENT_SECOND_MOUNTED = "COMMON_EVENT_SECOND_MOUNTED";
    static inline constexpr const char *COMMON_EVENT_CELLULAR_DATA_STATE_CHANGED =
        "COMMON_EVENT_CELLULAR_DATA_STATE_CHANGED";
    static inline constexpr const char *COMMON_EVENT_SIGNAL_INFO_CHANGED = "COMMON_EVENT_SIGNAL_INFO_CHANGED";

private:
    static inline const std::vector<std::string> commonEventVector_ = {COMMON_EVENT_RADIO_STATE_CHANGE,
        COMMON_EVENT_DATA_SHARE_READY,
        COMMON_EVENT_USER_SWITCHED,
        COMMON_EVENT_INCOMING_CALL_MISSED,
        COMMON_EVENT_SIM_STATE_CHANGED,
        COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_NAME_UPDATE,
        COMMON_EVENT_SHUTDOWN,
        COMMON_EVENT_SCREEN_UNLOCKED,
        COMMON_EVENT_SPECIAL_CODE,
        COMMON_EVENT_OPERATOR_CONFIG_CHANGED,
        COMMON_EVENT_NETWORK_STATE_CHANGED,
        COMMON_EVENT_CALL_STATE_CHANGED,
        COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED,
        COMMON_EVENT_SCREEN_ON,
        COMMON_EVENT_SCREEN_OFF,
        COMMON_EVENT_CONNECTIVITY_CHANGE,
        COMMON_EVENT_POWER_SAVE_MODE_CHANGED,
        COMMON_EVENT_CHARGING,
        COMMON_EVENT_DISCHARGING,
        COMMON_EVENT_AIRPLANE_MODE_CHANGED,
        COMMON_EVENT_NITZ_TIME_CHANGED,
        COMMON_EVENT_NITZ_TIMEZONE_CHANGED,
        COMMON_EVENT_LOCALE_CHANGED,
        COMMON_EVENT_SPN_INFO_CHANGED,
        COMMON_EVENT_SET_PRIMARY_SLOT_STATUS,
        COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED,
        COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED,
        COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED,
        COMMON_EVENT_STK_CARD_STATE_CHANGED,
        COMMON_EVENT_STK_SESSION_END,
        COMMON_EVENT_STK_COMMAND,
        COMMON_EVENT_STK_ALPHA_IDENTIFIER,
        COMMON_EVENT_SMS_EMERGENCY_CB_RECEIVE_COMPLETED,
        COMMON_EVENT_SMS_CB_RECEIVE_COMPLETED,
        COMMON_EVENT_SMS_RECEIVE_COMPLETED,
        COMMON_EVENT_SMS_WAPPUSH_RECEIVE_COMPLETED,
        COMMON_EVENT_BATTERY_LOW,
        COMMON_EVENT_SECOND_MOUNTED,
        COMMON_EVENT_CELLULAR_DATA_STATE_CHANGED,
        COMMON_EVENT_SIGNAL_INFO_CHANGED};
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // COMMON_EVENT_SUPPORT_H