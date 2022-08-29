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

#ifndef ENUM_CONVERT_H
#define ENUM_CONVERT_H

#include <string>

namespace OHOS {
namespace Telephony {
enum class TelephonyCardType {
    UNKNOWN_CARD = -1,
    SINGLE_MODE_SIM_CARD = 10,
    SINGLE_MODE_USIM_CARD = 20,
    SINGLE_MODE_RUIM_CARD = 30,
    DUAL_MODE_CG_CARD = 40,
    CT_NATIONAL_ROAMING_CARD = 41,
    CU_DUAL_MODE_CARD = 42,
    DUAL_MODE_TELECOM_LTE_CARD = 43,
    DUAL_MODE_UG_CARD = 50,
    SINGLE_MODE_ISIM_CARD = 60,
};

enum class TelephonySimState {
    SIM_STATE_UNKNOWN,
    SIM_STATE_NOT_PRESENT,
    SIM_STATE_LOCKED,
    SIM_STATE_NOT_READY,
    SIM_STATE_READY,
    SIM_STATE_LOADED
};

enum class TelephonyDataConnectionStatus {
    DATA_STATE_DISCONNECTED = 11,
    DATA_STATE_CONNECTING = 12,
    DATA_STATE_CONNECTED = 13,
    DATA_STATE_SUSPENDED = 14
};

enum class TelephonyCallState {
    CALL_STATUS_ACTIVE = 0,
    CALL_STATUS_HOLDING,
    CALL_STATUS_DIALING,
    CALL_STATUS_ALERTING,
    CALL_STATUS_INCOMING,
    CALL_STATUS_WAITING,
    CALL_STATUS_DISCONNECTED,
    CALL_STATUS_DISCONNECTING,
    CALL_STATUS_IDLE,
};

enum class TelephonyRadioTech {
    RADIO_TECHNOLOGY_UNKNOWN = 0,
    RADIO_TECHNOLOGY_GSM = 1,
    RADIO_TECHNOLOGY_1XRTT = 2,
    RADIO_TECHNOLOGY_WCDMA = 3,
    RADIO_TECHNOLOGY_HSPA = 4,
    RADIO_TECHNOLOGY_HSPAP = 5,
    RADIO_TECHNOLOGY_TD_SCDMA = 6,
    RADIO_TECHNOLOGY_EVDO = 7,
    RADIO_TECHNOLOGY_EHRPD = 8,
    RADIO_TECHNOLOGY_LTE = 9,
    RADIO_TECHNOLOGY_LTE_CA = 10,
    RADIO_TECHNOLOGY_IWLAN = 11,
    RADIO_TECHNOLOGY_NR = 12
};

enum class TelephonyCellDataFlowType {
    DATA_FLOW_TYPE_NONE = 0,
    DATA_FLOW_TYPE_DOWN = 1,
    DATA_FLOW_TYPE_UP = 2,
    DATA_FLOW_TYPE_UP_DOWN = 3,
    DATA_FLOW_TYPE_DORMANT = 4
};

enum class TelephonyLockReason {
    SIM_NONE,
    SIM_PIN,
    SIM_PUK,
    SIM_PN_PIN,
    SIM_PN_PUK,
    SIM_PU_PIN,
    SIM_PU_PUK,
    SIM_PP_PIN,
    SIM_PP_PUK,
    SIM_PC_PIN,
    SIM_PC_PUK,
    SIM_SIM_PIN,
    SIM_SIM_PUK,
};

std::string GetBoolValue(int32_t value);
std::string GetSimState(int32_t state);
std::string GetCallState(int32_t state);
std::string GetCardType(int32_t type);
std::string GetCellularDataConnectionState(int32_t state);
std::string GetCellularDataFlow(int32_t flowData);
std::string GetCellularDataConnectionNetworkType(int32_t type);
std::string GetLockReason(int32_t reason);
} // namespace Telephony
} // namespace OHOS

#endif // ENUM_CONVERT_H
