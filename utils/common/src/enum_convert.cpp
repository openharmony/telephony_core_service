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

#include "enum_convert.h"

#include "string"

namespace OHOS {
namespace Telephony {
std::string GetBoolValue(int32_t value)
{
    std::string result = "";
    if (value == 0) {
        result = "FALSE";
    } else {
        result = "TRUE";
    }
    return result;
}

std::string GetSimState(int32_t state)
{
    std::string result = "";
    switch (static_cast<TelephonySimState>(state)) {
        case TelephonySimState::SIM_STATE_UNKNOWN:
            result = "SIM_STATE_UNKNOWN";
            break;
        case TelephonySimState::SIM_STATE_NOT_PRESENT:
            result = "SIM_STATE_NOT_PRESENT";
            break;
        case TelephonySimState::SIM_STATE_LOCKED:
            result = "SIM_STATE_LOCKED";
            break;
        case TelephonySimState::SIM_STATE_NOT_READY:
            result = "SIM_STATE_NOT_READY";
            break;
        case TelephonySimState::SIM_STATE_READY:
            result = "SIM_STATE_READY";
            break;
        case TelephonySimState::SIM_STATE_LOADED:
            result = "SIM_STATE_LOADED";
            break;
        default:
            break;
    }
    return result;
}

std::string GetCallState(int32_t state)
{
    std::string result = "CALL_STATUS_IDLE";
    switch (static_cast<TelephonyCallState>(state)) {
        case TelephonyCallState::CALL_STATUS_ACTIVE:
            result = "CALL_STATUS_ACTIVE";
            break;
        case TelephonyCallState::CALL_STATUS_HOLDING:
            result = "CALL_STATUS_HOLDING";
            break;
        case TelephonyCallState::CALL_STATUS_DIALING:
            result = "CALL_STATUS_DIALING";
            break;
        case TelephonyCallState::CALL_STATUS_ALERTING:
            result = "CALL_STATUS_ALERTING";
            break;
        case TelephonyCallState::CALL_STATUS_INCOMING:
            result = "CALL_STATUS_INCOMING";
            break;
        case TelephonyCallState::CALL_STATUS_WAITING:
            result = "CALL_STATUS_WAITING";
            break;
        case TelephonyCallState::CALL_STATUS_DISCONNECTED:
            result = "CALL_STATUS_DISCONNECTED";
            break;
        case TelephonyCallState::CALL_STATUS_DISCONNECTING:
            result = "CALL_STATUS_DISCONNECTING";
            break;
        case TelephonyCallState::CALL_STATUS_IDLE:
            result = "CALL_STATUS_IDLE";
            break;
        default:
            break;
    }
    return result;
}

std::string GetCardType(int32_t type)
{
    std::string result = "";
    switch (static_cast<TelephonyCardType>(type)) {
        case TelephonyCardType::UNKNOWN_CARD:
            result = "UNKNOWN_CARD";
            break;
        case TelephonyCardType::SINGLE_MODE_SIM_CARD:
            result = "SINGLE_MODE_SIM_CARD";
            break;
        case TelephonyCardType::SINGLE_MODE_USIM_CARD:
            result = "SINGLE_MODE_USIM_CARD";
            break;
        case TelephonyCardType::SINGLE_MODE_RUIM_CARD:
            result = "SINGLE_MODE_RUIM_CARD";
            break;
        case TelephonyCardType::DUAL_MODE_CG_CARD:
            result = "DUAL_MODE_CG_CARD";
            break;
        case TelephonyCardType::CT_NATIONAL_ROAMING_CARD:
            result = "CT_NATIONAL_ROAMING_CARD";
            break;
        case TelephonyCardType::CU_DUAL_MODE_CARD:
            result = "CU_DUAL_MODE_CARD";
            break;
        case TelephonyCardType::DUAL_MODE_TELECOM_LTE_CARD:
            result = "DUAL_MODE_TELECOM_LTE_CARD";
            break;
        case TelephonyCardType::DUAL_MODE_UG_CARD:
            result = "DUAL_MODE_UG_CARD";
            break;
        case TelephonyCardType::SINGLE_MODE_ISIM_CARD:
            result = "SINGLE_MODE_ISIM_CARD";
            break;
        default:
            break;
    }
    return result;
}

std::string GetCellularDataConnectionState(int32_t state)
{
    std::string result = "";
    switch (static_cast<TelephonyDataConnectionStatus>(state)) {
        case TelephonyDataConnectionStatus::DATA_STATE_DISCONNECTED:
            result = "DATA_STATE_DISCONNECTED";
            break;
        case TelephonyDataConnectionStatus::DATA_STATE_CONNECTING:
            result = "DATA_STATE_CONNECTING";
            break;
        case TelephonyDataConnectionStatus::DATA_STATE_CONNECTED:
            result = "DATA_STATE_CONNECTED";
            break;
        case TelephonyDataConnectionStatus::DATA_STATE_SUSPENDED:
            result = "DATA_STATE_SUSPENDED";
            break;
        default:
            break;
    }
    return result;
}

std::string GetCellularDataFlow(int32_t flowData)
{
    std::string result = "";
    switch (static_cast<TelephonyCellDataFlowType>(flowData)) {
        case TelephonyCellDataFlowType::DATA_FLOW_TYPE_NONE:
            result = "DATA_FLOW_TYPE_NONE";
            break;
        case TelephonyCellDataFlowType::DATA_FLOW_TYPE_DOWN:
            result = "DATA_FLOW_TYPE_DOWN";
            break;
        case TelephonyCellDataFlowType::DATA_FLOW_TYPE_UP:
            result = "DATA_FLOW_TYPE_UP";
            break;
        case TelephonyCellDataFlowType::DATA_FLOW_TYPE_UP_DOWN:
            result = "DATA_FLOW_TYPE_UP_DOWN";
            break;
        case TelephonyCellDataFlowType::DATA_FLOW_TYPE_DORMANT:
            result = "DATA_FLOW_TYPE_DORMANT";
            break;
        default:
            break;
    }
    return result;
}

std::string GetCellularDataConnectionNetworkType(int32_t type)
{
    std::string result = "";
    switch (static_cast<TelephonyRadioTech>(type)) {
        case TelephonyRadioTech::RADIO_TECHNOLOGY_UNKNOWN:
            result = "RADIO_TECHNOLOGY_UNKNOWN";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_GSM:
            result = "RADIO_TECHNOLOGY_GSM";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_1XRTT:
            result = "RADIO_TECHNOLOGY_1XRTT";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_WCDMA:
            result = "RADIO_TECHNOLOGY_WCDMA";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_HSPA:
            result = "RADIO_TECHNOLOGY_HSPA";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_HSPAP:
            result = "RADIO_TECHNOLOGY_HSPAP";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_TD_SCDMA:
            result = "RADIO_TECHNOLOGY_TD_SCDMA";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_EVDO:
            result = "RADIO_TECHNOLOGY_EVDO";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_EHRPD:
            result = "RADIO_TECHNOLOGY_EHRPD";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_LTE:
            result = "RADIO_TECHNOLOGY_LTE";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_LTE_CA:
            result = "RADIO_TECHNOLOGY_LTE_CA";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_IWLAN:
            result = "RADIO_TECHNOLOGY_IWLAN";
            break;
        case TelephonyRadioTech::RADIO_TECHNOLOGY_NR:
            result = "RADIO_TECHNOLOGY_NR";
            break;
        default:
            break;
    }
    return result;
}

std::string GetLockReason(int32_t reason)
{
    std::string result = "";
    switch (static_cast<TelephonyLockReason>(reason)) {
        case TelephonyLockReason::SIM_NONE:
            result = "SIM_NONE";
            break;
        case TelephonyLockReason::SIM_PIN:
            result = "SIM_PIN";
            break;
        case TelephonyLockReason::SIM_PUK:
            result = "SIM_PUK";
            break;
        case TelephonyLockReason::SIM_PN_PIN:
            result = "SIM_PN_PIN";
            break;
        case TelephonyLockReason::SIM_PN_PUK:
            result = "SIM_PN_PUK";
            break;
        case TelephonyLockReason::SIM_PU_PIN:
            result = "SIM_PU_PIN";
            break;
        case TelephonyLockReason::SIM_PU_PUK:
            result = "SIM_PU_PUK";
            break;
        case TelephonyLockReason::SIM_PP_PIN:
            result = "SIM_PP_PIN";
            break;
        case TelephonyLockReason::SIM_PP_PUK:
            result = "SIM_PP_PUK";
            break;
        case TelephonyLockReason::SIM_PC_PIN:
            result = "SIM_PC_PIN";
            break;
        case TelephonyLockReason::SIM_PC_PUK:
            result = "SIM_PC_PUK";
            break;
        case TelephonyLockReason::SIM_SIM_PIN:
            result = "SIM_SIM_PIN";
            break;
        case TelephonyLockReason::SIM_SIM_PUK:
            result = "SIM_SIM_PUK";
            break;
        default:
            break;
    }
    return result;
}
} // namespace Telephony
} // namespace OHOS
