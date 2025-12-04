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

#include "core_service_hisysevent.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
// EVENT
static constexpr const char *SIGNAL_LEVEL_EVENT = "SIGNAL_LEVEL";
static constexpr const char *NETWORK_REGISTER_EVENT = "NETWORK_REGISTER";
static constexpr const char *RADIO_STATE_CHANGE_EVENT = "RADIO_STATE_CHANGE";
static constexpr const char *SET_DEFAULT_CELLULAR_DATA_EVENT = "SET_DEFAULT_CELLULAR_DATA";
static constexpr const char *SIM_STATE_CHANGE_EVENT = "SIM_STATE_CHANGE";
static constexpr const char *CALL_DIAL_FAILED_EVENT = "CALL_DIAL_FAILED";
static constexpr const char *CALL_ANSWER_FAILED_EVENT = "CALL_ANSWER_FAILED";
static constexpr const char *CALL_HANGUP_FAILED_EVENT = "CALL_HANGUP_FAILED";
static constexpr const char *SMS_SEND_FAILED_EVENT = "SMS_SEND_FAILED";
static constexpr const char *SMS_RECEIVE_FAILED_EVENT = "SMS_RECEIVE_FAILED";
static constexpr const char *DATA_ACTIVATE_FAILED_EVENT = "DATA_ACTIVATE_FAILED";
static constexpr const char *AIRPLANE_MODE_EVENT = "AIRPLANE_MODE_STATE";
static constexpr const char *SET_ACTIVESIM_FAILED_EVENT = "SET_ACTIVESIM_FAILED";
static constexpr const char *MATCH_SIM_EVENT = "SIM_MATCH";

// KEY
static constexpr const char *SLOT_ID_KEY = "SLOT_ID";
static constexpr const char *SIGANL_LEVEL_KEY = "LEVEL";
static constexpr const char *NETWORK_DOMAIN_KEY = "REGISTRATION_DOMAIN";
static constexpr const char *NETWORK_TECH_KEY = "RADIO_TECH";
static constexpr const char *NETWORK_STATE_KEY = "REGISTRATION_STATE";
static constexpr const char *STATE_KEY = "STATE";
static constexpr const char *MODULE_NAME_KEY = "MODULE";
static constexpr const char *CALL_ID_KEY = "CALL_ID";
static constexpr const char *CALL_TYPE_KEY = "CALL_TYPE";
static constexpr const char *VIDEO_STATE_KEY = "VIDEO_STATE";
static constexpr const char *ERROR_TYPE_KEY = "ERROR_TYPE";
static constexpr const char *ERROR_MSG_KEY = "ERROR_MSG";
static constexpr const char *MSG_TYPE_KEY = "MSG_TYPE";
static constexpr const char *DATA_SWITCH_KEY = "DATA_SWITCH";
static constexpr const char *UPLINK_DATA_KEY = "UPLINK_DATA";
static constexpr const char *DOWNLINK_DATA_KEY = "DOWNLINK_DATA";
static constexpr const char *DATASTATE_KEY = "DATASTATE";
static constexpr const char *SWITCH_KEY = "SWITCH";
static constexpr const char *SIM_STATE_KEY = "SIM_STATE";
static constexpr const char *MATCHSIM_FILE_STATE_KEY = "MATCHSIM_FILE_STATE";
static constexpr const char *MATCHSIM_REASON_KEY = "MATCHSIM_REASON";
static constexpr const char *MATCHSIM_STATE_TRACKER_KEY = "MATCHSIM_STATE_TRACKER";
static constexpr const char *MATCHSIM_FAIL_REASON_KEY = "MATCHSIM_FAIL_REASON";
static constexpr const char *MATCHSIM_STATE_KEY = "MATCHSIM_STATE";
static constexpr const char *MATCHSIM_OPKEY_KEY = "MATCHSIM_OPKEY";
static constexpr const char *MATCHSIM_OPNAME_KEY = "MATCHSIM_OPNAME";
static constexpr const char *MATCHSIM_SPN_KEY = "MATCHSIM_SPN";
static constexpr const char *MATCHSIM_GID1_KEY = "MATCHSIM_GID1";
static constexpr const char *MATCHSIM_GID2_KEY = "MATCHSIM_GID2";
static constexpr const char *MATCHSIM_MCCMNC_KEY = "MATCHSIM_MCCMNC";

// VALUE
static constexpr const char *CORE_SERVICE_MODULE = "CORE_SERVICE";

void CoreServiceHiSysEvent::WriteSignalLevelBehaviorEvent(int32_t slotId, int32_t level)
{
    HiWriteBehaviorEvent(SIGNAL_LEVEL_EVENT, SLOT_ID_KEY, slotId, SIGANL_LEVEL_KEY, level);
}

void CoreServiceHiSysEvent::WriteNetworkStateBehaviorEvent(int32_t slotId, int32_t domain, int32_t tech, int32_t state)
{
    HiWriteBehaviorEvent(NETWORK_REGISTER_EVENT, SLOT_ID_KEY, slotId, NETWORK_DOMAIN_KEY, domain, NETWORK_TECH_KEY,
        tech, NETWORK_STATE_KEY, state);
}

void CoreServiceHiSysEvent::WriteRadioStateBehaviorEvent(int32_t slotId, int32_t state)
{
    HiWriteBehaviorEvent(RADIO_STATE_CHANGE_EVENT, SLOT_ID_KEY, slotId, STATE_KEY, state);
}

void CoreServiceHiSysEvent::WriteDefaultDataSlotIdBehaviorEvent(int32_t slotId)
{
    HiWriteBehaviorEvent(SET_DEFAULT_CELLULAR_DATA_EVENT, SLOT_ID_KEY, slotId);
}

void CoreServiceHiSysEvent::WriteSimStateBehaviorEvent(int32_t slotId, int32_t state)
{
    HiWriteBehaviorEvent(SIM_STATE_CHANGE_EVENT, SLOT_ID_KEY, slotId, STATE_KEY, state);
}

void CoreServiceHiSysEvent::WriteDialCallFaultEvent(int32_t slotId, int32_t errCode, const std::string &desc)
{
    HiWriteFaultEvent(CALL_DIAL_FAILED_EVENT, MODULE_NAME_KEY, CORE_SERVICE_MODULE, SLOT_ID_KEY, slotId, CALL_TYPE_KEY,
        INVALID_PARAMETER, VIDEO_STATE_KEY, INVALID_PARAMETER, ERROR_TYPE_KEY, errCode, ERROR_MSG_KEY, desc);
}

void CoreServiceHiSysEvent::WriteAnswerCallFaultEvent(int32_t slotId, int32_t errCode, const std::string &desc)
{
    HiWriteFaultEvent(CALL_ANSWER_FAILED_EVENT, MODULE_NAME_KEY, CORE_SERVICE_MODULE, SLOT_ID_KEY, slotId, CALL_ID_KEY,
        INVALID_PARAMETER, VIDEO_STATE_KEY, INVALID_PARAMETER, ERROR_TYPE_KEY, errCode, ERROR_MSG_KEY, desc);
}

void CoreServiceHiSysEvent::WriteHangUpFaultEvent(int32_t slotId, int32_t errCode, const std::string &desc)
{
    HiWriteFaultEvent(CALL_HANGUP_FAILED_EVENT, MODULE_NAME_KEY, CORE_SERVICE_MODULE, SLOT_ID_KEY, slotId, CALL_ID_KEY,
        INVALID_PARAMETER, ERROR_TYPE_KEY, errCode, ERROR_MSG_KEY, desc);
}

void CoreServiceHiSysEvent::WriteSmsSendFaultEvent(
    int32_t slotId, SmsMmsMessageType type, SmsMmsErrorCode errorCode, const std::string &desc)
{
    HiWriteFaultEvent(SMS_SEND_FAILED_EVENT, MODULE_NAME_KEY, CORE_SERVICE_MODULE, SLOT_ID_KEY, slotId, MSG_TYPE_KEY,
        static_cast<int32_t>(type), ERROR_TYPE_KEY, static_cast<int32_t>(errorCode), ERROR_MSG_KEY, desc);
}

void CoreServiceHiSysEvent::WriteSmsReceiveFaultEvent(
    int32_t slotId, SmsMmsMessageType type, SmsMmsErrorCode errorCode, const std::string &desc)
{
    HiWriteFaultEvent(SMS_RECEIVE_FAILED_EVENT, MODULE_NAME_KEY, CORE_SERVICE_MODULE, SLOT_ID_KEY, slotId, MSG_TYPE_KEY,
        static_cast<int32_t>(type), ERROR_TYPE_KEY, static_cast<int32_t>(errorCode), ERROR_MSG_KEY, desc);
}

void CoreServiceHiSysEvent::WriteDataActivateFaultEvent(
    int32_t slotId, int32_t switchState, CellularDataErrorCode errorType, const std::string &errorMsg)
{
    HiWriteFaultEvent(DATA_ACTIVATE_FAILED_EVENT, MODULE_NAME_KEY, CORE_SERVICE_MODULE, SLOT_ID_KEY, slotId,
        DATA_SWITCH_KEY, switchState, UPLINK_DATA_KEY, INVALID_PARAMETER, DOWNLINK_DATA_KEY, INVALID_PARAMETER,
        DATASTATE_KEY, INVALID_PARAMETER, ERROR_TYPE_KEY, static_cast<int32_t>(errorType), ERROR_MSG_KEY, errorMsg);
}

void CoreServiceHiSysEvent::WriteAirplaneModeChangeEvent(const int32_t enable)
{
    HiWriteBehaviorEvent(AIRPLANE_MODE_EVENT, SWITCH_KEY, enable);
}

void CoreServiceHiSysEvent::WriteSetActiveSimFaultEvent(
    int32_t slotId, SimCardErrorCode errorCode, const std::string &desc)
{
    HiWriteFaultEvent(SET_ACTIVESIM_FAILED_EVENT, MODULE_NAME_KEY, CORE_SERVICE_MODULE, SLOT_ID_KEY, slotId,
        ERROR_TYPE_KEY, static_cast<int32_t>(errorCode), ERROR_MSG_KEY, desc);
}

void CoreServiceHiSysEvent::WriteMatchSimBehaviorEvent(int32_t slotId, const MatchSimInfo &matchSimInfo)
{
    HiWriteBehaviorEvent(MATCH_SIM_EVENT,
        SLOT_ID_KEY, slotId,
        SIM_STATE_KEY, matchSimInfo.simState,
        MATCHSIM_FILE_STATE_KEY, matchSimInfo.matchSimFileState,
        MATCHSIM_REASON_KEY, matchSimInfo.matchSimReason,
        MATCHSIM_STATE_TRACKER_KEY, matchSimInfo.matchSimStateTracker,
        MATCHSIM_FAIL_REASON_KEY, matchSimInfo.matchSimFailReason,
        MATCHSIM_STATE_KEY, matchSimInfo.matchSimState,
        MATCHSIM_OPKEY_KEY, matchSimInfo.GetOpkey(),
        MATCHSIM_OPNAME_KEY, matchSimInfo.GetOpname(),
        MATCHSIM_SPN_KEY, matchSimInfo.GetSpn(),
        MATCHSIM_GID1_KEY, matchSimInfo.GetGid1(),
        MATCHSIM_GID2_KEY, matchSimInfo.GetGid2(),
        MATCHSIM_MCCMNC_KEY, matchSimInfo.GetMccMnc());
}
} // namespace Telephony
} // namespace OHOS
