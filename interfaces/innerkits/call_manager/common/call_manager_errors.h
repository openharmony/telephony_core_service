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

#ifndef CALL_MANAGER_ERRORS_H
#define CALL_MANAGER_ERRORS_H

#include "../../common/telephony_errors.h"

namespace OHOS {
namespace Telephony {
enum CallManagerErrorCode {
    CALL_MANAGER_PHONE_NUMBER_NULL = CALL_ERR_OFFSET,
    CALL_MANAGER_DIAL_FAILED,
    CALL_MANAGER_ACCEPT_FAILED,
    CALL_MANAGER_REJECT_FAILED,
    CALL_MANAGER_HOLD_FAILED,
    CALL_MANAGER_UNHOLD_FAILED,
    CALL_MANAGER_HANGUP_FAILED,
    CALL_MANAGER_NOT_NEW_STATE,
    CALL_MANAGER_DIAL_SCENE_INCORRECT,
    CALL_MANAGER_CREATE_CALL_OBJECT_FAIL,
    CALL_MANAGER_SETAUDIO_FAILED,
    CALL_MANAGER_CALL_NULL,
    CALL_MANAGER_CALL_EXIST, // already exists and needs to be deleted
    CALL_MANAGER_CALL_DISCONNECTED,
    CALL_MANAGER_PHONE_BEYOND,
    CALL_MANAGER_HAS_NEW_CALL,
    CALL_MANAGER_VIDEO_MODE_ERR,
    CALL_MANAGER_PHONE_NUMBER_INVALID,
    CALL_MANAGER_CALLID_INVALID,
    CALL_MANAGER_CURRENT_RINGING,
    CALL_MANAGER_SWAP_FAILED,
    CALL_MANAGER_CALL_IS_NOT_ACTIVATED,
    CALL_MANAGER_CALL_IS_NOT_ON_HOLDING,
    CALL_MANAGER_SET_MUTE_FAILED,
    CALL_MANAGER_MUTE_RINGER_FAILED,
    CALL_MANAGER_SET_AUDIO_DEVICE_FAILED,
    CALL_MANAGER_GET_IS_RINGING_FAILED,
    CALL_MANAGER_UPDATE_CALL_STATE_FAILED,
    CALL_MANAGER_UPDATE_CALL_EVENT_FAILED,
    CALL_MANAGER_ILLEGAL_CALL_OPERATION,
    CALL_MANAGER_CALL_STATE_MISMATCH_OPERATION,
    CALL_MANAGER_START_DTMF_FAILED,
    CALL_MANAGER_SEND_DTMF_FAILED,
    CALL_MANAGER_SEND_DTMF_BUNCH_FAILED,
    CALL_MANAGER_STOP_DTMF_FAILED,
    CALL_MANAGER_SEND_DTMF_INPUT_IS_EMPTY,
    CALL_MANAGER_DTMF_PARAMETER_INVALID,
    CALL_MANAGER_FORMATTING_FAILED,
    CALL_MANAGER_CONFERENCE_NOT_EXISTS,
    CALL_MANAGER_CONFERENCE_CALL_EXCEED_LIMIT,
    CALL_MANAGER_UNKNOW_DIAL_TYPE,
    CALL_MANAGER_HAS_CALLBACK,

    // cellular call
    ERR_PARAMETER_INVALID, // parameter error or invalid
    ERR_CALL_STATE, // call state error
    ERR_CALL_NUMBER_LIMIT, // call number limit
    ERR_MMI_TYPE, // include：Supplementary Service、USSD
    ERR_SYSTEM_INVOKE, // Error calling standard system library function, such as: strcpy_s、 memset_s
    ERR_CONNECTION, // Connection is null
    ERR_GET_RADIO_STATE, // radio state error
    ERR_REPORT_CALLS_INFO, // report calls info error
    ERR_NETWORK_TYPE, // Network type error
    ERR_NULL_POINTER, // pointer is nullptr
    ERR_PHONE_NUMBER_EMPTY, // phone number is empty
    ERR_INVALID_SLOT_ID, // invalid slot id
};

// 3GPP TS 24.008 V3.9.0 (2001-09)  10.5.4.11 Cause
enum PROTOCOL_ERROR_TYPE {
    ERR_PARAMETER_OUT_OF_RANGE = PROTOCOL_ERR_OFFSET, // (e.g. parameter out of range)
    ERR_CALL_ALREADY_EXISTS, // Call completed elsewhere
    ERR_RADIO_STATE, // Radio state error, Network out of order
    ERR_MANDATORY_INFO_INVALID, // Invalid mandatory information
    ERR_RESOURCE_UNAVAILABLE, // Resources unavailable, unspecified
    ERR_OPTION_NOT_AVAILABLE, // service or option not available
    ERR_OPTION_NOT_IMPLEMENTED, // service or option not implemented
    ERR_DESCRIPTOR_INVALID, // descriptor checked fail, Invalid transaction identifier value
};
} // namespace Telephony
} // namespace OHOS

#endif // CALL_MANAGER_ERRORS_H
