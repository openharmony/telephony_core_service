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

#include "../core/telephony_errors.h"

namespace OHOS {
namespace Telephony {
enum CallManagerErrorCode {
    CALL_ERR_PHONE_NUMBER_EMPTY = CALL_ERR_OFFSET,
    CALL_ERR_DIAL_FAILED,
    CALL_ERR_ACCEPT_FAILED,
    CALL_ERR_REJECT_FAILED,
    CALL_ERR_HOLD_FAILED,
    CALL_ERR_UNHOLD_FAILED,
    CALL_ERR_HANGUP_FAILED,
    CALL_ERR_NOT_NEW_STATE,
    CALL_ERR_DIAL_SCENE_INCORRECT,
    CALL_ERR_CREATE_CALL_OBJECT_FAILED,
    CALL_ERR_CALL_OBJECT_IS_NULL,
    CALL_ERR_NUMBER_OUT_OF_RANGE,
    CALL_ERR_DIAL_IS_BUSY,
    CALL_ERR_CALLID_INVALID,
    CALL_ERR_CALL_IS_NOT_ACTIVATED,
    CALL_ERR_CALL_IS_NOT_ON_HOLDING,
    CALL_ERR_ILLEGAL_CALL_OPERATION,
    CALL_ERR_CALL_STATE_MISMATCH_OPERATION,
    CALL_ERR_SEND_DTMF_INPUT_IS_EMPTY,
    CALL_ERR_DTMF_PARAMETER_INVALID,
    CALL_ERR_FORMAT_PHONE_NUMBER_FAILED,
    CALL_ERR_CONFERENCE_NOT_EXISTS,
    CALL_ERR_CONFERENCE_CALL_EXCEED_LIMIT,
    CALL_ERR_UNKNOW_DIAL_TYPE,
    CALL_ERR_CALLBACK_ALREADY_EXIST,
    CALL_ERR_CALL_STATE, // call state error
    CALL_ERR_CALL_COUNTS_EXCEED_LIMIT, // call count exceed limit
    CALL_ERR_CALL_CONNECTION_NOT_EXIST, // Connection is null
    CALL_ERR_GET_RADIO_STATE_FAILED, // radio state error
    CALL_ERR_UNSUPPORTED_NETWORK_TYPE, // Network type error
    CALL_ERR_INVALID_SLOT_ID, // invalid slot id
    CALL_ERR_UNKNOW_CALL_TYPE,
    CALL_ERR_VIDEO_ILLEGAL_CALL_TYPE,
    CALL_ERR_VIDEO_ILLEGAL_MEDIA_TYPE,
    CALL_ERR_FUNCTION_NOT_SUPPORTED,
    CALL_ERR_INVALID_DIAL_SCENE,
    CALL_ERR_INVALID_VIDEO_STATE,
    CALL_ERR_EMERGENCY_UNSOPPORT_CONFERENCEABLE,
    CALL_ERR_INVALID_RESTRICTION_TYPE,
    CALL_ERR_INVALID_RESTRICTION_MODE,
    CALL_ERR_INVALID_TRANSFER_TYPE,
    CALL_ERR_INVALID_TRANSFER_SETTING_TYPE,
};

// 3GPP TS 24.008 V3.9.0 (2001-09)  10.5.4.11 Cause
enum PROTOCOL_ERROR_TYPE {
    CALL_ERR_PARAMETER_OUT_OF_RANGE = PROTOCOL_ERR_OFFSET, // (e.g. parameter out of range)
    CALL_ERR_CALL_ALREADY_EXISTS, // Call completed elsewhere
    CALL_ERR_RADIO_STATE, // Radio state error, Network out of order
    CALL_ERR_RESOURCE_UNAVAILABLE, // Resources unavailable, unspecified
    CALL_ERR_OPTION_NOT_AVAILABLE, // service or option not available
    CALL_ERR_OPTION_NOT_IMPLEMENTED, // service or option not implemented
};
} // namespace Telephony
} // namespace OHOS

#endif // CALL_MANAGER_ERRORS_H
