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

#ifndef TELEPHONY_HISYSEVENT_H
#define TELEPHONY_HISYSEVENT_H

#include <string>

#include "hisysevent.h"

namespace OHOS {
namespace Telephony {
using EventType = OHOS::HiviewDFX::HiSysEvent::EventType;
static constexpr const char *DOMAIN_NAME = OHOS::HiviewDFX::HiSysEvent::Domain::TELEPHONY;
static const int32_t INVALID_PARAMETER = 0xFF;

/**
 * @brief Indicates the error code of call.
 */
enum class CallErrorCode {
    /**
     * Indicates no error.
     */
    CALL_ERROR_NONE = 0,

    /**
     * Indicates the permission error.
     */
    CALL_ERROR_PERMISSION_ERR = 1,

    /**
     * Indicates the phone number is empty.
     */
    CALL_ERROR_PHONE_NUMBER_EMPTY,

    /**
     * Indicates the phone number is out of range.
     */
    CALL_ERROR_NUMBER_OUT_OF_RANGE,

    /**
     * Indicates the ptr is null.
     */
    CALL_ERROR_CALL_LOCAL_PTR_NULL,

    /**
     * Indicates the dial type is unknown, out of CARRIER, VOICE_MAIL or OTT type.
     */
    CALL_ERROR_UNKNOW_DIAL_TYPE,

    /**
     * Indicates the slot id is invalid.
     */
    CALL_ERROR_INVALID_SLOT_ID,

    /**
     * Indicates the call type is unknown, out of CS, IMS or OTT type.
     */
    CALL_ERROR_UNKNOW_CALL_TYPE,

    /**
     * Indicates the dial scene is invalid.
     */
    CALL_ERROR_INVALID_DIAL_SCENE,

    /**
     * Indicates the video state is invalid.
     */
    CALL_ERROR_INVALID_VIDEO_STATE,

    /**
     * Indicates the call id is valid.
     */
    CALL_ERROR_INVALID_CALLID,

    /**
     * Indicates the dial is busy, there is already a new call creating/connecting or dialing.
     */
    CALL_ERROR_DIAL_IS_BUSY = 11,

    /**
     * Indicates the dial time is out of range.
     */
    CALL_ERROR_DIAL_TIME_OUT,

    /**
     * Indicates the incoming time is out of range.
     */
    CALL_ERROR_INCOMING_TIME_OUT,

    /**
     * Indicates the answer time is out of range.
     */
    CALL_ERROR_ANSWER_TIME_OUT,

    /**
     * Indicates failed to send the event handle.
     */
    CALL_ERROR_SYSTEM_EVENT_HANDLE_FAILURE,

    /**
     * Indicates the dial number is not a valid FDN number.
     */
    CALL_ERROR_INVALID_FDN_NUMBER,

    /**
     * Indicates the device is not dialing.
     */
    CALL_ERROR_DEVICE_NOT_DIALING,

    /**
     * Indicates memset failed.
     */
    CALL_ERROR_MEMSET_FAIL,

    /**
     * Indicates memcpy failed.
     */
    CALL_ERROR_MEMCPY_FAIL,

    /**
     * Indicates IPC connect stub failed.
     */
    CALL_ERROR_IPC_CONNECT_STUB_FAIL,

    /**
     * Indicates IPC write descriptor token failed.
     */
    CALL_ERROR_IPC_WRITE_DESCRIPTOR_TOKEN_FAIL = 21,

    /**
     * Indicates IPC write data failed.
     */
    CALL_ERROR_IPC_WRITE_DATA_FAIL,

    /**
     * Indicates IPC send request failed.
     */
    CALL_ERROR_IPC_SEND_REQUEST_FAIL,

    /**
     * Indicates call operation is illegal.
     */
    CALL_ERROR_ILLEGAL_CALL_OPERATION,

    /**
     * Indicates notify call state failed.
     */
    CALL_ERROR_PHONE_CALLSTATE_NOTIFY_FAILED,

    /**
     * Indicates the call already exists.
     */
    CALL_ERROR_CALL_ALREADY_EXISTS,

    /**
     * Indicates the network type is unsupported.
     */
    CALL_ERROR_UNSUPPORTED_NETWORK_TYPE,

    /**
     * Indicates create request failed.
     */
    CALL_ERROR_CREATE_REQUEST_FAIL,

    /**
     * Indicates send request failed.
     */
    CALL_ERROR_SEND_REQUEST_FAIL,

    /**
     * Indicates call object is null.
     */
    CALL_ERROR_CALL_OBJECT_IS_NULL,

    /**
     * Indicates the state of SRVCC is unexpecred.
     */
    CALL_ERROR_UNEXPECTED_SRVCC_STATE = 31,

    /**
     * Indicates the counts of call exceed limit.
     */
    CALL_ERROR_CALL_COUNTS_EXCEED_LIMIT,

    /**
     * Indicates get radio state failed.
     */
    CALL_ERROR_GET_RADIO_STATE_FAILED,

    /**
     * Indicates the resource is unavailable.
     */
    CALL_ERROR_RESOURCE_UNAVAILABLE,

    /**
     * Indicates the call connection does not exist.
     */
    CALL_ERROR_CALL_CONNECTION_NOT_EXIST,

    /**
     * Indicates the argument is invalid.
     */
    CALL_ERROR_ARGUMENT_INVALID,

    /**
     * Indicates IMS service does not exist.
     */
    CALL_ERROR_IMS_SERVICE_NOT_EXIST,

    /**
     * Indicates the radio response info is error.
     */
    CALL_ERROR_RADIO_RESPONSEINFO_ERROR,
};

/**
 * @brief Indicates the error code of SmsMms.
 */
enum class SmsMmsErrorCode {
    /**
     * Indicates the permission error.
     */
    SMS_ERROR_PERMISSION_ERROR = 100,

    /**
     * Indicates the pointer is null.
     */
    SMS_ERROR_NULL_POINTER,

    /**
     * Indicates the input parameter is empty.
     */
    SMS_ERROR_EMPTY_INPUT_PARAMETER,

    /**
     * Indicates the network type is unknown.
     */
    SMS_ERROR_UNKNOWN_NETWORK_TYPE,

    /**
     * Indicates the PDU encoding failed.
     */
    SMS_ERROR_PDU_ENCODEING_FAIL,

    /**
     * Indicates the message segment exceed the limit.
     */
    SMS_ERROR_EXCEED_MAX_SEGMENT_NUM,

    /**
     * Indicates send sms when device is not in service.
     */
    SMS_ERROR_SENDSMS_NOT_IN_SERVICE,

    /**
     * Indicates unsupport SMS capability.
     */
    SMS_ERROR_SMS_CAPABLE_UNSUPPORTED,

    /**
     * Indicates add message to database failed.
     */
    SMS_ERROR_ADD_TO_DATABASE_FAIL,

    /**
     * Indicates the message repeated.
     */
    SMS_ERROR_REPEATED_ERROR,

    /**
     * Indicates publish common event failed.
     */
    SMS_ERROR_PUBLISH_COMMON_EVENT_FAIL,

    /**
     * Indicates decode PDU failed.
     */
    SMS_ERROR_PDU_DECODE_FAIL,

    /**
     * Indicates publish cell broadcast event failed.
     */
    SMS_ERROR_CELL_BROADCAST_PUD_ANALYSIS_FAIL,

    /**
     * Indicates create request failed.
     */
    SMS_ERROR_CREATE_REQUEST_FAIL,

    /**
     * Indicates send request failed.
     */
    SMS_ERROR_SEND_REQUEST_FAIL,

    /**
     * Indicates read message failed.
     */
    SMS_ERROR_MESSAGE_READ_FAIL,

    /**
     * Indicates the time of sms broadcast out of range.
     */
    SMS_ERROR_BROADCAST_TIME_OUT,

    /**
     * Indicates the SMS address is blocked.
     */
    SMS_ERROR_ADDRESS_BLOCKED,
};

/**
 * @brief Indicates the error code of cellular data.
 */
enum class CellularDataErrorCode {
    /**
     * Indicates permission error.
     */
    DATA_ERROR_PERMISSION_ERROR = 200,

    /**
     * Indicates write database failed.
     */
    DATA_ERROR_DATABASE_WRITE_ERROR,

    /**
     * Indicates the PS is not registered .
     */
    DATA_ERROR_PS_NOT_ATTACH,

    /**
     * Indicates the SIM is not ready.
     */
    DATA_ERROR_SIM_NOT_READY,

    /**
     * Indicates the solt try to establish data connection is not the default data cellular slot.
     */
    DATA_ERROR_CELLULAR_DATA_SLOT_ID_MISMATCH,

    /**
     * Indicates the data roaming switch is OFF but current PS is roaming.
     */
    DATA_ERROR_ROAMING_SWITCH_OFF_AND_ROAMING,

    /**
     * Indicates call and data is not concurrency.
     */
    DATA_ERROR_CALL_AND_DATA_NOT_CONCURRENCY,

    /**
     * Indicates there is higher priority connection.
     */
    DATA_ERROR_HAS_HIGHER_PRIORITY_CONNECTION,

    /**
     * Indicates activate PDP context failed.
     */
    DATA_ERROR_PDP_ACTIVATE_FAIL,

    /**
     * Indicates deactive PDP context failed.
     */
    DATA_ERROR_PDP_DEACTIVATE_FAIL,

    /**
     * Indicates active PDP context overtime.
     */
    DATA_ERROR_DATA_ACTIVATE_TIME_OUT,

    /**
     * Indicates radio response info error.
     */
    DATA_ERROR_RADIO_RESPONSEINFO_ERROR,
};

class TelephonyHiSysEvent {
public:
    template<typename... Types>
    static void HiWriteBehaviorEvent(const std::string &eventName, Types... args)
    {
        HiSysEventWrite(DOMAIN_NAME, eventName, EventType::BEHAVIOR, args...);
    }

    template<typename... Types>
    static void HiWriteFaultEvent(const std::string &eventName, Types... args)
    {
        HiSysEventWrite(DOMAIN_NAME, eventName, EventType::FAULT, args...);
    }
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_HISYSEVENT_H
