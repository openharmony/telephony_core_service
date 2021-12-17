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

#ifndef CALL_MANAGER_INNER_TYPE_H
#define CALL_MANAGER_INNER_TYPE_H

#include <cstdio>
#include <string>
#include <vector>
#include <ctime>

namespace OHOS {
namespace Telephony {
const int kMaxNumberLen = 30;
const uint32_t REJECT_CALL_MSG_MAX_LEN = 300;
constexpr uint32_t MAX_CALL_COUNT = 15;
constexpr uint32_t ACCOUNT_NUMBER_MAX_LENGTH = 100;
constexpr uint32_t CONNECT_SERVICE_WAIT_TIME = 1000; // ms
constexpr int32_t ERR_ID = -1;

// call type
enum CallType {
    TYPE_CS = 0, // CS
    TYPE_IMS = 1, // IMS
    TYPE_OTT = 2, // OTT
    TYPE_ERR_CALL = 3, // OTHER
};

// call state
enum TelCallState {
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

enum TelConferenceState {
    TEL_CONFERENCE_IDLE = 0,
    TEL_CONFERENCE_ACTIVE,
    TEL_CONFERENCE_DISCONNECTING,
    TEL_CONFERENCE_DISCONNECTED,
};

// phone type
enum PhoneNetType {
    PHONE_TYPE_GSM = 1, // gsm
    PHONE_TYPE_CDMA = 2, // cdma
};

// call mode
enum VideoStateType {
    TYPE_VOICE = 0, // Voice
    TYPE_VIDEO, // Video
};

enum DialScene {
    CALL_NORMAL = 0,
    CALL_PRIVILEGED,
    CALL_EMERGENCY,
};

enum CallDirection {
    CALL_DIRECTION_OUT = 0,
    CALL_DIRECTION_IN,
    CALL_DIRECTION_UNKNOW,
};

enum class CallRunningState {
    CALL_RUNNING_STATE_CREATE = 0, // A new session
    CALL_RUNNING_STATE_CONNECTING,
    CALL_RUNNING_STATE_DIALING,
    CALL_RUNNING_STATE_RINGING,
    CALL_RUNNING_STATE_ACTIVE,
    CALL_RUNNING_STATE_HOLD,
    CALL_RUNNING_STATE_ENDED,
    CALL_RUNNING_STATE_ENDING,
};

enum class CallEndedType {
    UNKNOWN = 0,
    PHONE_IS_BUSY,
    INVALID_NUMBER,
    CALL_ENDED_NORMALLY,
};

struct SIMCardInfo {
    int32_t simId; // IccId
    int32_t country;
    int32_t state; // SIM card active status
    PhoneNetType phoneNetType;
};

enum class DialType {
    DIAL_CARRIER_TYPE = 0,
    DIAL_VOICE_MAIL_TYPE,
    DIAL_OTT_TYPE,
};

enum class CallStateToApp {
    /**
     * Indicates an invalid state, which is used when the call state fails to be obtained.
     */
    CALL_STATE_UNKNOWN = -1,

    /**
     * Indicates that there is no ongoing call.
     */
    CALL_STATE_IDLE = 0,

    /**
     * Indicates that an incoming call is ringing or waiting.
     */
    CALL_STATE_RINGING = 1,

    /**
     * Indicates that a least one call is in the dialing, active, or hold state, and there is no new incoming call
     * ringing or waiting.
     */
    CALL_STATE_OFFHOOK = 2
};

enum CallAnswerType {
    CALL_ANSWER_MISSED = 0,
    CALL_ANSWER_ACTIVED,
    CALL_ANSWER_REJECT,
};

struct CallAttributeInfo {
    char accountNumber[kMaxNumberLen];
    bool speakerphoneOn;
    int32_t accountId;
    VideoStateType videoState;
    int64_t startTime; // Call start time
    bool isEcc;
    CallType callType;
    int32_t callId;
    TelCallState callState;
    TelConferenceState conferenceState;
    time_t callBeginTime;
    time_t callEndTime;
    time_t ringBeginTime;
    time_t ringEndTime;
    CallDirection callDirection;
    CallAnswerType answerType;
};

struct CallRecordInfo {
    int32_t callId;
    char phoneNumber[kMaxNumberLen];
    CallType callType;
    time_t callBeginTime;
    time_t callEndTime;
    uint32_t ringDuration;
    uint32_t callDuration;
    CallDirection directionType;
    CallAnswerType answerType;
    int32_t countryCode;
};

enum CallAbilityEventId {
    EVENT_UNKNOW_ID = 0,
    EVENT_DIAL_AT_CMD_SEND_FAILED,
    EVENT_DIAL_NO_CARRIER,
    EVENT_HOLD_SEND_FAILED,
    EVENT_ACTIVE_SEND_FAILED,
    EVENT_START_DTMF_SUCCESS,
    EVENT_START_DTMF_FAILED,
    EVENT_STOP_DTMF_SUCCESS,
    EVENT_STOP_DTMF_FAILED,
    EVENT_SEND_DTMF_SUCCESS,
    EVENT_SEND_DTMF_FAILED,
    EVENT_SEND_DTMF_STRING_SUCCESS,
    EVENT_SEND_DTMF_STRING_FAILED,
    EVENT_DISCONNECTED_UNKNOW,
    EVENT_SET_CALL_PREFERENCE_MODE_SUCCESS,
    EVENT_SET_CALL_PREFERENCE_MODE_FAILED,
    EVENT_SET_IMS_VOLTE_SUCCESS,
    EVENT_SET_IMS_VOLTE_FAILED,
    EVENT_GET_IMS_DATA_FAILED,
};

struct CallEventInfo {
    CallAbilityEventId eventId;
};

struct AccountInfo {
    int32_t accountId;
    int32_t power;
    char bundleName[kMaxNumberLen];
    bool isEnabled;
};

struct CallReportInfo {
    int32_t index;
    char accountNum[kMaxNumberLen]; // call phone number
    int32_t accountId;
    CallType callType; // call type: CS、IMS
    VideoStateType callMode; // call mode: video or audio
    TelCallState state; // call state
    int32_t voiceDomain; // 0:CS、1:IMS
};

struct CallsReportInfo {
    std::vector<CallReportInfo> callVec;
    int32_t slotId;
};

enum class DisconnectedDetails : int32_t {
    UNKNOWN = 0,
};

enum AudioDevice {
    DEVICE_EARPIECE = 0,
    DEVICE_SPEAKER,
    DEVICE_WIRED_HEADSET,
    DEVICE_BLUETOOTH_SCO,
    DEVICE_DISABLE,
    DEVICE_UNKNOWN,
};

enum CellularCallEventType {
    EVENT_REQUEST_RESULT_TYPE = 0,
};

enum RequestResultEventId {
    RESULT_DIAL_SEND_FAILED = 0,
    RESULT_DIAL_NO_CARRIER = 1,
    RESULT_END_SEND_FAILED = 2,
    RESULT_REJECT_SEND_FAILED = 3,
    RESULT_ACCEPT_SEND_FAILED = 4,
    RESULT_HOLD_SEND_FAILED = 5,
    RESULT_ACTIVE_SEND_FAILED = 6,
    RESULT_SWAP_SEND_FAILED = 7,
    RESULT_JOIN_SEND_FAILED = 8,
    RESULT_SPLIT_SEND_FAILED = 9,
    RESULT_SUPPLEMENT_SEND_FAILED = 10,

    RESULT_INITIATE_DTMF_SUCCESS = 11,
    RESULT_INITIATE_DTMF_FAILED = 12,
    RESULT_CEASE_DTMF_SUCCESS = 13,
    RESULT_CEASE_DTMF_FAILED = 14,
    RESULT_TRANSMIT_DTMF_SUCCESS = 15,
    RESULT_TRANSMIT_DTMF_FAILED = 16,
    RESULT_TRANSMIT_DTMF_STRING_SUCCESS = 17,
    RESULT_TRANSMIT_DTMF_STRING_FAILED = 18,

    RESULT_GET_CURRENT_CALLS_FAILED = 19,

    RESULT_SET_CALL_PREFERENCE_MODE_SUCCESS = 20,
    RESULT_SET_CALL_PREFERENCE_MODE_FAILED = 21,
    RESULT_SET_LTE_IMS_SWITCH_STATUS_SUCCESS = 22,
    RESULT_SET_LTE_IMS_SWITCH_STATUS_FAILED = 23,
    RESULT_GET_IMS_CALLS_DATA_FAILED = 24,

    RESULT_GET_CALL_WAITING_SUCCESS = 25,
    RESULT_GET_CALL_WAITING_FAILED = 26,
    RESULT_SET_CALL_WAITING_SUCCESS = 27,
    RESULT_SET_CALL_WAITING_FAILED = 28,
    RESULT_GET_CALL_RESTRICTION_SUCCESS = 29,
    RESULT_GET_CALL_RESTRICTION_FAILED = 30,
    RESULT_SET_CALL_RESTRICTION_SUCCESS = 31,
    RESULT_SET_CALL_RESTRICTION_FAILED = 32,
    RESULT_GET_CALL_TRANSFER_SUCCESS = 33,
    RESULT_GET_CALL_TRANSFER_FAILED = 34,
    RESULT_SET_CALL_TRANSFER_SUCCESS = 35,
    RESULT_SET_CALL_TRANSFER_FAILED = 36,
};

enum CallResultReportId {
    GET_CALL_WAITING_REPORT_ID = 0,
    SET_CALL_WAITING_REPORT_ID,
    GET_CALL_RESTRICTION_REPORT_ID,
    SET_CALL_RESTRICTION_REPORT_ID,
    GET_CALL_TRANSFER_REPORT_ID,
    SET_CALL_TRANSFER_REPORT_ID,
    GET_CALL_CLIP_ID,
    GET_CALL_CLIR_ID,
    SET_CALL_CLIR_ID,
    GET_CALL_VOTLE_REPORT_ID,
    SET_CALL_VOTLE_REPORT_ID,
};

struct CellularCallEventInfo {
    CellularCallEventType eventType;
    RequestResultEventId eventId;
};

struct CallWaitResponse {
    int32_t result; // 0: ok  other: error
    int32_t status;
    int32_t classCw;
};

struct ClipResponse {
    int32_t result; // 0: ok  other: error
    int32_t action;
    int32_t clipStat;
};

struct ClirResponse {
    int32_t result; // 0: ok  other: error
    int32_t action;
    int32_t clirStat;
};

struct CallTransferResponse {
    int32_t result; // 0: ok  other: error
    int32_t status;
    int32_t classx;
    std::string number;
    int32_t type;
};

struct CallRestrictionResponse {
    int32_t result; // 0: ok  other: error
    int32_t status; // parameter sets/shows the result code presentation status in the TA
    int32_t classCw; // parameter shows the subscriber CLIP service status in the network, <0-4>
};

struct CallPreferenceResponse {
    int32_t result; // 0: ok  other: error
    /*
     * 1：CS Voice only
     * 2：CS Voice preferred, IMS PS Voice as secondary
     * 3：IMS PS Voice preferred, CS Voice as secondary
     * 4：IMS PS Voice only
     */
    int32_t mode;
};

struct LteImsSwitchResponse {
    int32_t result; // 0: ok  other: error
    int32_t active; // 0: off 1: on
};

enum DtmfPlaytime {
    DTMF_PLAY_TONE_MSEC_0 = 0, // stop play
    DTMF_PLAY_TONE_MSEC_1 = 1,
    DTMF_PLAY_TONE_MSEC_2 = 95, // Play time, the length is milliseconds
    DTMF_PLAY_TONE_MSEC_3 = 150,
    DTMF_PLAY_TONE_MSEC_4 = 200,
    DTMF_PLAY_TONE_MSEC_5 = 250,
    DTMF_PLAY_TONE_MSEC_6 = 300,
    DTMF_PLAY_TONE_MSEC_7 = 350,
    DTMF_PLAY_TONE_DEFAULT_MSEC = 60000, // default play time
};

enum DtmfPlayIntervalTime {
    DTMF_PLAY_TONE_MIN_INTERVAL_MSEC = 10, // Play interval time, the length is milliseconds
    DTMF_PLAY_TONE_MAX_INTERVAL_MSEC = 60000,
    DTMF_PLAY_TONE_DEFAULT_INTERVAL_MSEC = 0, // Default parameter
};

/**
 * 27007-430_2001 7.11	Call forwarding number and conditions +CCFC
 * 3GPP TS 22.082 [4]
 * <mode>:
 * 0	disable
 * 1	enable
 * 3	registration
 * 4	erasure
 */
enum CallTransferSettingType {
    CALL_TRANSFER_DISABLE = 0,
    CALL_TRANSFER_ENABLE = 1,
    CALL_TRANSFER_REGISTRATION = 3,
    CALL_TRANSFER_ERASURE = 4,
};

/**
 * 27007-430_2001 7.11	Call forwarding number and conditions +CCFC
 * 3GPP TS 22.082 [4]
 * <reason>:
 * 0	unconditional
 * 1	mobile busy
 * 2	no reply
 * 3	not reachable
 */
enum CallTransferType {
    TRANSFER_TYPE_UNCONDITIONAL = 0,
    TRANSFER_TYPE_BUSY = 1,
    TRANSFER_TYPE_NO_REPLY = 2,
    TRANSFER_TYPE_NOT_REACHABLE = 3,
};

struct CallTransferInfo {
    CallTransferSettingType settingType;
    CallTransferType type;
    char transferNum[kMaxNumberLen];
};

struct VideoWindow {
    int32_t x;
    int32_t y;
    int32_t z;
    int32_t width;
    int32_t height;
};

// 3GPP TS 22.030 V4.0.0 (2001-03)
// 3GPP TS 22.088 V4.0.0 (2001-03)
enum CallRestrictionType {
    RESTRICTION_TYPE_ALL_INCOMING = 0,
    RESTRICTION_TYPE_ALL_OUTGOING,
    RESTRICTION_TYPE_INTERNATIONAL,
    RESTRICTION_TYPE_INTERNATIONAL_EXCLUDING_HOME,
    RESTRICTION_TYPE_ROAMING_INCOMING,
    RESTRICTION_TYPE_ALL_CALLS,
    RESTRICTION_TYPE_OUTGOING_SERVICES,
    RESTRICTION_TYPE_INCOMING_SERVICES,
};

// 3GPP TS 22.088 V4.0.0 (2001-03)
enum CallRestrictionMode {
    RESTRICTION_MODE_DEACTIVATION = 0,
    RESTRICTION_MODE_ACTIVATION = 1,
};

struct CallRestrictionInfo {
    CallRestrictionType fac;
    CallRestrictionMode mode;
    char password[kMaxNumberLen];
};

// 3GPP TS 27.007 V3.9.0 (2001-06) Call related supplementary services +CHLD
// 3GPP TS 27.007 V3.9.0 (2001-06) 7.22	Informative examples
enum CallSupplementType {
    TYPE_DEFAULT = 0, // default type
    TYPE_HANG_UP_HOLD_WAIT = 1, // release the held call and the wait call
    TYPE_HANG_UP_ACTIVE = 2, // release the active call and recover the held call
    TYPE_HANG_UP_ALL = 3, // release all calls
};

enum CellularCallReturnType {
    // 3GPP TS 27.007 V3.9.0 (2001-06) 6.27	Informative examples
    RETURN_TYPE_MMI = 0,
};
} // namespace Telephony
} // namespace OHOS
#endif // CALL_MANAGER_INNER_TYPE_H
