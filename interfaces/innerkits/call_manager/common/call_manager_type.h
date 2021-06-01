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

#ifndef CALL_MANAGER_TYPE_H
#define CALL_MANAGER_TYPE_H
#include <cstdio>

#include "call_types.h"

namespace OHOS {
namespace TelephonyCallManager {
const int kMaxSchemeNumberLen = 4;

enum DialScene {
    CALL_NORMAL = 0,
    CALL_PRIVILEGED,
    CALL_EMERGENCY,
};

enum class CallStateType {
    CALL_STATE_CREATE_TYPE = 0, // A new session
    CALL_STATE_CONNECTING_TYPE,
    CALL_STATE_DIALING_TYPE,
    CALL_STATE_RINGING_TYPE,
    CALL_STATE_ACTIVE_TYPE,
    CALL_STATE_HOLD_TYPE,
    CALL_STATE_ENDED_TYPE,
    CALL_STATE_ENDING_TYPE,
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

struct AccountInfo {
    int32_t slotId;
    int32_t power;
    char bundleName[kMaxNumberLen];
    bool isEnabled;
};

struct CellularCallReportInfo {
    char phoneNum[kMaxNumberLen]; // call phone number
    int32_t phoneId;
    CallType callType; // call type: CS、IMS
    VedioStateType callMode; // call mode: video or audio
    TelCallStates state;
};

struct CallReportInfo {
    char accountNum[kMaxNumberLen]; // call phone number
    int32_t accountId;
    CallType callType; // call type: CS、IMS
    VedioStateType callMode; // call mode: video or audio
    TelCallStates state;
};

struct CallsReportInfo {
    std::vector<CallReportInfo> callVec;
    int32_t slotId;
};

enum class DisconnectedDetails {
    UNKNOWN = 0,
};
} // namespace TelephonyCallManager
} // namespace OHOS
#endif // CALL_MANAGER_TYPE_H