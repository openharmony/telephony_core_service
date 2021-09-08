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

#ifndef CELLULAR_CALL_CELLULAR_CALL_TYPES_H
#define CELLULAR_CALL_CELLULAR_CALL_TYPES_H

#include <map>
#include "call_manager_errors.h"
#include "call_manager_inner_type.h"

namespace OHOS {
namespace Telephony {
const int32_t MAX_SIZE = 10;

/***********************down event**********************************/
struct CellularCallInfo {
    int32_t callId; // uuid
    char phoneNum[kMaxNumberLen]; // call phone number
    int32_t slotId; // del
    int32_t accountId;
    CallType callType; // call type: CS、IMS
    int32_t videoState; // 0: audio 1:video
    int32_t index; // CallInfo index
};

/**
 * 27007-430_2001 7.11	Call forwarding number and conditions +CCFC
 * 3GPP TS 22.082 [4]
 * <mode>:
 * 0	disable
 * 1	enable
 * 2	query status
 * 3	registration
 * 4	erasure
 */
enum CallTransferSettingType {
    DISABLE = 0,
    ENABLE = 1,
    QUERY_STATUS = 2,
    REGISTRATION = 3,
    ERASURE = 4,
};

/**
 * 27007-430_2001 7.11	Call forwarding number and conditions +CCFC
 * 3GPP TS 22.082 [4]
 * <reason>:
 * 0	unconditional
 * 1	mobile busy
 * 2	no reply
 * 3	not reachable
 * 4	all call forwarding (refer 3GPP TS 22.030 [19])
 * 5	all conditional call forwarding (refer 3GPP TS 22.030 [19])
 */
enum CallTransferType {
    UNCONDITIONAL = 0,
    MOBILE_BUSY = 1,
    NO_REPLY = 2,
    NOT_REACHABLE = 3,
};

struct CallTransferInfo {
    CallTransferSettingType settingType;
    CallTransferType type;
    char transferNum[kMaxNumberLen];
};

// 3GPP TS 22.030 V4.0.0 (2001-03)
// 3GPP TS 22.088 V4.0.0 (2001-03)
enum CallRestrictionType {
    RESTRICTION_TYPE_ALL_OUTGOING = 0,
    RESTRICTION_TYPE_INTERNATIONAL = 1,
    RESTRICTION_TYPE_INTERNATIONAL_EXCLUDING_HOME = 2,
    RESTRICTION_TYPE_ALL_INCOMING = 3,
    RESTRICTION_TYPE_ROAMING_INCOMING = 4,
};

// 3GPP TS 22.088 V4.0.0 (2001-03)
enum CallRestrictionMode {
    RESTRICTION_MODE_DEACTIVATION = 0,
    RESTRICTION_MODE_ACTIVATION = 1,
    RESTRICTION_MODE_QUERY = 2,
};

struct CallRestrictionInfo {
    CallRestrictionType fac;
    CallRestrictionMode mode;
    char password[kMaxNumberLen];
};

// 3GPP TS 27.007 V3.9.0 (2001-06) Call related supplementary services +CHLD
// 3GPP TS 27.007 V3.9.0 (2001-06) 7.22	Informative examples
enum CallSupplementType {
    TYPE_HANG_UP_HOLD_WAIT = 0, // release the held call and the wait call
    TYPE_HANG_UP_ACTIVE = 1, // release the active call and recover the held call
    TYPE_HANG_UP_ALL = 2, // release all calls
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_CELLULAR_CALL_TYPES_H
