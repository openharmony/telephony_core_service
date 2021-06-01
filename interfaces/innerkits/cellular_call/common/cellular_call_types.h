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

#include "call_types.h"

namespace OHOS {
namespace CellularCall {
enum ErrorCode {
    ERR_PARAMETER_INVALID = 0x02 + 1, // parameter error or invalid
    ERR_CALL_STATE, // call state error
    ERR_RADIO_STATE, // Radio state error
    ERR_FDN_TYPE, // FDN type
    ERR_MMI_TYPE, // include：Supplementary Service、USSD
    ERR_SYSTEM_INVOKE, // Error calling standard system library function
    ERR_CONNECTION, // Connection is null
    ERR_RIL_MANAGER, // ril manager is nullptr
    ERR_GET_RADIO_STATE, // radio state error
    ERR_REPORT_CALLS_INFO, // report calls info error
    ERR_NETWORK_TYPE, // Network type error
};
/**************************common**********************************/

/***********************down event**********************************/
struct CellularCallInfo {
    int32_t callId; // uuid
    char phoneNum[kMaxNumberLen]; // call phone number
    int32_t slotId; // del
    int32_t accountId;
    PhoneNetType phoneNetType; // 1: gsm  2: cdma
    CallType callType; // call type: CS、IMS
    int32_t videoState; // 0: audio 1:video
};

/*************************up event********************************/
struct CellularCallReportInfo {
    char phoneNum[kMaxNumberLen]; // call phone number
    int32_t phoneId;
    CallType callType; // call type: CS、IMS
    VedioStateType callMode; // call mode: video or audio
    TelCallStates state;
};

struct CellularCSCallResponseInfo {
    std::vector<CellularCallReportInfo> callVec;
    int32_t slotId;
};
} // namespace CellularCall
} // namespace OHOS

#endif // CELLULAR_CALL_CELLULAR_CALL_TYPES_H
