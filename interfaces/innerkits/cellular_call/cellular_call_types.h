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
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_CELLULAR_CALL_TYPES_H
