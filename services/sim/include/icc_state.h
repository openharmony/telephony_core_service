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

#ifndef OHOS_ICC_STATE_H
#define OHOS_ICC_STATE_H

#include <iostream>

namespace OHOS {
namespace Telephony {
// matched to HRilSimState
const int ICC_CONTENT_UNKNOWN = -1;
const int ICC_CARD_ABSENT = 0;
const int ICC_CONTENT_READY = 1;
const int ICC_CONTENT_PIN = 2;
const int ICC_CONTENT_PUK = 3;
const int ICC_CONTENT_PIN2 = 4;
const int ICC_CONTENT_PUK2 = 5;
const int ICC_CONTENT_PH_NET_PIN = 6;
const int ICC_CONTENT_PH_NET_PUK = 7;
const int ICC_CONTENT_PH_NET_SUB_PIN = 8;
const int ICC_CONTENT_PH_NET_SUB_PUK = 9;
const int ICC_CONTENT_PH_SP_PIN = 10;
const int ICC_CONTENT_PH_SP_PUK = 11;

const int CONTENT_INDEX_INVALID = -1;
const int ICC_CONTENT_NUM = 0;
const int PIN_SUBSTITUE_FALSE = 0;
const int PIN_SUBSTITUE_TRUE = 1;

const int ICC_PIN_STATE_UNKNOWN = 0;
const int ICC_PIN_NOT_VERIFIED = 1;
const int ICC_PIN_VERIFIED = 2;
const int ICC_PIN_DISABLED = 3;
const int ICC_PIN_BLOCKED_ENABLED = 4;
const int ICC_PIN_BLOCKED_PERM = 5;

const int ICC_UNKNOWN_TYPE = 0;
const int ICC_SIM_TYPE = 1;
const int ICC_USIM_TYPE = 2;
const int ICC_RUIM_TYPE = 4;
const int ICC_CG_TYPE = 5;
const int ICC_DUAL_MODE_ROAMING_TYPE = 7;
const int ICC_UNICOM_DUAL_MODE_TYPE = 8;
const int ICC_4G_LTE_TYPE = 9;
const int ICC_UG_TYPE = 10;
const int ICC_IMS_TYPE = 11;

const int ICC_SIMLOCK_UNKNOWN = 0;
const int ICC_SIMLOCK_IN_PROGRESS = 1;
const int ICC_SIMLOCK_READY = 2;

class IccContent {
public:
    IccContent();
    ~IccContent() {}

public:
    int32_t simLockSubState_;
    int32_t substitueOfPin1_;
    int32_t stateOfPin1_;
    int32_t stateOfPin2_;
};

// icc state
class IccState {
public:
    IccState();
    ~IccState() {}

public:
    int32_t simType_ = 0;
    int32_t simStatus_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ICC_STATE_H
