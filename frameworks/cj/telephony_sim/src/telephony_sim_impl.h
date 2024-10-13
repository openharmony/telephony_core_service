/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef TELEPHONY_SIM_IMPL_H
#define TELEPHONY_SIM_IMPL_H

#include "sim_state_type.h"
#include "telephony_napi_common_error.h"
#include "telephony_sim_utils.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {

class TelephonySimImpl {
public:
    static bool IsSimActive(int32_t slotId, int32_t &errCode);
    static int32_t getDefaultVoiceSlotId();
    static bool hasOperatorPrivileges(int32_t slotId, int32_t &errCode);
    static char* getISOCountryCodeForSim(int32_t slotId, int32_t &errCode);
    static char* getSimOperatorNumeric(int32_t slotId, int32_t &errCode);
    static char* getSimSpn(int32_t slotId, int32_t &errCode);
    static int32_t getSimState(int32_t slotId, int32_t &errCode);
    static int32_t getCardType(int32_t slotId, int32_t &errCode);
    static bool hasSimCard(int32_t slotId, int32_t &errCode);
    static CIccAccountInfo getSimAccountInfo(int32_t slotId, int32_t &errCode);
    static CArryIccAccountInfo getActiveSimAccountInfoList(int32_t &errCode);
    static int32_t getMaxSimCount();
    static char* getOpKey(int32_t slotId, int32_t &errCode);
    static char* getOpName(int32_t slotId, int32_t &errCode);
    static int32_t getDefaultVoiceSimId(int32_t &errCode);
};
}
}

#endif