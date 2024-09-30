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

#ifndef TELEPHONY_SIM_FFI_H
#define TELEPHONY_SIM_FFI_H

#include "ffi_remote_data.h"
#include "telephony_sim_impl.h"

namespace OHOS {
namespace Telephony {
extern "C" {
    FFI_EXPORT bool FfiTelephonySimIsSimActive(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonySimGetDefaultVoiceSlotId();
    FFI_EXPORT bool FfiTelephonySimHasOperatorPrivileges(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonySimGetISOCountryCodeForSim(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonySimGetSimOperatorNumeric(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonySimGetSimSpn(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonySimGetSimState(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonySimGetCardType(int32_t slotId, int32_t *errCode);
    FFI_EXPORT bool FfiTelephonySimHasSimCard(int32_t slotId, int32_t *errCode);
    FFI_EXPORT CIccAccountInfo FfiTelephonySimGetSimAccountInfo(int32_t slotId, int32_t *errCode);
    FFI_EXPORT CArryIccAccountInfo FfiTelephonySimGetActiveSimAccountInfoList(int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonySimGetMaxSimCount();
    FFI_EXPORT char* FfiTelephonySimGetOpKey(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonySimGetOpName(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonySimGetDefaultVoiceSimId(int32_t *errCode);
}
}
}

#endif