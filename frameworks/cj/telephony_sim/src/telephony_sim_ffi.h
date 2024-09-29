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
    FFI_EXPORT int32_t FfiTelephonyGetDefaultVoiceSlotId();
    FFI_EXPORT bool FfiTelephonyHasOperatorPrivileges(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonyGetISOCountryCodeForSim(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonyGetSimOperatorNumeric(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonyGetSimSpn(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonyGetSimState(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonyGetCardType(int32_t slotId, int32_t *errCode);
    FFI_EXPORT bool FfiTelephonyHasSimCard(int32_t slotId, int32_t *errCode);
    FFI_EXPORT CIccAccountInfo FfiTelephonyGetSimAccountInfo(int32_t slotId, int32_t *errCode);
    FFI_EXPORT CArryIccAccountInfo FfiTelephonyGetActiveSimAccountInfoList(int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonyGetMaxSimCount();
    FFI_EXPORT char* FfiTelephonyGetOpKey(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonyGetOpName(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonyGetDefaultVoiceSimId(int32_t *errCode);
}
}
}

#endif