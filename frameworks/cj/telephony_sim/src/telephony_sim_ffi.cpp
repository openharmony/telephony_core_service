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

#include "telephony_sim_ffi.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Telephony {
extern "C" {

    bool FfiTelephonySimIsSimActive(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::IsSimActive(slotId, *errCode);
    }

    int32_t FfiTelephonySimGetDefaultVoiceSlotId()
    {
        return TelephonySimImpl::getDefaultVoiceSlotId();
    }

    bool FfiTelephonySimHasOperatorPrivileges(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::hasOperatorPrivileges(slotId, *errCode);
    }

    char* FfiTelephonySimGetISOCountryCodeForSim(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::getISOCountryCodeForSim(slotId, *errCode);
    }

    char* FfiTelephonySimGetSimOperatorNumeric(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::getSimOperatorNumeric(slotId, *errCode);
    }

    char* FfiTelephonySimGetSimSpn(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::getSimSpn(slotId, *errCode);
    }

    int32_t FfiTelephonySimGetSimState(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::getSimState(slotId, *errCode);
    }

    int32_t FfiTelephonySimGetCardType(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::getCardType(slotId, *errCode);
    }

    bool FfiTelephonySimHasSimCard(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::hasSimCard(slotId, *errCode);
    }

    CIccAccountInfo FfiTelephonySimGetSimAccountInfo(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::getSimAccountInfo(slotId, *errCode);
    }

    CArryIccAccountInfo FfiTelephonySimGetActiveSimAccountInfoList(int32_t *errCode)
    {
        return TelephonySimImpl::getActiveSimAccountInfoList(*errCode);
    }

    int32_t FfiTelephonySimGetMaxSimCount()
    {
        return TelephonySimImpl::getMaxSimCount();
    }

    char* FfiTelephonySimGetOpKey(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::getOpKey(slotId, *errCode);
    }

    char* FfiTelephonySimGetOpName(int32_t slotId, int32_t *errCode)
    {
        return TelephonySimImpl::getOpName(slotId, *errCode);
    }

    int32_t FfiTelephonySimGetDefaultVoiceSimId(int32_t *errCode)
    {
        return TelephonySimImpl::getDefaultVoiceSimId(*errCode);
    }
}
}  // namespace Telephony
}  // namespace OHOS
