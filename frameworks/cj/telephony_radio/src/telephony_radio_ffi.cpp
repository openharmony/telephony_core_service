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

#include "telephony_radio_ffi.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Telephony {
extern "C" {

    CNetworkRadioTech FfiOHOSTelephonyRadioGetRadioTech(int32_t slotId, int32_t *errCode)
    {
        return TelephonyRadioImpl::GetRadioTech(slotId, *errCode);
    }

    CNetworkState FfiOHOSTelephonyRadioGetNetworkState(int32_t slotId, int32_t *errCode)
    {
        return TelephonyRadioImpl::GetNetworkState(slotId, *errCode);
    }

    int32_t FfiOHOSTelephonyRadioGetNetworkSelectionMode(int32_t slotId, int32_t *errCode)
    {
        return TelephonyRadioImpl::GetNetworkSelectionMode(slotId, *errCode);
    }

    char* FfiOHOSTelephonyRadioGetISOCountryCodeForNetwork(int32_t slotId, int32_t *errCode)
    {
        return TelephonyRadioImpl::GetISOCountryCodeForNetwork(slotId, *errCode);
    }

    int32_t FfiOHOSTelephonyRadioGetPrimarySlotId(int32_t *errCode)
    {
        return TelephonyRadioImpl::GetPrimarySlotId(*errCode);
    }

    CArraySignalInformation FfiOHOSTelephonyRadioGetSignalInfoList(int32_t slotId, int32_t *errCode)
    {
        return TelephonyRadioImpl::GetSignalInfoList(slotId, *errCode);
    }

    bool FfiOHOSTelephonyRadioIsNRSupported()
    {
        return TelephonyRadioImpl::IsNRSupported();
    }

    bool FfiOHOSTelephonyRadioIsRadioOn(int32_t slotId, int32_t *errCode)
    {
        return TelephonyRadioImpl::IsRadioOn(slotId, *errCode);
    }

    char* FfiOHOSTelephonyGetOperatorName(int32_t slotId, int32_t *errCode)
    {
        return TelephonyRadioImpl::GetOperatorName(slotId, *errCode);
    }
}
}  // namespace Telephony
}  // namespace OHOS
