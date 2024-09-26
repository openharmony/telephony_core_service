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

#ifndef TELEPHONY_RADIO_FFI_H
#define TELEPHONY_RADIO_FFI_H

#include "ffi_remote_data.h"
#include "telephony_radio_impl.h"
#include "telephony_radio_utils.h"

namespace OHOS {
namespace Telephony {
extern "C" {
    FFI_EXPORT CNetworkRadioTech FfiTelephonyRadioGetRadioTech(int32_t slotId, int32_t *errCode);
    FFI_EXPORT CNetworkState FfiTelephonyRadioGetNetworkState(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonyRadioGetNetworkSelectionMode(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonyRadioGetISOCountryCodeForNetwork(int32_t slotId, int32_t *errCode);
    FFI_EXPORT int32_t FfiTelephonyRadioGetPrimarySlotId(int32_t *errCode);
    FFI_EXPORT CArraySignalInformation FfiTelephonyRadioGetSignalInfoList(int32_t slotId, int32_t *errCode);
    FFI_EXPORT bool FfiTelephonyRadioIsNRSupported();
    FFI_EXPORT bool FfiTelephonyRadioIsRadioOn(int32_t slotId, int32_t *errCode);
    FFI_EXPORT char* FfiTelephonyRadioGetOperatorName(int32_t slotId, int32_t *errCode);
}
}
}

#endif