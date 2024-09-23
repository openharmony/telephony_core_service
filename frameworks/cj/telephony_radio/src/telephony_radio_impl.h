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
#ifndef TELEPHONY_RADIO_IMPL_H
#define TELEPHONY_RADIO_IMPL_H

#include "telephony_radio_utils.h"

#include "network_state.h"
#include "signal_information.h"
#include "telephony_napi_common_error.h"
#include "telephony_radio_callback.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {

class TelephonyRadioImpl {
public:
    static CNetworkRadioTech GetRadioTech(int32_t slotId, int32_t &errCode);
    static CNetworkState GetNetworkState(int32_t slotId, int32_t &errCode);
    static int32_t GetNetworkSelectionMode(int32_t slotId, int32_t &errCode);
    static char* GetISOCountryCodeForNetwork(int32_t slotId, int32_t &errCode);
    static int32_t GetPrimarySlotId(int32_t &errCode);
    static CArraySignalInformation GetSignalInfoList(int32_t slotId, int32_t &errCode);
    static bool IsNRSupported();
    static bool IsRadioOn(int32_t slotId, int32_t &errCode);
    static char* GetOperatorName(int32_t slotId, int32_t &errCode);
};
}
}

#endif