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

#ifndef RADIO_NETWORK_MANAGER_H
#define RADIO_NETWORK_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>
#include "i_core_service.h"
#include "iremote_object.h"
#include "refbase.h"

namespace OHOS {
namespace Telephony {
class RadioNetworkManager {
public:
    static int32_t GetPsRadioTech(int32_t slotId);
    static int32_t GetCsRadioTech(int32_t slotId);
    static std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId);
    static std::u16string GetOperatorNumeric(int32_t slotId);
    static std::u16string GetOperatorName(int32_t slotId);
    static sptr<NetworkState> GetNetworkState(int32_t slotId);
    static bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    static bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback);
    static bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    static bool SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback);
    static bool GetRadioState(const sptr<INetworkSearchCallback> &callback);
    static std::u16string GetIsoCountryCodeForNetwork(int32_t slotId);
    static bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    static bool SetPreferredNetwork(
        int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback);
    static bool SendUpdateCellLocationRequest();
    static std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId);
    static std::u16string GetImei(int32_t slotId);
};
} // namespace Telephony
} // namespace OHOS
#endif // RADIO_NETWORK_MANAGER_H
