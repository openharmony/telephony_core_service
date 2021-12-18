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

#ifndef NETWORK_SEARCH_SERVICE_PROXY_HOLDER_H
#define NETWORK_SEARCH_SERVICE_PROXY_HOLDER_H

#include <string>
#include <vector>
#include <mutex>
#include "i_core_service.h"
#include "iremote_object.h"
#include "refbase.h"
#include "signal_information.h"
#include "network_search_result.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchServiceProxyHolder {
public:
    int32_t GetPsRadioTech(int32_t slotId);
    int32_t GetCsRadioTech(int32_t slotId);
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId);
    std::u16string GetOperatorNumeric(int32_t slotId);
    std::u16string GetOperatorName(int32_t slotId);
    sptr<NetworkState> GetNetworkState(int32_t slotId);
    bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback);
    bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback);
    bool GetRadioState(const sptr<INetworkSearchCallback> &callback);
    std::u16string GetIsoCountryCodeForNetwork(int32_t slotId);
    bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    bool SetPreferredNetwork(int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback);
    bool GetImsRegStatus(int32_t slotId);
    bool SendUpdateCellLocationRequest();
    bool InitNetworkSearchProxy();
    void ResetServiceProxy();
    std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId);
    std::u16string GetImei(int32_t slotId);

private:
    std::mutex mutex_;
    sptr<ICoreService> radioNetworkService_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> recipient_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_PROXY_HOLDER_H