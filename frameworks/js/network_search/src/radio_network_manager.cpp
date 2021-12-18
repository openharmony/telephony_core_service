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

#include "radio_network_manager.h"
#include "network_search_service_proxy_holder.h"
#include "singleton.h"

namespace OHOS {
namespace Telephony {
int32_t RadioNetworkManager::GetPsRadioTech(int32_t slotId)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetPsRadioTech(slotId);
}

int32_t RadioNetworkManager::GetCsRadioTech(int32_t slotId)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetCsRadioTech(slotId);
}

std::vector<sptr<SignalInformation>> RadioNetworkManager::GetSignalInfoList(int32_t slotId)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetSignalInfoList(slotId);
}

std::u16string RadioNetworkManager::GetOperatorNumeric(int32_t slotId)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetOperatorNumeric(slotId);
}

std::u16string RadioNetworkManager::GetOperatorName(int32_t slotId)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetOperatorName(slotId);
}

sptr<NetworkState> RadioNetworkManager::GetNetworkState(int32_t slotId)
{
    return sptr<NetworkState>(
        DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetNetworkState(slotId));
}

bool RadioNetworkManager::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetNetworkSelectionMode(
        slotId, callback);
}

bool RadioNetworkManager::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->SetNetworkSelectionMode(
        slotId, selectMode, networkInformation, resumeSelection, callback);
}

bool RadioNetworkManager::SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->SetRadioState(isOn, callback);
}

bool RadioNetworkManager::GetRadioState(const sptr<INetworkSearchCallback> &callback)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetRadioState(callback);
}

bool RadioNetworkManager::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetNetworkSearchInformation(
        slotId, callback);
}

std::u16string RadioNetworkManager::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetIsoCountryCodeForNetwork(slotId);
}

bool RadioNetworkManager::GetPreferredNetworkMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->GetPreferredNetworkMode(
        slotId, callback);
}

bool RadioNetworkManager::SetPreferredNetworkMode(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    return DelayedSingleton<NetworkSearchServiceProxyHolder>::GetInstance()->SetPreferredNetworkMode(
        slotId, networkMode, callback);
}

bool RadioNetworkManager::SendUpdateCellLocationRequest()
{
    return false;
}
} // namespace Telephony
} // namespace OHOS
