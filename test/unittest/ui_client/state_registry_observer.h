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

#ifndef STATE_REGISTRY_OBSERVER_H
#define STATE_REGISTRY_OBSERVER_H

#include "string_ex.h"
#include "telephony_log_wrapper.h"
#include "telephony_observer.h"

namespace OHOS {
namespace Telephony {
class StateRegistryObserver : public Telephony::TelephonyObserver {
public:
    StateRegistryObserver() = default;
    ~StateRegistryObserver() = default;

    void OnCallStateUpdated(int32_t slotId, int32_t callState, const std::u16string &phoneNumber)
    {
        TELEPHONY_LOGI(
            "StateRegistryObserver%{public}d::OnCallStateUpdated callState is %{public}d", slotId, callState);
    }

    void OnSignalInfoUpdated(int32_t slotId, const std::vector<sptr<SignalInformation>> &vec)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnSignalInfoUpdated", slotId);
    }

    void OnSignalInfoUpdatedExt(int32_t slotId, const std::vector<sptr<SignalInformation>> &vec)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnSignalInfoUpdatedExt", slotId);
    }

    void OnNetworkStateUpdated(int32_t slotId, const sptr<NetworkState> &networkState)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnNetworkStateUpdated", slotId);
    }

    void OnNetworkStateUpdatedExt(int32_t slotId, const sptr<NetworkState> &networkState)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnNetworkStateUpdatedExt", slotId);
    }

    void OnCellInfoUpdated(int32_t slotId, const std::vector<sptr<CellInformation>> &vec)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnCellInfoUpdated", slotId);
    }

    void OnCellInfoUpdatedExt(int32_t slotId, const std::vector<sptr<CellInformation>> &vec)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnCellInfoUpdatedExt", slotId);
    }

    void OnSimStateUpdated(int32_t slotId, CardType type, SimState state, LockReason reason)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnSimStateUpdated state is %{public}d", slotId, state);
    }

    void OnCellularDataConnectStateUpdated(int32_t slotId, int32_t dataState, int32_t networkType)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnCellularDataConnectStateUpdated dataState is %{public}d",
            slotId, dataState);
    }

    void OnCellularDataFlowUpdated(int32_t slotId, int32_t dataFlowType)
    {
        TELEPHONY_LOGI("StateRegistryObserver%{public}d::OnCellularDataFlowUpdated dataFlowType is %{public}d", slotId,
            dataFlowType);
    }

    void OnCfuIndicatorUpdated(int32_t slotId, bool cfuResult)
    {
        TELEPHONY_LOGI(
            "StateRegistryObserver%{public}d::OnCfuIndicatorUpdated cfuResult is %{public}d", slotId, cfuResult);
    }

    void OnVoiceMailMsgIndicatorUpdated(int32_t slotId, bool voiceMailMsgResult)
    {
        TELEPHONY_LOGI(
            "StateRegistryObserver%{public}d::OnVoiceMailMsgIndicatorUpdated voiceMailMsgResult is %{public}d", slotId,
            voiceMailMsgResult);
    }

    void OnIccAccountUpdated()
    {
        TELEPHONY_LOGI("StateRegistryObserver::OnIccAccountUpdated");
    }
};
} // namespace Telephony
} // namespace OHOS
#endif // STATE_REGISTRY_OBSERVER_H