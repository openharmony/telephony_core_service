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

#ifndef TELEPHONY_STATE_REGISTRY_PROXY_H
#define TELEPHONY_STATE_REGISTRY_PROXY_H

#include "iremote_proxy.h"

#include "i_telephony_state_notify.h"

namespace OHOS {
namespace Telephony {
class TelephonyStateRegistryProxy : public IRemoteProxy<ITelephonyStateNotify> {
public:
    explicit TelephonyStateRegistryProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<ITelephonyStateNotify>(impl)
    {}

    virtual ~TelephonyStateRegistryProxy() = default;

    int32_t UpdateCellularDataConnectState(
        int32_t slotId, int32_t dataState, int32_t networkState) override;
    int32_t UpdateCellularDataFlow(
        int32_t slotId, int32_t dataFlowType) override;
    int32_t UpdateCallState(
        int32_t slotId, int32_t callStatus, const std::u16string &number) override;
    int32_t UpdateCallStateForSlotId(
        int32_t slotId, int32_t callId, int32_t callStatus, const std::u16string &number) override;
    int32_t UpdateSignalInfo(
        int32_t slotId, const std::vector<sptr<SignalInformation>> &vec) override;
    int32_t UpdateCellInfo(
        int32_t slotId, const std::vector<sptr<CellInformation>> &vec) override;
    int32_t UpdateNetworkState(
        int32_t slotId, const sptr<NetworkState> &networkState) override;
    int32_t UpdateSimState(
        int32_t slotId, CardType type, SimState state, LockReason reason) override;
    int32_t UpdateCfuIndicator(int32_t slotId, bool cfuResult) override;
    int32_t UpdateVoiceMailMsgIndicator(int32_t slotId, bool voiceMailMsgResult) override;

    int32_t RegisterStateChange(const sptr<TelephonyObserverBroker> &telephonyObserver,
        int32_t slotId, uint32_t mask, bool isUpdate) override;
    int32_t UnregisterStateChange(int32_t slotId, uint32_t mask) override;

private:
    static inline BrokerDelegator<TelephonyStateRegistryProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_STATE_REGISTRY_PROXY_H
