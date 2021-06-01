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
namespace TelephonyState {
class TelephonyStateRegistryProxy : public IRemoteProxy<ITelephonyStateNotify> {
public:
    /**
     * TelephonyStateRegistryProxy
     *
     * @param impl
     */
    explicit TelephonyStateRegistryProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<ITelephonyStateNotify>(impl)
    {}

    virtual ~TelephonyStateRegistryProxy() = default;

    int32_t UpdateCallState(int32_t callStatus, const std::u16string &number);
    int32_t UpdateCallStateForSlotIndex(
        int32_t simId, int32_t slotIndex, int32_t callStatus, const std::u16string &number);
    int32_t UpdateSignalInfo(int32_t simId, int32_t slotIndex, const std::vector<sptr<SignalInformation>> &vec);
    int32_t UpdateNetworkState(int32_t simId, int32_t slotIndex, const sptr<NetworkState> &networkState);
    int32_t RegisterStateChange(const sptr<TelephonyObserverBroker> &telephonyObserver, int32_t simId,
        uint32_t mask, const std::u16string &package, bool isUpdate);
    int32_t UnregisterStateChange(int32_t simId, uint32_t mask);

private:
    static inline BrokerDelegator<TelephonyStateRegistryProxy> delegator_;
};
} // namespace TelephonyState
} // namespace OHOS
#endif // TELEPHONY_STATE_REGISTRY_PROXY_H
