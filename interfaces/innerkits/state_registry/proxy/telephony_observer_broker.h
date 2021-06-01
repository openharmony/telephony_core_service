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

#ifndef TELEPHONY_OBSERVER_BROKER_H
#define TELEPHONY_OBSERVER_BROKER_H

#include "iremote_broker.h"

#include "network_state.h"
#include "signal_information.h"

namespace OHOS {
namespace TelephonyState {
class TelephonyObserverBroker : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.base.telephony.TelephonyObserverBroker");
    enum {
        ON_CALL_STATE_UPDATED = 0,
        ON_SIGNAL_INFO_UPDATED,
        ON_NETWORK_STATE_UPDATED
    };

    virtual void OnCallStateUpdated(int32_t callState, const std::u16string &phoneNumber) = 0;
    virtual void OnSignalInfoUpdated(const std::vector<sptr<SignalInformation>> &vec) = 0;
    virtual void OnNetworkStateUpdated(const sptr<NetworkState> &networkState) = 0;

public:
    static const uint32_t OBSERVER_MASK_NETWORK_STATE = 0x00000001;
    static const uint32_t OBSERVER_MASK_CALL_STATE = 0x00000004;
    static const uint32_t OBSERVER_MASK_SIGNAL_STRENGTHS = 0x00000016;
};
} // namespace TelephonyState
} // namespace OHOS
#endif // TELEPHONY_OBSERVER_BROKER_H