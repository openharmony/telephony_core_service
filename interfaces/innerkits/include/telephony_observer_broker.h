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
#include "cell_information.h"
#include "network_state.h"
#include "signal_information.h"
#include "sim_state_type.h"

namespace OHOS {
namespace Telephony {
class TelephonyObserverBroker : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.TelephonyObserverBroker");

    enum class ObserverBrokerCode {
        ON_CALL_STATE_UPDATED = 0,
        ON_SIGNAL_INFO_UPDATED,
        ON_NETWORK_STATE_UPDATED,
        ON_CELL_INFO_UPDATED,
        ON_SIM_STATE_UPDATED,
        ON_CELLULAR_DATA_CONNECT_STATE_UPDATED,
        ON_CELLULAR_DATA_FLOW_UPDATED,
        ON_CFU_INDICATOR_UPDATED,
        ON_VOICE_MAIL_MSG_INDICATOR_UPDATED,
    };

    virtual void OnCellularDataConnectStateUpdated(
        int32_t slotId, int32_t dataState, int32_t networkType) = 0;
    virtual void OnCallStateUpdated(
        int32_t slotId, int32_t callState, const std::u16string &phoneNumber) = 0;
    virtual void OnSignalInfoUpdated(
        int32_t slotId, const std::vector<sptr<SignalInformation>> &vec) = 0;
    virtual void OnNetworkStateUpdated(
        int32_t slotId, const sptr<NetworkState> &networkState) = 0;
    virtual void OnCellInfoUpdated(
        int32_t slotId, const std::vector<sptr<CellInformation>> &vec) = 0;
    virtual void OnSimStateUpdated(
        int32_t slotId, CardType type, SimState state, LockReason reason) = 0;
    virtual void OnCellularDataFlowUpdated(
        int32_t slotId, int32_t dataFlowType) = 0;
    virtual void OnCfuIndicatorUpdated(int32_t slotId, bool cfuResult) = 0;
    virtual void OnVoiceMailMsgIndicatorUpdated(int32_t slotId, bool voiceMailMsgResult) = 0;

public:
    static const uint32_t OBSERVER_MASK_NETWORK_STATE = 0x00000001;
    static const uint32_t OBSERVER_MASK_CALL_STATE = 0x00000004;
    static const uint32_t OBSERVER_MASK_CELL_INFO = 0x00000008;
    static const uint32_t OBSERVER_MASK_SIGNAL_STRENGTHS = 0x00000010;
    static const uint32_t OBSERVER_MASK_SIM_STATE = 0x00000020;
    static const uint32_t OBSERVER_MASK_DATA_CONNECTION_STATE = 0x00000040;
    static const uint32_t OBSERVER_MASK_DATA_FLOW = 0x00000080;
    static const uint32_t OBSERVER_MASK_CFU_INDICATOR = 0x00000100;
    static const uint32_t OBSERVER_MASK_VOICE_MAIL_MSG_INDICATOR = 0x00000200;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_OBSERVER_BROKER_H