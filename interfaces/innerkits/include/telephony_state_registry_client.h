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

#ifndef TELEPHONY_STATE_REGISTRY_CLIENT_H
#define TELEPHONY_STATE_REGISTRY_CLIENT_H

#include <cstdint>
#include <iremote_object.h>
#include <singleton.h>

#include "i_telephony_state_notify.h"

namespace OHOS {
namespace Telephony {
class TelephonyStateRegistryClient : public DelayedRefSingleton<TelephonyStateRegistryClient> {
    DECLARE_DELAYED_REF_SINGLETON(TelephonyStateRegistryClient);

public:
    /**
     * @brief Update cellular data connect state
     *
     * @param slotId sim slot id
     * @param dataState cellular data link state
     * @param networkState network state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateCellularDataConnectState(int32_t slotId, int32_t dataState, int32_t networkState);
    /**
     * @brief Update call state
     *
     * @param slotId sim slot id
     * @param callStatus call status
     * @param number call number
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateCallState(int32_t slotId, int32_t callStatus, const std::u16string &number);
    /**
     * @brief Update call state for slotId
     *
     * @param slotId sim slot id
     * @param callId call id
     * @param callStatus call status
     * @param number incoming number
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateCallStateForSlotId(
        int32_t slotId, int32_t callId, int32_t callStatus, const std::u16string &number);
    /**
     * @brief Update signal information
     *
     * @param slotId sim slot id
     * @param vec networkType search signal information
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateSignalInfo(int32_t slotId, const std::vector<sptr<SignalInformation>> &vec);
    /**
     * @brief Update cell information
     *
     * @param slotId sim slot id
     * @param vec cell info
     * @return int32_t TELEPHONY_NO_ERROR on success, others on failure.
     */
    int32_t UpdateCellInfo(int32_t slotId, const std::vector<sptr<CellInformation>> &vec);
    /**
     * @brief Update network state
     *
     * @param slotId sim slot id
     * @param networkStatus network status
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateNetworkState(int32_t slotId, const sptr<NetworkState> &networkState);
    /**
     * @brief Update sim state
     *
     * @param slotId sim slot id
     * @param CardType sim card type
     * @param state sim state
     * @param reason Indicates the reason of update sim state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateSimState(int32_t slotId, CardType type, SimState state, LockReason reason);
    /**
     * @brief Update cellular data flow
     *
     * @param slotId sim slot id
     * @param dataFlowType cellular data flow state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateCellularDataFlow(int32_t slotId, int32_t flowType);
    /**
     * @brief Update call forward unconditionally indicator
     *
     * @param slotId sim slot id
     * @param cfuResult set the result of call forwarding
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateCfuIndicator(int32_t slotId, bool cfuResult);
    /**
     * @brief Update voice mail message indicator
     *
     * @param slotId sim slot id
     * @param voiceMailMsgResult voice mail message indicator
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t UpdateVoiceMailMsgIndicator(int32_t slotId, bool voiceMailMsgResult);
    int32_t UpdateIccAccount();
    sptr<ITelephonyStateNotify> GetProxy();

private:
    class StateRegistryDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit StateRegistryDeathRecipient(TelephonyStateRegistryClient &client) : client_(client) {}
        ~StateRegistryDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        TelephonyStateRegistryClient &client_;
    };

    void OnRemoteDied(const wptr<IRemoteObject> &remote);

private:
    std::mutex mutexProxy_;
    sptr<ITelephonyStateNotify> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_STATE_REGISTRY_CLIENT_H
