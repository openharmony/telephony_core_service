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

#ifndef OHOS_I_TELEPHONY_STATE_NOTIFY_H
#define OHOS_I_TELEPHONY_STATE_NOTIFY_H

#include "telephony_observer_broker.h"

namespace OHOS {
namespace Telephony {
class ITelephonyStateNotify : public IRemoteBroker {
public:
    enum class StateNotifyCode {
        CELL_INFO = 0,
        CELLULAR_DATA_STATE,
        CELLULAR_DATA_FLOW,
        SIGNAL_INFO,
        NET_WORK_STATE,
        CALL_STATE,
        CALL_STATE_FOR_ID,
        SIM_STATE,
        ADD_OBSERVER,
        REMOVE_OBSERVER
    };

    /**
     * UpdateCellularDataConnectState
     *
     * @param slotId sim slot id
     * @param dataState cellular data link state
     * @param networkState network state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UpdateCellularDataConnectState(
        int32_t slotId, int32_t dataState, int32_t networkState) = 0;
    /**
     * UpdateCellularDataFlow
     *
     * @param slotId sim slot id
     * @param dataFlowType cellular data flow state
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UpdateCellularDataFlow(
        int32_t slotId, int32_t dataFlowType) = 0;

    /**
     * UpdateSimState
     *
     * @param slotId sim slot id
     * @param CardType sim card type
     * @param state sim state
     * @param reason
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UpdateSimState(
        int32_t slotId, CardType type, SimState state, LockReason reason) = 0;
    /**
     * UpdateCallState
     *
     * @param slotId sim slot id
     * @param callStatus call status
     * @param number call number
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UpdateCallState(
        int32_t slotId, int32_t callStatus, const std::u16string &number) = 0;

    /**
     * UpdateCallStateForSlotId
     *
     * @param slotId sim slot id
     * @param callId call id
     * @param callStatus call status
     * @param number incoming number
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UpdateCallStateForSlotId(
        int32_t slotId, int32_t callId, int32_t callStatus, const std::u16string &incomingNumber) = 0;

    /**
     * UpdateSignalInfo
     *
     * @param slotId sim slot id
     * @param vec networkType search signal information
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UpdateSignalInfo(
        int32_t slotId, const std::vector<sptr<SignalInformation>> &vec) = 0;

    /**
      * UpdateCellInfo
      *
      * @param slotId sim slot id
      * @param vec cell info
      * @return int32_t TELEPHONY_NO_ERROR on success, others on failure.
      */
    virtual int32_t UpdateCellInfo(
        int32_t slotId, const std::vector<sptr<CellInformation>> &vec) = 0;

    /**
     * UpdateNetworkState
     *
     * @param slotId sim slot id
     * @param networkStatus network status
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UpdateNetworkState(
        int32_t slotId, const sptr<NetworkState> &networkState) = 0;

    /**
     * RegisterStateChange
     *
     * @param telephonyObserver api callback
     * @param slotId sim slot id
     * @param mask  listening type bitmask
     * @param isUpdate Whether to update immediately
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t RegisterStateChange(const sptr<TelephonyObserverBroker> &telephonyObserver,
        int32_t slotId, uint32_t mask, bool isUpdate) = 0;

    /**
     * UnregisterStateChange
     *
     * @param slotId sim slot id
     * @param mask listening type bitmask
     * @return int32_t TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UnregisterStateChange(int32_t slotId, uint32_t mask) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ITelephonyStateNotify");
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_I_TELEPHONY_STATE_NOTIFY_H
