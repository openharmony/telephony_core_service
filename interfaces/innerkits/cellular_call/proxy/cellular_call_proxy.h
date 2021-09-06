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

#ifndef CELLULAR_CALL_PROXY_H
#define CELLULAR_CALL_PROXY_H

#include "cellular_call_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Telephony {
class CellularCallProxy : public IRemoteProxy<CellularCallInterface> {
public:
    /**
     * CellularCallProxy
     *
     * @param impl
     */
    explicit CellularCallProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<CellularCallInterface>(impl) {}

    ~CellularCallProxy() = default;

    /**
     * Call management dial interface
     *
     * @param CellularCallInfo, dial param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int Dial(const CellularCallInfo &callInfo) override;

    /**
     * End.
     *
     * @param CellularCallInfo, End param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int End(const CellularCallInfo &callInfo) override;

    /**
     * Reject.
     *
     * @param CellularCallInfo, Reject param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int Reject(const CellularCallInfo &callInfo) override;

    /**
     * Answer.
     *
     * @param CellularCallInfo, Answer param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int Answer(const CellularCallInfo &callInfo) override;

    /**
     * Hold.
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int Hold() override;

    /**
     * Active.
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int Active() override;

    /**
     * Swap.
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int Swap() override;

    /**
     * IsUrgentCall.
     *
     * @param phone number.
     * @param slotId.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int IsUrgentCall(const std::string &phoneNum, int32_t slotId, int32_t &errorCode) override;

    /**
     * Merge into multiple calls
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int Join() override;

    /**
     * Split.
     *
     * @param std::string splitString
     * @param index
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int Split(const std::string &splitString, int32_t index) override;

    /**
     * CallSupplement.
     *
     * @param CallSupplementType type
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int CallSupplement(CallSupplementType type) override;

    /**
     * InitiateDTMF.
     *
     * @param DTMF Code.
     * @param phoneNum.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int InitiateDTMF(char cDTMFCode, const std::string &phoneNum) override;

    /**
     * CeaseDTMF.
     *
     * @param phoneNum.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int CeaseDTMF(const std::string &phoneNum) override;

    /**
     * TransmitDTMF.
     *
     * @param DTMF Code.
     * @param phoneNum.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int TransmitDTMF(char cDTMFCode, const std::string &phoneNum) override;

    /**
     * Send DTMF String.
     * @param DTMF Code string.
     * @param phoneNum.
     * @param switchOn.
     * @param switchOff.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t TransmitDTMFString(
        const std::string &dtmfCodeStr, const std::string &phoneNum, int32_t switchOn, int32_t switchOff) override;

    /**
     * Set Call Transfer
     * @param CallTransferInfo
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallTransfer(const CallTransferInfo &cfInfo, int32_t slotId) override;

    /**
     * Inquire Call Transfer
     * @param CallTransferType
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t InquireCallTransfer(CallTransferType type, int32_t slotId) override;

    /**
     * Set Call Waiting
     * @param activate
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallWaiting(bool activate, int32_t slotId) override;

    /**
     * Inquire Call Waiting
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t InquireCallWaiting(int32_t slotId) override;

    /**
     * Set Call Restriction
     * @param CallRestrictionInfo
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t SetCallRestriction(const CallRestrictionInfo &crInfo, int32_t slotId) override;

    /**
     * Inquire Call Restriction
     * @param CallRestrictionType
     * @param slot Id
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    int32_t InquireCallRestriction(CallRestrictionType facType, int32_t slotId) override;

    /**
     * RegisterCallManagerCallBack
     * @param sptr<ICallStatusCallback>
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback) override;

    /**
     * UnRegister CallManager CallBack
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int UnRegisterCallManagerCallBack() override;

private:
    static inline BrokerDelegator<CellularCallProxy> delegator_;
    const int32_t DATA_SIZE = 10;
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_PROXY_H
