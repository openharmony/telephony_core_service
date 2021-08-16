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

#ifndef CELLULAR_CALL_INTERFACE_H
#define CELLULAR_CALL_INTERFACE_H

#include "cellular_call_types.h"
#include "i_call_status_callback.h"

namespace OHOS {
namespace Telephony {
class CellularCallInterface : public IRemoteBroker {
public:
    // operation type
    enum {
        DIAL = 1,
        END = 2,
        REJECT = 3,
        ANSWER = 4,
        HOLD = 5,
        ACTIVE = 6,
        SWAP = 7,
        URGENT_CALL = 8,
        JOIN = 9,
        SPLIT = 10,
        INITIATE_DTMF = 11,
        CEASE_DTMF = 12,
        TRANSMIT_DTMF = 13,
        TRANSMIT_DTMF_STRING = 14,
        SET_CALL_TRANSFER = 15,
        INQUIRE_CALL_TRANSFER = 16,
        SET_CALL_WAITING = 17,
        INQUIRE_CALL_WAITING = 18,
        SET_CALL_RESTRICTION = 19,
        INQUIRE_CALL_RESTRICTION = 20,
        REGISTER_CALLBACK = 21,
        UNREGISTER_CALLBACK = 22,
        CALL_SUPPLEMENT = 23,
    };

    /**
     * Call management dial interface
     *
     * @param CellularCall, dial param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int Dial(const CellularCallInfo &callInfo) = 0;

    /**
     * End.
     *
     * @param CallInfo, End param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int End(const CellularCallInfo &callInfo) = 0;

    /**
     * Answer.
     *
     * @param CallInfo, Answer param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int Answer(const CellularCallInfo &callInfo) = 0;

    /**
     * Reject.
     *
     * @param CallInfo, Reject param.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int Reject(const CellularCallInfo &callInfo) = 0;

    /**
     * Hold.
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int Hold() = 0;

    /**
     * Active.
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int Active() = 0;

    /**
     * Swap.
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int Swap() = 0;

    /**
     * IsUrgentCall.
     *
     * @param phone number.
     * @param slotId.
     * @param errorCode.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int IsUrgentCall(const std::string &phoneNum, int32_t slotId, int32_t &errorCode) = 0;

    /**
     * Merge into multiple calls
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int Join() = 0;

    /**
     * Split.
     *
     * @param std::string splitString
     * @param index
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int Split(const std::string &splitString, int32_t index) = 0;

    /**
     * CallSupplement.
     *
     * @param CallSupplementType
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int CallSupplement(CallSupplementType type) = 0;

    /**
     * InitiateDTMF.
     *
     * @param DTMF Code.
     * @param phoneNum.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int InitiateDTMF(char cDTMFCode, const std::string &phoneNum) = 0;

    /**
     * CeaseDTMF.
     *
     * @param phoneNum.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int CeaseDTMF(const std::string &phoneNum) = 0;

    /**
     * TransmitDTMF.
     *
     * @param DTMF Code.
     * @param phoneNum.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int TransmitDTMF(char cDTMFCode, const std::string &phoneNum) = 0;

    /**
     * Send DTMF String.
     * @param DTMF Code string.
     * @param phoneNum.
     * @param switchOn.
     * @param switchOff.
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t TransmitDTMFString(
        const std::string &dtmfCodeStr, const std::string &phoneNum, int32_t switchOn, int32_t switchOff) = 0;

    /**
     * Set Call Transfer
     * @param CallTransferInfo
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetCallTransfer(const CallTransferInfo &ctInfo, int32_t slotId) = 0;

    /**
     * Inquire Call Transfer
     * @param CallTransferType
     * @param slotId
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t InquireCallTransfer(CallTransferType type, int32_t slotId) = 0;

    /**
     * Set Call Waiting
     * @param activate
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetCallWaiting(bool activate, int32_t slotId) = 0;

    /**
     * Inquire Call Waiting
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t InquireCallWaiting(int32_t slotId) = 0;

    /**
     * Set Call Restriction
     * @param CallRestrictionInfo
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t SetCallRestriction(const CallRestrictionInfo &cRInfo, int32_t slotId) = 0;

    /**
     * Inquire Call Restriction
     * @param CallRestrictionType
     * @return Returns kTelephonyNoErr on success, others on failure.
     */
    virtual int32_t InquireCallRestriction(CallRestrictionType facType, int32_t slotId) = 0;

    /**
     * Register CallBack
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback) = 0;

    /**
     * UnRegister CallBack
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int UnRegisterCallManagerCallBack() = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.CellularCallInterface");
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_INTERFACE_H
