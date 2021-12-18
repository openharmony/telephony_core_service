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

#ifndef TEL_RIL_CALL_H
#define TEL_RIL_CALL_H

#include "tel_ril_base.h"

namespace OHOS {
namespace Telephony {
class TelRilCall : public TelRilBase {
public:
    TelRilCall(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);

    ~TelRilCall() = default;

    /**
     * @brief Get current Calls
     */
    void GetCallList(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Calling Dial by UusInformation
     *
     * @param string address
     * @param int clirMode
     */
    void Dial(const std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief  Reject the Call
     */
    void Reject(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Hang up the call
     *
     *  @param : int32_t gsmIndex
     */
    void Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Answer the call
     */
    void Answer(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Hold the call
     */
    void HoldCall(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Active the call
     */
    void UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Hold and active the call
     */
    void SwitchCall(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Keep all other calls except the callIndex call;
     *  @param : int32_t callIndex
     *  @param : int32_t callType
     */
    void SeparateConference(int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief CombineConference the call
     *  @param : int32_t callIndex
     *  @param : int32_t callType
     */
    void CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Call Supplement
     *  @param : int32_t type
     */
    void CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    void GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    void SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    void GetCallTransferInfo(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    void SetCallTransferInfo(int32_t reason, int32_t mode, std::string number, int32_t classx,
        const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    void GetClip(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    void SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    void GetClir(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    void SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    void GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    void SetCallRestriction(
        std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result);

    void SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result);
    void SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    void StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    void StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Call Status Change response
     *
     * @param data is HDF service callback message
     */
    void CallStateUpdated(MessageParcel &data);

    /**
     * @brief Answering a call response
     *
     * @param data is HDF service callback message
     */
    void AnswerResponse(MessageParcel &data);

    /**
     * @brief Get current call information
     *
     * @param data is HDF service callback message
     */
    void GetCallListResponse(MessageParcel &data);

    /**
     * @brief Initiate call response
     *
     * @param data is HDF service callback message
     */
    void DialResponse(MessageParcel &data);

    /**
     * @brief Hang up response
     *
     * @param data is HDF service callback message
     */
    void HangupResponse(MessageParcel &data);

    /**
     * @brief Reject call response
     *
     * @param data is HDF service callback message
     */
    void RejectResponse(MessageParcel &data);

    /**
     * @brief Hold the call response
     *
     * @param data is HDF service callback message
     */
    void HoldCallResponse(MessageParcel &data);

    /**
     * @brief Active the call response
     *
     * @param data is HDF service callback message
     */
    void UnHoldCallResponse(MessageParcel &data);

    /**
     * @brief Holding and active the call response
     *
     * @param data is HDF service callback message
     */
    void SwitchCallResponse(MessageParcel &data);

    /**
     * @brief join the call response
     *
     * @param data is HDF service callback message
     */
    void CombineConferenceResponse(MessageParcel &data);

    /**
     * @brief split the call response
     *
     * @param data is HDF service callback message
     */
    void SeparateConferenceResponse(MessageParcel &data);

    /**
     * @brief call supplement response
     *
     * @param data is HDF service callback message
     */
    void CallSupplementResponse(MessageParcel &data);

    /**
     * @brief get call wait response
     *
     * @param data is HDF service callback message
     */
    void GetCallWaitingResponse(MessageParcel &data);

    /**
     * @brief set call forward response
     *
     * @param data is HDF service callback message
     */
    void SetCallTransferInfoResponse(MessageParcel &data);

    /**
     * @brief get call forward response
     *
     * @param data is HDF service callback message
     */
    void GetCallTransferInfoResponse(MessageParcel &data);

    /**
     * @brief set call forward response
     *
     * @param data is HDF service callback message
     */
    void GetClipResponse(MessageParcel &data);

    /**
     * @brief get call forward response
     *
     * @param data is HDF service callback message
     */
    void SetClipResponse(MessageParcel &data);

    /**
     * @brief set call forward response
     *
     * @param data is HDF service callback message
     */
    void GetClirResponse(MessageParcel &data);

    /**
     * @brief get call forward response
     *
     * @param data is HDF service callback message
     */
    void SetClirResponse(MessageParcel &data);

    /**
     * @brief set call forward response
     *
     * @param data is HDF service callback message
     */
    void GetCallRestrictionResponse(MessageParcel &data);

    /**
     * @brief get call forward response
     *
     * @param data is HDF service callback message
     */
    void SetCallRestrictionResponse(MessageParcel &data);

    /**
     * @brief set call wait response
     *
     * @param data is HDF service callback message
     */
    void SetCallWaitingResponse(MessageParcel &data);

    void SendDtmfResponse(MessageParcel &data);

    void StartDtmfResponse(MessageParcel &data);

    void StopDtmfResponse(MessageParcel &data);

    bool IsCallRespOrNotify(uint32_t code);

    void ProcessCallRespOrNotify(uint32_t code, MessageParcel &data);

    /**
     *  @brief get Ims call list
     */
    void GetImsCallList(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get Ims call list response
     *
     * @param data is HDF service callback message
     */
    void GetImsCallListResponse(MessageParcel &data);

    /**
     *  @brief set voice call preference mode
     */
    void SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief set voice call preference mode
     *
     * @param data is HDF service callback message
     */
    void SetCallPreferenceResponse(MessageParcel &data);

  /**
     *  @brief get voice call preference mode
     */
    void GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get voice call preference mode
     *
     * @param data is HDF service callback message
     */
    void GetCallPreferenceResponse(MessageParcel &data);

       /**
     *  @brief set IMS service capability switch
     */
    void SetLteImsSwitchStatus(const int32_t active, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief set IMS service capability switch
     *
     * @param data is HDF service callback message
     */
    void SetLteImsSwitchStatusResponse(MessageParcel &data);

  /**
     *  @brief get IMS service capability switch
     */
    void GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get IMS service capability switch
     *
     * @param data is HDF service callback message
     */
    void GetLteImsSwitchStatusResponse(MessageParcel &data);

    /**
     * @brief call cring notice
     *
     * @param data is HDF service callback message
     */
    void CallCringNotice(MessageParcel &data);

        /**
     * @brief call waiti notice
     *
     * @param data is HDF service callback message
     */
    void CallWaitingNotice(MessageParcel &data);

        /**
     * @brief call connect notice
     *
     * @param data is HDF service callback message
     */
    void CallConnectNotice(MessageParcel &data);

        /**
     * @brief call end notice
     *
     * @param data is HDF service callback message
     */
    void CallEndNotice(MessageParcel &data);

            /**
     * @brief call status info notice
     *
     * @param data is HDF service callback message
     */
    void CallStatusInfoNotice(MessageParcel &data);

            /**
     * @brief call Ims service status notice
     *
     * @param data is HDF service callback message
     */
    void CallImsServiceStatusNotice(MessageParcel &data);

private:
    bool IsCallResponse(uint32_t code);
    bool IsCallNotification(uint32_t code);
    void AddHandlerToMap();

private:
    using Func = void (TelRilCall::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_CALL_H
