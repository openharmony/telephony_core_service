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
    TelRilCall(int32_t slotId, sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);

    ~TelRilCall() = default;

    /**
     * @brief Get current Calls
     */
    int32_t GetCallList(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Calling Dial by UusInformation
     *
     * @param string address
     * @param int32_t clirMode
     */
    int32_t Dial(const std::string address, int32_t clirMode, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief  Reject the Call
     */
    int32_t Reject(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Hang up the call
     *
     *  @param : int32_t gsmIndex
     */
    int32_t Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Answer the call
     */
    int32_t Answer(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Hold the call
     */
    int32_t HoldCall(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Active the call
     */
    int32_t UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Hold and active the call
     */
    int32_t SwitchCall(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Keep all other calls except the callIndex call;
     *  @param : int32_t callIndex
     *  @param : int32_t callType
     */
    int32_t SeparateConference(int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief CombineConference the call
     *  @param : int32_t callIndex
     *  @param : int32_t callType
     */
    int32_t CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Call Supplement
     *  @param : int32_t type
     */
    int32_t CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    int32_t GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    int32_t SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    int32_t GetCallTransferInfo(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    int32_t SetCallTransferInfo(int32_t reason, int32_t mode, std::string number, int32_t classx,
        const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    int32_t GetClip(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    int32_t SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    int32_t GetClir(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    int32_t SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Get Call Wait
     */
    int32_t GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     *  @brief Set Call Wait
     */
    int32_t SetCallRestriction(
        std::string fac, int32_t mode, std::string password, const AppExecFwk::InnerEvent::Pointer &result);

    int32_t SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Call Status Change response
     *
     * @param data is HDF service callback message
     */
    int32_t CallStateUpdated(MessageParcel &data);

    /**
     * @brief Answering a call response
     *
     * @param data is HDF service callback message
     */
    int32_t AnswerResponse(MessageParcel &data);

    /**
     * @brief Get current call information
     *
     * @param data is HDF service callback message
     */
    int32_t GetCallListResponse(MessageParcel &data);

    /**
     * @brief Initiate call response
     *
     * @param data is HDF service callback message
     */
    int32_t DialResponse(MessageParcel &data);

    /**
     * @brief Hang up response
     *
     * @param data is HDF service callback message
     */
    int32_t HangupResponse(MessageParcel &data);

    /**
     * @brief Reject call response
     *
     * @param data is HDF service callback message
     */
    int32_t RejectResponse(MessageParcel &data);

    /**
     * @brief Hold the call response
     *
     * @param data is HDF service callback message
     */
    int32_t HoldCallResponse(MessageParcel &data);

    /**
     * @brief Active the call response
     *
     * @param data is HDF service callback message
     */
    int32_t UnHoldCallResponse(MessageParcel &data);

    /**
     * @brief Holding and active the call response
     *
     * @param data is HDF service callback message
     */
    int32_t SwitchCallResponse(MessageParcel &data);

    /**
     * @brief join the call response
     *
     * @param data is HDF service callback message
     */
    int32_t CombineConferenceResponse(MessageParcel &data);

    /**
     * @brief split the call response
     *
     * @param data is HDF service callback message
     */
    int32_t SeparateConferenceResponse(MessageParcel &data);

    /**
     * @brief call supplement response
     *
     * @param data is HDF service callback message
     */
    int32_t CallSupplementResponse(MessageParcel &data);

    /**
     * @brief get call wait response
     *
     * @param data is HDF service callback message
     */
    int32_t GetCallWaitingResponse(MessageParcel &data);

    /**
     * @brief set call forward response
     *
     * @param data is HDF service callback message
     */
    int32_t SetCallTransferInfoResponse(MessageParcel &data);

    /**
     * @brief get call forward response
     *
     * @param data is HDF service callback message
     */
    int32_t GetCallTransferInfoResponse(MessageParcel &data);

    /**
     * @brief set call forward response
     *
     * @param data is HDF service callback message
     */
    int32_t GetClipResponse(MessageParcel &data);

    /**
     * @brief get call forward response
     *
     * @param data is HDF service callback message
     */
    int32_t SetClipResponse(MessageParcel &data);

    /**
     * @brief set call forward response
     *
     * @param data is HDF service callback message
     */
    int32_t GetClirResponse(MessageParcel &data);

    /**
     * @brief get call forward response
     *
     * @param data is HDF service callback message
     */
    int32_t SetClirResponse(MessageParcel &data);

    /**
     * @brief set call forward response
     *
     * @param data is HDF service callback message
     */
    int32_t GetCallRestrictionResponse(MessageParcel &data);

    /**
     * @brief get call forward response
     *
     * @param data is HDF service callback message
     */
    int32_t SetCallRestrictionResponse(MessageParcel &data);

    /**
     * @brief set call wait response
     *
     * @param data is HDF service callback message
     */
    int32_t SetCallWaitingResponse(MessageParcel &data);

    int32_t SendDtmfResponse(MessageParcel &data);

    int32_t StartDtmfResponse(MessageParcel &data);

    int32_t StopDtmfResponse(MessageParcel &data);

    bool IsCallRespOrNotify(uint32_t code);

    /**
     *  @brief get Ims call list
     */
    int32_t GetImsCallList(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get Ims call list response
     *
     * @param data is HDF service callback message
     */
    int32_t GetImsCallListResponse(MessageParcel &data);

    /**
     *  @brief set voice call preference mode
     */
    int32_t SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief set voice call preference mode
     *
     * @param data is HDF service callback message
     */
    int32_t SetCallPreferenceResponse(MessageParcel &data);

    /**
     *  @brief get voice call preference mode
     */
    int32_t GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get voice call preference mode
     *
     * @param data is HDF service callback message
     */
    int32_t GetCallPreferenceResponse(MessageParcel &data);

    /**
     *  @brief set IMS service capability switch
     */
    int32_t SetLteImsSwitchStatus(const int32_t active, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief set IMS service capability switch
     *
     * @param data is HDF service callback message
     */
    int32_t SetLteImsSwitchStatusResponse(MessageParcel &data);

    /**
     *  @brief get IMS service capability switch
     */
    int32_t GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get IMS service capability switch
     *
     * @param data is HDF service callback message
     */
    int32_t GetLteImsSwitchStatusResponse(MessageParcel &data);

    /**
     *  @brief set ussd
     */
    int32_t SetUssd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result);
    /**
     * @brief set ussd  response
     *
     * @param data is HDF service callback message
     */
    int32_t SetUssdResponse(MessageParcel &data);
    /**
     *  @brief get ussd
     */
    int32_t GetUssd(const AppExecFwk::InnerEvent::Pointer &result);
    /**
     * @brief get ussd cusd response
     *
     * @param data is HDF service callback message
     */
    int32_t GetUssdResponse(MessageParcel &data);

    /**
     * @brief call cring notice
     *
     * @param data is HDF service callback message
     */
    int32_t CallCringNotice(MessageParcel &data);

    /**
     * @brief call wait notice
     *
     * @param data is HDF service callback message
     */
    int32_t CallWaitingNotice(MessageParcel &data);

    /**
     * @brief call connect notice
     *
     * @param data is HDF service callback message
     */
    int32_t CallConnectNotice(MessageParcel &data);

    /**
     * @brief call end notice
     *
     * @param data is HDF service callback message
     */
    int32_t CallEndNotice(MessageParcel &data);

    /**
     * @brief call status info notice
     *
     * @param data is HDF service callback message
     */
    int32_t CallStatusInfoNotice(MessageParcel &data);

    /**
     * @brief call Ims service status notice
     *
     * @param data is HDF service callback message
     */
    int32_t CallImsServiceStatusNotice(MessageParcel &data);

    /**
     * @brief call ussd notice
     *
     * @param data is HDF service callback message
     */
    int32_t CallUssdNotice(MessageParcel &data);

    /**
     *  @brief set ussd
     */
    int32_t SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief set ussd  response
     *
     * @param data is HDF service callback message
     */
    int32_t SetMuteResponse(MessageParcel &data);

    /**
     *  @brief get mute  cmut
     */
    int32_t GetMute(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get mute cmut response
     *
     * @param data is HDF service callback message
     */
    int32_t GetMuteResponse(MessageParcel &data);

    /**
     *  @brief get call list
     */
    int32_t GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get call list response
     *
     * @param data is HDF service callback message
     */
    int32_t GetEmergencyCallListResponse(MessageParcel &data);

    /**
     *  @brief get mute  cmut
     */
    int32_t GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief get mute cmut response
     *
     * @param data is HDF service callback message
     */
    int32_t GetCallFailReasonResponse(MessageParcel &data);

    /**
     * @brief report of ringback voice
     *
     * @param data is HDF service callback message
     */
    int32_t CallRingbackVoiceNotice(MessageParcel &data);

    /**
     * @brief report of srvcc
     *
     * @param data is HDF service callback message
     */
    int32_t SrvccStatusNotice(MessageParcel &data);

    /**
     * @brief call XLEMA notice
     *
     * @param data is HDF service callback message
     */
    int32_t CallEmergencyNotice(MessageParcel &data);

private:
    bool IsCallResponse(uint32_t code);
    bool IsCallNotification(uint32_t code);
    void AddHandlerToMap();
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_CALL_H
