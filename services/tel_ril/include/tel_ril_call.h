/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "hril_call_parcel.h"
#include "tel_ril_base.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class TelRilCall : public TelRilBase {
public:
    TelRilCall(int32_t slotId, sptr<IRemoteObject> cellularRadio, sptr<HDI::Ril::V1_0::IRilInterface> rilInterface,
        std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler);
    ~TelRilCall() = default;

    bool IsCallRespOrNotify(uint32_t code);

    int32_t GetCallList(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t Dial(const std::string address, int32_t clirMode, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t Reject(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t Answer(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t HoldCall(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SwitchCall(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SeparateConference(int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetCallTransferInfo(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetCallTransferInfo(int32_t reason, int32_t mode, std::string number, int32_t classx,
        const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetClip(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetClir(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetCallRestriction(
        std::string fac, int32_t mode, std::string password, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t AnswerResponse(MessageParcel &data);
    int32_t GetCallListResponse(MessageParcel &data);
    int32_t DialResponse(MessageParcel &data);
    int32_t HangupResponse(MessageParcel &data);
    int32_t RejectResponse(MessageParcel &data);
    int32_t HoldCallResponse(MessageParcel &data);
    int32_t UnHoldCallResponse(MessageParcel &data);
    int32_t SwitchCallResponse(MessageParcel &data);
    int32_t CombineConferenceResponse(MessageParcel &data);
    int32_t SeparateConferenceResponse(MessageParcel &data);
    int32_t CallSupplementResponse(MessageParcel &data);
    int32_t GetCallWaitingResponse(MessageParcel &data);
    int32_t SetCallTransferInfoResponse(MessageParcel &data);
    int32_t GetCallTransferInfoResponse(MessageParcel &data);
    int32_t GetClipResponse(MessageParcel &data);
    int32_t SetClipResponse(MessageParcel &data);
    int32_t GetClirResponse(MessageParcel &data);
    int32_t SetClirResponse(MessageParcel &data);
    int32_t GetCallRestrictionResponse(MessageParcel &data);
    int32_t SetCallRestrictionResponse(MessageParcel &data);
    int32_t SetCallWaitingResponse(MessageParcel &data);
    int32_t SendDtmfResponse(MessageParcel &data);
    int32_t StartDtmfResponse(MessageParcel &data);
    int32_t StopDtmfResponse(MessageParcel &data);
    int32_t SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetCallPreferenceResponse(MessageParcel &data);
    int32_t GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetCallPreferenceResponse(MessageParcel &data);
    int32_t SetUssd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetUssdResponse(MessageParcel &data);
    int32_t GetUssd(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetUssdResponse(MessageParcel &data);
    int32_t CallStateUpdated(MessageParcel &data);
    int32_t CallUssdNotice(MessageParcel &data);
    int32_t SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetMuteResponse(MessageParcel &data);
    int32_t GetMute(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetMuteResponse(MessageParcel &data);
    int32_t GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList);
    int32_t SetEmergencyCallList(std::vector<EmergencyCall> &eccVec, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetCallFailReasonResponse(MessageParcel &data);
    int32_t CallRingbackVoiceNotice(MessageParcel &data);
    int32_t SrvccStatusNotice(MessageParcel &data);
    int32_t CallEmergencyNotice(const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList);
    int32_t CallSsNotice(MessageParcel &data);

private:
    bool IsCallResponse(uint32_t code);
    bool IsCallNotification(uint32_t code);
    void AddHandlerToMap();
    void BuildEmergencyInfoList(std::shared_ptr<EmergencyInfoList> emergencyCallList,
        const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_CALL_H
