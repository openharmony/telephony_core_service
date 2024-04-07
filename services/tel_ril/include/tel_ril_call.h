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

namespace OHOS {
namespace Telephony {
class TelRilCall : public TelRilBase {
public:
    TelRilCall(int32_t slotId, sptr<HDI::Ril::V1_3::IRil> rilInterface,
        std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler);
    ~TelRilCall() = default;

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
    int32_t SetCallRestriction(std::string restrictionType,
        int32_t mode, std::string password, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
        const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetUssd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetUssd(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetMute(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetEmergencyCallList(
        const std::vector<EmergencyCall> &eccVec, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetBarringPassword(std::string fac, const char *oldPassword,
        const char *newPassword, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t CloseUnFinishedUssd(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t AnswerResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetCallListResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CallInfoList &callList);
    int32_t DialResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t HangupResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t RejectResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t HoldCallResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t UnHoldCallResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SwitchCallResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t CombineConferenceResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SeparateConferenceResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t CallSupplementResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetCallWaitingResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CallWaitResult &callWaitResult);
    int32_t SetCallTransferInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetCallTransferInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::CallForwardQueryInfoList &cFQueryList);
    int32_t GetClipResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::GetClipResult &getClipResult);
    int32_t SetClipResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetClirResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::GetClirResult &getClirResult);
    int32_t SetClirResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetCallRestrictionResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CallRestrictionResult &result);
    int32_t SetCallRestrictionResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SetCallWaitingResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SendDtmfResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t StartDtmfResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t StopDtmfResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SetCallPreferenceModeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetCallPreferenceModeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t mode);
    int32_t SetUssdResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetUssdResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t cusd);
    int32_t SetMuteResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetMuteResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t mute);
    int32_t GetEmergencyCallListResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::EmergencyInfoList &emergencyInfoList);
    int32_t SetEmergencyCallListResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetCallFailReasonResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t callFail);
    int32_t SetBarringPasswordResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t CallStateUpdated();
    int32_t CallUssdNotice(const HDI::Ril::V1_1::UssdNoticeInfo &ussdNoticeInfo);
    int32_t CallSsNotice(const HDI::Ril::V1_1::SsNoticeInfo &ssNoticeInfo);
    int32_t CallRingbackVoiceNotice(const HDI::Ril::V1_1::RingbackVoice &ringbackVoice);
    int32_t CallSrvccStatusNotice(const HDI::Ril::V1_1::SrvccStatus &srvccStatus);
    int32_t CallEmergencyNotice(const HDI::Ril::V1_1::EmergencyInfoList &emergencyInfoList);
    int32_t CallRsrvccStatusNotify();
    int32_t CloseUnFinishedUssdResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SetVoNRSwitch(int32_t state, const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SetVoNRSwitchResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);

private:
    void BuildEmergencyInfoList(std::shared_ptr<EmergencyInfoList> emergencyCallList,
        const HDI::Ril::V1_1::EmergencyInfoList &emergencyInfoList);
    void BuildCallInfoList(std::shared_ptr<CallInfoList> callInfoList,
        const HDI::Ril::V1_1::CallInfoList &iCallInfoList);
    void BuildCFQueryInfoList(std::shared_ptr<CallForwardQueryInfoList> cFQueryInfoList,
        const HDI::Ril::V1_1::CallForwardQueryInfoList &cFQueryList);
    int32_t ResponseSupplement(const char *funcName, const HDI::Ril::V1_1::RilRadioResponseInfo &iResponseInfo);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_CALL_H
