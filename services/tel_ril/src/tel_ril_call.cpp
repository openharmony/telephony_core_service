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

#include "tel_ril_call.h"

#include "core_service_hisysevent.h"
#include "hril_call_parcel.h"
#include "hril_notification.h"
#include "hril_request.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
TelRilCall::TelRilCall(int32_t slotId, sptr<IRemoteObject> cellularRadio,
    sptr<HDI::Ril::V1_0::IRilInterface> rilInterface, std::shared_ptr<ObserverHandler> observerHandler,
    std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, rilInterface, observerHandler, handler) {}

int32_t TelRilCall::AnswerResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::HoldCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::UnHoldCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SwitchCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICallInfoList &callInfoList)
{
    std::shared_ptr<CallInfoList> callInfo = std::make_shared<CallInfoList>();
    if (callInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildCallInfoList(callInfo, callInfoList);
    return Response<CallInfoList>(TELEPHONY_LOG_FUNC_NAME, responseInfo, callInfo);
}

int32_t TelRilCall::DialResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::HangupResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::RejectResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::CombineConferenceResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SeparateConferenceResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::CallSupplementResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallWaitingResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICallWaitResult &callWaitResult)
{
    std::shared_ptr<CallWaitResult> callWaitInfoResult = std::make_shared<CallWaitResult>();
    if (callWaitInfoResult == nullptr) {
        TELEPHONY_LOGE("ERROR : callWaitInfoResult == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callWaitInfoResult->result = callWaitResult.result;
    callWaitInfoResult->status = callWaitResult.status;
    callWaitInfoResult->classCw = callWaitResult.classCw;
    return Response<CallWaitResult>(TELEPHONY_LOG_FUNC_NAME, responseInfo, callWaitInfoResult);
}

int32_t TelRilCall::SetCallWaitingResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SetCallTransferInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallTransferInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICallForwardQueryInfoList &cFQueryList)
{
    std::shared_ptr<CallForwardQueryInfoList> cFQueryInfoList = std::make_shared<CallForwardQueryInfoList>();
    if (cFQueryInfoList == nullptr) {
        TELEPHONY_LOGE("ERROR : cFQueryInfoList == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildCFQueryInfoList(cFQueryInfoList, cFQueryList);
    return Response<CallForwardQueryInfoList>(TELEPHONY_LOG_FUNC_NAME, responseInfo, cFQueryInfoList);
}

int32_t TelRilCall::GetClipResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IGetClipResult &getClipResult)
{
    std::shared_ptr<GetClipResult> clipResult = std::make_shared<GetClipResult>();
    clipResult->result = getClipResult.result;
    clipResult->action = getClipResult.action;
    clipResult->clipStat = getClipResult.clipStat;
    return Response<GetClipResult>(TELEPHONY_LOG_FUNC_NAME, responseInfo, clipResult);
}

int32_t TelRilCall::SetClipResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetClirResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IGetClirResult &getClirResult)
{
    std::shared_ptr<GetClirResult> result = std::make_shared<GetClirResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("ERROR : result == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    result->result = getClirResult.result;
    result->action = getClirResult.action;
    result->clirStat = getClirResult.clirStat;
    return Response<GetClirResult>(TELEPHONY_LOG_FUNC_NAME, responseInfo, result);
}

int32_t TelRilCall::SetClirResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallRestrictionResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICallRestrictionResult &result)
{
    std::shared_ptr<CallRestrictionResult> callRestrictionResult = std::make_shared<CallRestrictionResult>();
    if (callRestrictionResult == nullptr) {
        TELEPHONY_LOGE("ERROR : callRestrictionResult == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callRestrictionResult->result = result.result;
    callRestrictionResult->status = result.status;
    callRestrictionResult->classCw = result.classCw;
    return Response<CallRestrictionResult>(TELEPHONY_LOG_FUNC_NAME, responseInfo, callRestrictionResult);
}

int32_t TelRilCall::SetCallRestrictionResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SendDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::StartDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::StopDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SetCallPreferenceModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallPreferenceModeResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t mode)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo, mode);
}

int32_t TelRilCall::SetUssdResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetUssdResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t cusd)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo, cusd);
}

int32_t TelRilCall::SetMuteResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetMuteResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t mute)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo, mute);
}

int32_t TelRilCall::GetCallFailReasonResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t callFail)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo, callFail);
}

int32_t TelRilCall::SetBarringPasswordResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_CALL_LIST,
        &HDI::Ril::V1_0::IRilInterface::GetCallList);
}

int32_t TelRilCall::Dial(const std::string address, int32_t clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_0::IDialInfo dialInfo = {};
    dialInfo.address = address;
    dialInfo.clir = clirMode;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_DIAL,
        &HDI::Ril::V1_0::IRilInterface::Dial, dialInfo);
}

int32_t TelRilCall::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_REJECT,
        &HDI::Ril::V1_0::IRilInterface::Reject);
}

int32_t TelRilCall::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_HANGUP,
        &HDI::Ril::V1_0::IRilInterface::Hangup, gsmIndex);
}

int32_t TelRilCall::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_ANSWER,
        &HDI::Ril::V1_0::IRilInterface::Answer);
}

int32_t TelRilCall::HoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_HOLD_CALL,
        &HDI::Ril::V1_0::IRilInterface::HoldCall);
}

int32_t TelRilCall::UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_UNHOLD_CALL,
        &HDI::Ril::V1_0::IRilInterface::UnHoldCall);
}

int32_t TelRilCall::SwitchCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SWITCH_CALL,
        &HDI::Ril::V1_0::IRilInterface::SwitchCall);
}

int32_t TelRilCall::CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_COMBINE_CONFERENCE,
        &HDI::Ril::V1_0::IRilInterface::CombineConference, callType);
}

int32_t TelRilCall::GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_CALL_WAITING,
        &HDI::Ril::V1_0::IRilInterface::GetCallWaiting);
}

int32_t TelRilCall::SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_CALL_WAITING,
        &HDI::Ril::V1_0::IRilInterface::SetCallWaiting, activate);
}

int32_t TelRilCall::SeparateConference(
    int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SEPARATE_CONFERENCE,
        &HDI::Ril::V1_0::IRilInterface::SeparateConference, callIndex, callType);
}

int32_t TelRilCall::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_CALL_SUPPLEMENT,
        &HDI::Ril::V1_0::IRilInterface::CallSupplement, type);
}

int32_t TelRilCall::GetCallTransferInfo(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_CALL_TRANSFER_INFO,
        &HDI::Ril::V1_0::IRilInterface::GetCallTransferInfo, reason);
}

int32_t TelRilCall::SetCallTransferInfo(
    int32_t reason, int32_t mode, std::string number, int32_t classx, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_0::ICallForwardSetInfo callForwardSetInfo = {};
    callForwardSetInfo.reason = reason;
    callForwardSetInfo.mode = mode;
    callForwardSetInfo.classx = classx;
    callForwardSetInfo.number = number;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_CALL_TRANSFER_INFO,
        &HDI::Ril::V1_0::IRilInterface::SetCallTransferInfo, callForwardSetInfo);
}

int32_t TelRilCall::GetClip(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_CLIP,
        &HDI::Ril::V1_0::IRilInterface::GetClip);
}

int32_t TelRilCall::SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_CLIP,
        &HDI::Ril::V1_0::IRilInterface::SetClip, action);
}

int32_t TelRilCall::GetClir(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_CLIR,
        &HDI::Ril::V1_0::IRilInterface::GetClir);
}

int32_t TelRilCall::SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_CLIR,
        &HDI::Ril::V1_0::IRilInterface::SetClir, action);
}

int32_t TelRilCall::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_CALL_RESTRICTION,
        &HDI::Ril::V1_0::IRilInterface::GetCallRestriction, fac);
}

int32_t TelRilCall::SetCallRestriction(
    std::string fac, int32_t mode, std::string password, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_0::ICallRestrictionInfo callRestrictionInfo = {};
    callRestrictionInfo.fac = fac;
    callRestrictionInfo.mode = mode;
    callRestrictionInfo.password = password;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_CALL_RESTRICTION,
        &HDI::Ril::V1_0::IRilInterface::SetCallRestriction, callRestrictionInfo);
}

int32_t TelRilCall::SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_0::IDtmfInfo dtmfInfo = {};
    dtmfInfo.callId = index;
    dtmfInfo.dtmfKey = sDTMFCode;
    dtmfInfo.onLength = switchOn;
    dtmfInfo.offLength = switchOff;
    dtmfInfo.stringLength = sDTMFCode.length();
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SEND_DTMF,
        &HDI::Ril::V1_0::IRilInterface::SendDtmf, dtmfInfo);
}

int32_t TelRilCall::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    char dtmfKey[2];
    dtmfKey[0] = cDTMFCode;
    dtmfKey[1] = '\0';

    HDI::Ril::V1_0::IDtmfInfo dtmfInfo = {};
    dtmfInfo.callId = index;
    dtmfInfo.dtmfKey = dtmfKey;
    dtmfInfo.onLength = 1;
    dtmfInfo.offLength = 0;
    dtmfInfo.stringLength = 1;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SEND_DTMF,
        &HDI::Ril::V1_0::IRilInterface::SendDtmf, dtmfInfo);
}

int32_t TelRilCall::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    char dtmfKey[2];
    dtmfKey[0] = cDTMFCode;
    dtmfKey[1] = '\0';

    HDI::Ril::V1_0::IDtmfInfo dtmfInfo = {};
    dtmfInfo.callId = index;
    dtmfInfo.dtmfKey = dtmfKey;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_START_DTMF,
        &HDI::Ril::V1_0::IRilInterface::StartDtmf, dtmfInfo);
}

int32_t TelRilCall::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    char dtmfKey[2];
    dtmfKey[0] = 'A';
    dtmfKey[1] = '\0';

    HDI::Ril::V1_0::IDtmfInfo dtmfInfo = {};
    dtmfInfo.callId = index;
    dtmfInfo.dtmfKey = dtmfKey;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_STOP_DTMF,
        &HDI::Ril::V1_0::IRilInterface::StopDtmf, dtmfInfo);
}

int32_t TelRilCall::SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_CALL_PREFERENCE,
        &HDI::Ril::V1_0::IRilInterface::SetCallPreferenceMode, mode);
}

int32_t TelRilCall::GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_CALL_PREFERENCE,
        &HDI::Ril::V1_0::IRilInterface::GetCallPreferenceMode);
}

int32_t TelRilCall::SetUssd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_USSD,
        &HDI::Ril::V1_0::IRilInterface::SetUssd, str);
}

int32_t TelRilCall::GetUssd(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_USSD,
        &HDI::Ril::V1_0::IRilInterface::GetUssd);
}

int32_t TelRilCall::SetBarringPassword(std::string fac, std::string oldPassword,
    std::string newPassword, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_0::ISetBarringInfo setBarringInfo = {};
    setBarringInfo.fac = fac;
    setBarringInfo.oldPassword = oldPassword;
    setBarringInfo.newPassword = newPassword;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_BARRING_PASSWORD,
        &HDI::Ril::V1_0::IRilInterface::SetBarringPassword, setBarringInfo);
}

int32_t TelRilCall::CallStateUpdated(int32_t type)
{
    return Notify(TELEPHONY_LOG_FUNC_NAME, RadioEvent::RADIO_CALL_STATUS_INFO);
}

int32_t TelRilCall::CallUssdNotice(const HDI::Ril::V1_0::IUssdNoticeInfo &ussdNoticeInfo)
{
    std::shared_ptr<UssdNoticeInfo> ussdNotice = std::make_shared<UssdNoticeInfo>();
    if (ussdNotice == nullptr) {
        TELEPHONY_LOGE("ERROR : ussdNotice == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    ussdNotice->m = ussdNoticeInfo.m;
    ussdNotice->str = ussdNoticeInfo.str;
    return Notify<UssdNoticeInfo>(
        TELEPHONY_LOG_FUNC_NAME, ussdNotice, RadioEvent::RADIO_CALL_USSD_NOTICE);
}

int32_t TelRilCall::CallSsNotice(const HDI::Ril::V1_0::ISsNoticeInfo &ssNoticeInfo)
{
    std::shared_ptr<SsNoticeInfo> ssNotice = std::make_shared<SsNoticeInfo>();
    if (ssNotice == nullptr) {
        TELEPHONY_LOGE("ERROR : ssNotice == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    ssNotice->serviceType = ssNoticeInfo.serviceType;
    ssNotice->requestType = ssNoticeInfo.requestType;
    ssNotice->serviceClass = ssNoticeInfo.serviceClass;
    ssNotice->result = ssNoticeInfo.result;
    return Notify<SsNoticeInfo>(
        TELEPHONY_LOG_FUNC_NAME, ssNotice, RadioEvent::RADIO_CALL_SS_NOTICE);
}

int32_t TelRilCall::CallRingbackVoiceNotice(const HDI::Ril::V1_0::IRingbackVoice &ringbackVoice)
{
    std::shared_ptr<RingbackVoice> ringbackVoiceInfo = std::make_shared<RingbackVoice>();
    if (ringbackVoiceInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ringbackVoiceInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    ringbackVoiceInfo->status = ringbackVoice.status;
    return Notify<RingbackVoice>(
        TELEPHONY_LOG_FUNC_NAME, ringbackVoiceInfo, RadioEvent::RADIO_CALL_RINGBACK_VOICE);
}

int32_t TelRilCall::CallSrvccStatusNotice(const HDI::Ril::V1_0::ISrvccStatus &srvccStatus)
{
    std::shared_ptr<SrvccStatus> srvccStatusInfo = std::make_shared<SrvccStatus>();
    if (srvccStatusInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : srvccStatusInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    srvccStatusInfo->status = srvccStatus.status;
    return Notify<SrvccStatus>(
        TELEPHONY_LOG_FUNC_NAME, srvccStatusInfo, RadioEvent::RADIO_CALL_SRVCC_STATUS);
}

int32_t TelRilCall::SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_MUTE,
        &HDI::Ril::V1_0::IRilInterface::SetMute, mute);
}

int32_t TelRilCall::GetMute(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_MUTE,
        &HDI::Ril::V1_0::IRilInterface::GetMute);
}

int32_t TelRilCall::GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_EMERGENCY_LIST,
        &HDI::Ril::V1_0::IRilInterface::GetEmergencyCallList);
}

int32_t TelRilCall::SetEmergencyCallList(
    std::vector<EmergencyCall> &eccVec, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_0::IEmergencyInfoList emergencyInfoList;
    emergencyInfoList.callSize = (int32_t)eccVec.size();
    int index = 1;
    for (EmergencyCall ecc : eccVec) {
        HDI::Ril::V1_0::IEmergencyCall emergencyCall = {};
        emergencyCall.index = index;
        emergencyCall.total = eccVec.size();
        emergencyCall.eccNum = ecc.eccNum;
        emergencyCall.eccType = (HDI::Ril::V1_0::IEccType)(ecc.eccType);
        emergencyCall.simpresent = (HDI::Ril::V1_0::ISimpresentType)(ecc.simpresent);
        emergencyCall.mcc = ecc.mcc;
        emergencyCall.abnormalService = (HDI::Ril::V1_0::IAbnormalServiceType)(ecc.abnormalService);
        index++;
        emergencyInfoList.calls.push_back(emergencyCall);
    }
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_SET_EMERGENCY_LIST,
        &HDI::Ril::V1_0::IRilInterface::SetEmergencyCallList, emergencyInfoList);
}

int32_t TelRilCall::SetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList)
{
    std::shared_ptr<EmergencyInfoList> emergencyCallList = std::make_shared<EmergencyInfoList>();
    if (emergencyCallList == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildEmergencyInfoList(emergencyCallList, emergencyInfoList);
    return Response<EmergencyInfoList>(TELEPHONY_LOG_FUNC_NAME, responseInfo, emergencyCallList);
}

int32_t TelRilCall::GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, HREQ_CALL_GET_FAIL_REASON,
        &HDI::Ril::V1_0::IRilInterface::GetCallFailReason);
}

int32_t TelRilCall::CallEmergencyNotice(const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList)
{
    std::shared_ptr<EmergencyInfoList> emergencyCallInfoList = std::make_shared<EmergencyInfoList>();
    BuildEmergencyInfoList(emergencyCallInfoList, emergencyInfoList);
    return Notify<EmergencyInfoList>(
        TELEPHONY_LOG_FUNC_NAME, emergencyCallInfoList, RadioEvent::RADIO_CALL_EMERGENCY_NUMBER_REPORT);
}

void TelRilCall::BuildEmergencyInfoList(
    std::shared_ptr<EmergencyInfoList> emergencyCallList, const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList)
{
    emergencyCallList->callSize = emergencyInfoList.callSize;
    for (auto ecc : emergencyInfoList.calls) {
        EmergencyInfo call;
        call.index = ecc.index;
        call.total = ecc.total;
        call.eccNum = ecc.eccNum;
        call.category = ecc.simpresent;
        call.mcc = ecc.mcc;
        call.abnormalService = ecc.abnormalService;
        emergencyCallList->calls.push_back(call);
    }
}

void TelRilCall::BuildCallInfoList(
    std::shared_ptr<CallInfoList> callInfoList, const HDI::Ril::V1_0::ICallInfoList &iCallInfoList)
{
    callInfoList->callSize = iCallInfoList.callSize;
    for (auto info : iCallInfoList.calls) {
        CallInfo call;
        call.index = info.index;
        call.dir = info.dir;
        call.state = info.state;
        call.mode = info.mode;
        call.mpty = info.mpty;
        call.voiceDomain = info.voiceDomain;
        call.callType = info.callType;
        call.number = info.number;
        call.type = info.type;
        call.alpha = info.alpha;
        callInfoList->calls.push_back(call);
    }
}

void TelRilCall::BuildCFQueryInfoList(std::shared_ptr<CallForwardQueryInfoList> cFQueryInfoList,
    const HDI::Ril::V1_0::ICallForwardQueryInfoList &cFQueryList)
{
    cFQueryInfoList->callSize = cFQueryList.callSize;
    for (auto info : cFQueryList.calls) {
        CallForwardQueryResult call;
        call.serial = info.serial;
        call.result = info.result;
        call.status = info.status;
        call.classx = info.classx;
        call.number = info.number;
        call.type = info.type;
        call.reason = info.reason;
        call.time = info.time;
        cFQueryInfoList->calls.push_back(call);
    }
}
} // namespace Telephony
} // namespace OHOS
