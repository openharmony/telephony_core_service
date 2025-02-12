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
#include "radio_event.h"
#include "tel_ril_call_parcel.h"

namespace OHOS {
namespace Telephony {
static const int32_t TYPE_CS = 0;
static const int32_t DTMF_ON_LENGTH = 150;
static const int32_t DTMF_OFF_LENGTH = 70;
static const int32_t DTMF_STRING_LENGTH = 1;

TelRilCall::TelRilCall(int32_t slotId, sptr<HDI::Ril::V1_4::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, rilInterface, observerHandler, handler)
{}

int32_t TelRilCall::AnswerResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::HoldCallResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::UnHoldCallResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SwitchCallResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallListResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CallInfoList &callInfoList)
{
    std::shared_ptr<CallInfoList> callInfo = std::make_shared<CallInfoList>();
    if (callInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildCallInfoList(callInfo, callInfoList);
    return Response<CallInfoList>(TELEPHONY_LOG_FUNC_NAME, responseInfo, callInfo);
}

int32_t TelRilCall::GetCallListResponseExt(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_4::CallInfoExtList &callInfoList)
{
    std::shared_ptr<CallInfoList> callInfo = std::make_shared<CallInfoList>();
    if (callInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildCallInfoExtList(callInfo, callInfoList);
    return Response<CallInfoList>(TELEPHONY_LOG_FUNC_NAME, responseInfo, callInfo);
}

int32_t TelRilCall::DialResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::HangupResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::RejectResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::CombineConferenceResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SeparateConferenceResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::CallSupplementResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallWaitingResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CallWaitResult &callWaitResult)
{
    std::shared_ptr<CallWaitResult> callWaitInfoResult = std::make_shared<CallWaitResult>();
    if (callWaitInfoResult == nullptr) {
        TELEPHONY_LOGE("ERROR : callWaitInfoResult == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callWaitInfoResult->result.result = callWaitResult.result;
    callWaitInfoResult->status = callWaitResult.status;
    callWaitInfoResult->classCw = callWaitResult.classCw;
    const auto &radioResponseInfo = BuildHRilRadioResponseInfo(responseInfo);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    int32_t ret = ConfirmSupplementOfTelRilRequestInfo(TELEPHONY_LOG_FUNC_NAME, telRilRequest);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    } else if (radioResponseInfo.error != ErrType::NONE) {
        callWaitInfoResult->result.result = TELEPHONY_ERR_FAIL;
    }
    callWaitInfoResult->result.index = telRilRequest->pointer_->GetParam();
    return TelEventHandler::SendTelEvent(
        telRilRequest->pointer_->GetOwner(), telRilRequest->pointer_->GetInnerEventId(), callWaitInfoResult);
}

int32_t TelRilCall::SetCallWaitingResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SetCallTransferInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallTransferInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::CallForwardQueryInfoList &cFQueryList)
{
    std::shared_ptr<CallForwardQueryInfoList> cFQueryInfoList = std::make_shared<CallForwardQueryInfoList>();
    if (cFQueryInfoList == nullptr) {
        TELEPHONY_LOGE("ERROR : cFQueryInfoList == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const auto &radioResponseInfo = BuildHRilRadioResponseInfo(responseInfo);
    BuildCFQueryInfoList(cFQueryInfoList, cFQueryList);
    cFQueryInfoList->result.result = TELEPHONY_SUCCESS;
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    int32_t ret = ConfirmSupplementOfTelRilRequestInfo(TELEPHONY_LOG_FUNC_NAME, telRilRequest);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    } else if (radioResponseInfo.error != ErrType::NONE) {
        cFQueryInfoList->result.result = TELEPHONY_ERR_FAIL;
    }
    cFQueryInfoList->result.index = telRilRequest->pointer_->GetParam();
    return TelEventHandler::SendTelEvent(
        telRilRequest->pointer_->GetOwner(), telRilRequest->pointer_->GetInnerEventId(), cFQueryInfoList);
}

int32_t TelRilCall::GetClipResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::GetClipResult &getClipResult)
{
    std::shared_ptr<GetClipResult> clipResult = std::make_shared<GetClipResult>();
    if (clipResult == nullptr) {
        TELEPHONY_LOGE("ERROR : clipResult == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    clipResult->result.result = getClipResult.result;
    clipResult->action = getClipResult.action;
    clipResult->clipStat = getClipResult.clipStat;
    const auto &radioResponseInfo = BuildHRilRadioResponseInfo(responseInfo);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    int32_t ret = ConfirmSupplementOfTelRilRequestInfo(TELEPHONY_LOG_FUNC_NAME, telRilRequest);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    } else if (radioResponseInfo.error != ErrType::NONE) {
        clipResult->result.result = TELEPHONY_ERR_FAIL;
    }
    clipResult->result.index = telRilRequest->pointer_->GetParam();
    return TelEventHandler::SendTelEvent(
        telRilRequest->pointer_->GetOwner(), telRilRequest->pointer_->GetInnerEventId(), clipResult);
}

int32_t TelRilCall::SetClipResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetClirResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::GetClirResult &getClirResult)
{
    std::shared_ptr<GetClirResult> result = std::make_shared<GetClirResult>();
    if (result == nullptr) {
        TELEPHONY_LOGE("ERROR : result == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    result->result.result = getClirResult.result;
    result->action = getClirResult.action;
    result->clirStat = getClirResult.clirStat;
    const auto &radioResponseInfo = BuildHRilRadioResponseInfo(responseInfo);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    int32_t ret = ConfirmSupplementOfTelRilRequestInfo(TELEPHONY_LOG_FUNC_NAME, telRilRequest);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    } else if (radioResponseInfo.error != ErrType::NONE) {
        result->result.result = TELEPHONY_ERR_FAIL;
    }
    result->result.index = telRilRequest->pointer_->GetParam();
    return TelEventHandler::SendTelEvent(
        telRilRequest->pointer_->GetOwner(), telRilRequest->pointer_->GetInnerEventId(), result);
}

int32_t TelRilCall::SetClirResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallRestrictionResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CallRestrictionResult &result)
{
    std::shared_ptr<CallRestrictionResult> callRestrictionResult = std::make_shared<CallRestrictionResult>();
    if (callRestrictionResult == nullptr) {
        TELEPHONY_LOGE("ERROR : callRestrictionResult == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callRestrictionResult->result.result = result.result;
    callRestrictionResult->status = result.status;
    callRestrictionResult->classCw = result.classCw;
    const auto &radioResponseInfo = BuildHRilRadioResponseInfo(responseInfo);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    int32_t ret = ConfirmSupplementOfTelRilRequestInfo(TELEPHONY_LOG_FUNC_NAME, telRilRequest);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    } else if (radioResponseInfo.error != ErrType::NONE) {
        callRestrictionResult->result.result = TELEPHONY_ERR_FAIL;
    }
    callRestrictionResult->result.index = telRilRequest->pointer_->GetParam();
    return TelEventHandler::SendTelEvent(
        telRilRequest->pointer_->GetOwner(), telRilRequest->pointer_->GetInnerEventId(), callRestrictionResult);
}

int32_t TelRilCall::SetCallRestrictionResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SendDtmfResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    const auto &info = BuildHRilRadioResponseInfo(responseInfo);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(info);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("telRilRequest or pointer_ is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<RadioResponseInfo> radioResponseInfo = std::make_shared<RadioResponseInfo>();
    radioResponseInfo->serial = responseInfo.serial;
    radioResponseInfo->flag = telRilRequest->pointer_->GetParam();
    radioResponseInfo->error = static_cast<ErrType>(responseInfo.error);
    AppExecFwk::InnerEvent::Pointer response =
        AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SEND_DTMF, radioResponseInfo, TYPE_CS);
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : ErrorResponse --> handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TelEventHandler::SendTelEvent(handler, response);
}

int32_t TelRilCall::StartDtmfResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::StopDtmfResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SetCallPreferenceModeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallPreferenceModeResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t mode)
{
    std::shared_ptr<int32_t> result = std::make_shared<int32_t>();
    *result = mode;
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo, result);
}

int32_t TelRilCall::SetUssdResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetUssdResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t cusd)
{
    std::shared_ptr<int32_t> usdResult = std::make_shared<int32_t>();
    *usdResult = cusd;
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo, usdResult);
}

int32_t TelRilCall::SetMuteResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetMuteResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t mute)
{
    std::shared_ptr<int32_t> muteResult = std::make_shared<int32_t>();
    *muteResult = mute;
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo, muteResult);
}

int32_t TelRilCall::GetCallFailReasonResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t callFail)
{
    std::shared_ptr<int32_t> failCause = std::make_shared<int32_t>();
    *failCause = callFail;
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo, failCause);
}

int32_t TelRilCall::SetBarringPasswordResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return ResponseSupplement(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::CloseUnFinishedUssdResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::SetVoNRSwitchResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetCallList);
}

int32_t TelRilCall::Dial(const std::string address, int32_t clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_1::DialInfo dialInfo = {};
    dialInfo.address = address;
    dialInfo.clir = clirMode;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::Dial, dialInfo);
}

int32_t TelRilCall::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::Reject);
}

int32_t TelRilCall::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::Hangup, gsmIndex);
}

int32_t TelRilCall::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::Answer);
}

int32_t TelRilCall::HoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::HoldCall);
}

int32_t TelRilCall::UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::UnHoldCall);
}

int32_t TelRilCall::SwitchCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SwitchCall);
}

int32_t TelRilCall::CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::CombineConference, callType);
}

int32_t TelRilCall::GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetCallWaiting);
}

int32_t TelRilCall::SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetCallWaiting, activate);
}

int32_t TelRilCall::SeparateConference(
    int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SeparateConference, callIndex, callType);
}

int32_t TelRilCall::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::CallSupplement, type);
}

int32_t TelRilCall::GetCallTransferInfo(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetCallTransferInfo, reason);
}

int32_t TelRilCall::SetCallTransferInfo(
    int32_t reason, int32_t mode, std::string number, int32_t classx, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_1::CallForwardSetInfo callForwardSetInfo = {};
    callForwardSetInfo.reason = reason;
    callForwardSetInfo.mode = mode;
    callForwardSetInfo.classx = classx;
    callForwardSetInfo.number = number;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetCallTransferInfo, callForwardSetInfo);
}

int32_t TelRilCall::GetClip(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetClip);
}

int32_t TelRilCall::SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetClip, action);
}

int32_t TelRilCall::GetClir(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetClir);
}

int32_t TelRilCall::SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetClir, action);
}

int32_t TelRilCall::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetCallRestriction, fac);
}

int32_t TelRilCall::SetCallRestriction(
    std::string restrictionType, int32_t mode, std::string password, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_1::CallRestrictionInfo callRestrictionInfo = {};
    callRestrictionInfo.fac = restrictionType;
    callRestrictionInfo.mode = mode;
    callRestrictionInfo.password = password;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetCallRestriction, callRestrictionInfo);
}

int32_t TelRilCall::SendDtmfString(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_1::DtmfInfo dtmfInfo = {};
    dtmfInfo.callId = index;
    dtmfInfo.dtmfKey = sDTMFCode;
    dtmfInfo.onLength = switchOn;
    dtmfInfo.offLength = switchOff;
    dtmfInfo.stringLength = sDTMFCode.length();
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SendDtmf, dtmfInfo);
}

int32_t TelRilCall::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    char dtmfKey[2];
    dtmfKey[0] = cDTMFCode;
    dtmfKey[1] = '\0';

    HDI::Ril::V1_1::DtmfInfo dtmfInfo = {};
    dtmfInfo.callId = index;
    dtmfInfo.dtmfKey = dtmfKey;
    dtmfInfo.onLength = DTMF_ON_LENGTH;
    dtmfInfo.offLength = DTMF_OFF_LENGTH;
    dtmfInfo.stringLength = DTMF_STRING_LENGTH;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SendDtmf, dtmfInfo);
}

int32_t TelRilCall::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    char dtmfKey[2];
    dtmfKey[0] = cDTMFCode;
    dtmfKey[1] = '\0';

    HDI::Ril::V1_1::DtmfInfo dtmfInfo = {};
    dtmfInfo.callId = index;
    dtmfInfo.dtmfKey = dtmfKey;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::StartDtmf, dtmfInfo);
}

int32_t TelRilCall::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    char dtmfKey[2];
    dtmfKey[0] = 'A';
    dtmfKey[1] = '\0';

    HDI::Ril::V1_1::DtmfInfo dtmfInfo = {};
    dtmfInfo.callId = index;
    dtmfInfo.dtmfKey = dtmfKey;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::StopDtmf, dtmfInfo);
}

int32_t TelRilCall::SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetCallPreferenceMode, mode);
}

int32_t TelRilCall::GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetCallPreferenceMode);
}

int32_t TelRilCall::SetUssd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetUssd, str);
}

int32_t TelRilCall::GetUssd(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetUssd);
}

int32_t TelRilCall::SetBarringPassword(
    std::string fac, const char *oldPassword, const char *newPassword, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_1::SetBarringInfo setBarringInfo = {};
    setBarringInfo.fac = fac;
    setBarringInfo.oldPassword = oldPassword;
    setBarringInfo.newPassword = newPassword;
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetBarringPassword, setBarringInfo);
}

int32_t TelRilCall::CloseUnFinishedUssd(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::CloseUnFinishedUssd);
}

int32_t TelRilCall::SetVoNRSwitch(int32_t state, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetVonrSwitch, state);
}

int32_t TelRilCall::CallStateUpdated()
{
    return Notify(TELEPHONY_LOG_FUNC_NAME, RadioEvent::RADIO_CALL_STATUS_INFO);
}

int32_t TelRilCall::CallUssdNotice(const HDI::Ril::V1_1::UssdNoticeInfo &ussdNoticeInfo)
{
    std::shared_ptr<UssdNoticeInfo> ussdNotice = std::make_shared<UssdNoticeInfo>();
    if (ussdNotice == nullptr) {
        TELEPHONY_LOGE("ERROR : ussdNotice == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    ussdNotice->m = ussdNoticeInfo.type;
    ussdNotice->str = ussdNoticeInfo.message;
    return Notify<UssdNoticeInfo>(TELEPHONY_LOG_FUNC_NAME, ussdNotice, RadioEvent::RADIO_CALL_USSD_NOTICE);
}

int32_t TelRilCall::CallSsNotice(const HDI::Ril::V1_1::SsNoticeInfo &ssNoticeInfo)
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
    return Notify<SsNoticeInfo>(TELEPHONY_LOG_FUNC_NAME, ssNotice, RadioEvent::RADIO_CALL_SS_NOTICE);
}

int32_t TelRilCall::CallRingbackVoiceNotice(const HDI::Ril::V1_1::RingbackVoice &ringbackVoice)
{
    std::shared_ptr<RingbackVoice> ringbackVoiceInfo = std::make_shared<RingbackVoice>();
    if (ringbackVoiceInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ringbackVoiceInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    ringbackVoiceInfo->status = !ringbackVoice.status;
    return Notify<RingbackVoice>(TELEPHONY_LOG_FUNC_NAME, ringbackVoiceInfo, RadioEvent::RADIO_CALL_RINGBACK_VOICE);
}

int32_t TelRilCall::CallSrvccStatusNotice(const HDI::Ril::V1_1::SrvccStatus &srvccStatus)
{
    std::shared_ptr<SrvccStatus> srvccStatusInfo = std::make_shared<SrvccStatus>();
    if (srvccStatusInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : srvccStatusInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    srvccStatusInfo->status = srvccStatus.status;
    return Notify<SrvccStatus>(TELEPHONY_LOG_FUNC_NAME, srvccStatusInfo, RadioEvent::RADIO_CALL_SRVCC_STATUS);
}

int32_t TelRilCall::CallRsrvccStatusNotify()
{
    return Notify(TELEPHONY_LOG_FUNC_NAME, RadioEvent::RADIO_CALL_RSRVCC_STATUS);
}

int32_t TelRilCall::SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetMute, mute);
}

int32_t TelRilCall::GetMute(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetMute);
}

int32_t TelRilCall::GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetEmergencyCallList);
}

int32_t TelRilCall::SetEmergencyCallList(
    const std::vector<EmergencyCall> &eccVec, const AppExecFwk::InnerEvent::Pointer &result)
{
    HDI::Ril::V1_1::EmergencyInfoList emergencyInfoList;
    emergencyInfoList.callSize = static_cast<int32_t>(eccVec.size());
    int index = 1;
    for (EmergencyCall ecc : eccVec) {
        HDI::Ril::V1_1::EmergencyCall emergencyCall = {};
        emergencyCall.index = index;
        emergencyCall.total = eccVec.size();
        emergencyCall.eccNum = ecc.eccNum;
        emergencyCall.eccType = (HDI::Ril::V1_1::EccType)(ecc.eccType);
        emergencyCall.simpresent = (HDI::Ril::V1_1::SimpresentType)(ecc.simpresent);
        emergencyCall.mcc = ecc.mcc;
        emergencyCall.abnormalService = (HDI::Ril::V1_1::AbnormalServiceType)(ecc.abnormalService);
        index++;
        emergencyInfoList.calls.push_back(emergencyCall);
    }
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::SetEmergencyCallList, emergencyInfoList);
}

int32_t TelRilCall::SetEmergencyCallListResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilCall::GetEmergencyCallListResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::EmergencyInfoList &emergencyInfoList)
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
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetCallFailReason);
}

int32_t TelRilCall::CallEmergencyNotice(const HDI::Ril::V1_1::EmergencyInfoList &emergencyInfoList)
{
    std::shared_ptr<EmergencyInfoList> emergencyCallInfoList = std::make_shared<EmergencyInfoList>();
    BuildEmergencyInfoList(emergencyCallInfoList, emergencyInfoList);
    return Notify<EmergencyInfoList>(
        TELEPHONY_LOG_FUNC_NAME, emergencyCallInfoList, RadioEvent::RADIO_CALL_EMERGENCY_NUMBER_REPORT);
}

void TelRilCall::BuildEmergencyInfoList(
    std::shared_ptr<EmergencyInfoList> emergencyCallList, const HDI::Ril::V1_1::EmergencyInfoList &emergencyInfoList)
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
    std::shared_ptr<CallInfoList> callInfoList, const HDI::Ril::V1_1::CallInfoList &iCallInfoList)
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

void TelRilCall::BuildCallInfoExtList(
    std::shared_ptr<CallInfoList> callInfoList, const HDI::Ril::V1_4::CallInfoExtList &iCallInfoList)
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
        call.name = info.name;
        call.namePresentation = info.namePresentation;
        callInfoList->calls.push_back(call);
    }
}

void TelRilCall::BuildCFQueryInfoList(std::shared_ptr<CallForwardQueryInfoList> cFQueryInfoList,
    const HDI::Ril::V1_1::CallForwardQueryInfoList &cFQueryList)
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

int32_t TelRilCall::ResponseSupplement(const char *funcName, const HDI::Ril::V1_1::RilRadioResponseInfo &iResponseInfo)
{
    const auto &radioResponseInfo = BuildHRilRadioResponseInfo(iResponseInfo);
    auto telRilRequest = FindTelRilRequest(radioResponseInfo);
    int32_t ret = ConfirmSupplementOfTelRilRequestInfo(TELEPHONY_LOG_FUNC_NAME, telRilRequest);
    if (ret != TELEPHONY_SUCCESS) {
        return ret;
    }
    auto resultInfo = std::make_shared<SsBaseResult>();
    resultInfo->index = telRilRequest->pointer_->GetParam();
    resultInfo->result = TELEPHONY_SUCCESS;
    if (radioResponseInfo.error != ErrType::NONE) {
        resultInfo->result = TELEPHONY_ERR_FAIL;
    }
    return TelEventHandler::SendTelEvent(
        telRilRequest->pointer_->GetOwner(), telRilRequest->pointer_->GetInnerEventId(), resultInfo);
}
} // namespace Telephony
} // namespace OHOS
