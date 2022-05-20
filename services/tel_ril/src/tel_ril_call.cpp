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

#include "tel_ril_call.h"

#include "hril_call_parcel.h"
#include "hril_notification.h"
#include "hril_request.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
void TelRilCall::AddHandlerToMap()
{
    // Notification
    memberFuncMap_[HNOTI_CALL_STATE_UPDATED] = &TelRilCall::CallStateUpdated;
    memberFuncMap_[HNOTI_CALL_IMS_SERVICE_STATUS_REPORT] = &TelRilCall::CallImsServiceStatusNotice;
    memberFuncMap_[HNOTI_CALL_USSD_REPORT] = &TelRilCall::CallUssdNotice;
    memberFuncMap_[HNOTI_CALL_RINGBACK_VOICE_REPORT] = &TelRilCall::CallRingbackVoiceNotice;
    memberFuncMap_[HNOTI_CALL_SRVCC_STATUS_REPORT] = &TelRilCall::SrvccStatusNotice;
    memberFuncMap_[HNOTI_CALL_EMERGENCY_NUMBER_REPORT] = &TelRilCall::CallEmergencyNotice;
    memberFuncMap_[HNOTI_CALL_SS_REPORT] = &TelRilCall::CallSsNotice;

    // Response
    memberFuncMap_[HREQ_CALL_GET_CALL_LIST] = &TelRilCall::GetCallListResponse;
    memberFuncMap_[HREQ_CALL_DIAL] = &TelRilCall::DialResponse;
    memberFuncMap_[HREQ_CALL_HANGUP] = &TelRilCall::HangupResponse;
    memberFuncMap_[HREQ_CALL_REJECT] = &TelRilCall::RejectResponse;
    memberFuncMap_[HREQ_CALL_ANSWER] = &TelRilCall::AnswerResponse;
    memberFuncMap_[HREQ_CALL_HOLD_CALL] = &TelRilCall::HoldCallResponse;
    memberFuncMap_[HREQ_CALL_UNHOLD_CALL] = &TelRilCall::UnHoldCallResponse;
    memberFuncMap_[HREQ_CALL_SWITCH_CALL] = &TelRilCall::SwitchCallResponse;
    memberFuncMap_[HREQ_CALL_COMBINE_CONFERENCE] = &TelRilCall::CombineConferenceResponse;
    memberFuncMap_[HREQ_CALL_SEPARATE_CONFERENCE] = &TelRilCall::SeparateConferenceResponse;
    memberFuncMap_[HREQ_CALL_CALL_SUPPLEMENT] = &TelRilCall::CallSupplementResponse;
    memberFuncMap_[HREQ_CALL_GET_CALL_WAITING] = &TelRilCall::GetCallWaitingResponse;
    memberFuncMap_[HREQ_CALL_SET_CALL_WAITING] = &TelRilCall::SetCallWaitingResponse;
    memberFuncMap_[HREQ_CALL_GET_CALL_TRANSFER_INFO] = &TelRilCall::GetCallTransferInfoResponse;
    memberFuncMap_[HREQ_CALL_SET_CALL_TRANSFER_INFO] = &TelRilCall::SetCallTransferInfoResponse;
    memberFuncMap_[HREQ_CALL_GET_CALL_RESTRICTION] = &TelRilCall::GetCallRestrictionResponse;
    memberFuncMap_[HREQ_CALL_SET_CALL_RESTRICTION] = &TelRilCall::SetCallRestrictionResponse;
    memberFuncMap_[HREQ_CALL_GET_CLIP] = &TelRilCall::GetClipResponse;
    memberFuncMap_[HREQ_CALL_SET_CLIP] = &TelRilCall::SetClipResponse;
    memberFuncMap_[HREQ_CALL_GET_CLIR] = &TelRilCall::GetClirResponse;
    memberFuncMap_[HREQ_CALL_SET_CLIR] = &TelRilCall::SetClirResponse;
    memberFuncMap_[HREQ_CALL_SEND_DTMF] = &TelRilCall::SendDtmfResponse;
    memberFuncMap_[HREQ_CALL_START_DTMF] = &TelRilCall::StartDtmfResponse;
    memberFuncMap_[HREQ_CALL_STOP_DTMF] = &TelRilCall::StopDtmfResponse;
    memberFuncMap_[HREQ_CALL_GET_IMS_CALL_LIST] = &TelRilCall::GetImsCallListResponse;
    memberFuncMap_[HREQ_CALL_SET_CALL_PREFERENCE] = &TelRilCall::SetCallPreferenceResponse;
    memberFuncMap_[HREQ_CALL_GET_CALL_PREFERENCE] = &TelRilCall::GetCallPreferenceResponse;
    memberFuncMap_[HREQ_CALL_SET_LTEIMSSWITCH_STATUS] = &TelRilCall::SetLteImsSwitchStatusResponse;
    memberFuncMap_[HREQ_CALL_GET_LTEIMSSWITCH_STATUS] = &TelRilCall::GetLteImsSwitchStatusResponse;
    memberFuncMap_[HREQ_CALL_SET_USSD] = &TelRilCall::SetUssdResponse;
    memberFuncMap_[HREQ_CALL_GET_USSD] = &TelRilCall::GetUssdResponse;
    memberFuncMap_[HREQ_CALL_SET_MUTE] = &TelRilCall::SetMuteResponse;
    memberFuncMap_[HREQ_CALL_GET_MUTE] = &TelRilCall::GetMuteResponse;
    memberFuncMap_[HREQ_CALL_GET_EMERGENCY_LIST] = &TelRilCall::GetEmergencyCallListResponse;
    memberFuncMap_[HREQ_CALL_SET_EMERGENCY_LIST] = &TelRilCall::SetEmergencyCallListResponse;
    memberFuncMap_[HREQ_CALL_GET_FAIL_REASON] = &TelRilCall::GetCallFailReasonResponse;
}

TelRilCall::TelRilCall(int32_t slotId, sptr<IRemoteObject> cellularRadio,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, observerHandler, handler)
{
    AddHandlerToMap();
}

bool TelRilCall::IsCallResponse(uint32_t code)
{
    return ((code >= HREQ_CALL_BASE) && (code < HREQ_SMS_BASE));
}

bool TelRilCall::IsCallNotification(uint32_t code)
{
    return ((code >= HNOTI_CALL_BASE) && (code < HNOTI_SMS_BASE));
}

bool TelRilCall::IsCallRespOrNotify(uint32_t code)
{
    return IsCallResponse(code) || IsCallNotification(code);
}

int32_t TelRilCall::AnswerResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::HoldCallResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::UnHoldCallResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SwitchCallResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall  read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetCallListResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<CallInfoList> callInfo = std::make_shared<CallInfoList>();
    if (callInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    callInfo->flag = telRilRequest->pointer_->GetParam();
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, callInfo);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::DialResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall DialResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::HangupResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall HangupResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::RejectResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall RejectResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::CombineConferenceResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall CombineConferenceResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SeparateConferenceResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::CallSupplementResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall CallSupplementResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : CallSupplementResponse pointer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetCallWaitingResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<CallWaitResult> callWaitResult = std::make_shared<CallWaitResult>();
    callWaitResult->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, callWaitResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetCallWaitingResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall SetCallWaitingResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :  radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR :  handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetCallTransferInfoResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall SetCallTransferInfoResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetCallTransferInfoResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :  radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<CallForwardQueryInfoList> cFQueryList = std::make_shared<CallForwardQueryInfoList>();
    cFQueryList->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :  handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    handler->SendEvent(eventId, cFQueryList);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetClipResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<GetClipResult> getClipResult = std::make_shared<GetClipResult>();
    getClipResult->ReadFromParcel(data);

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, getClipResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetClipResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetClirResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<GetClirResult> getClirResult = std::make_shared<GetClirResult>();
    getClirResult->ReadFromParcel(data);

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, getClirResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetClirResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetCallRestrictionResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :  radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<CallRestrictionResult> result = std::make_shared<CallRestrictionResult>();
    result->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetCallRestrictionResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SendDtmfResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::StartDtmfResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::StopDtmfResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_LIST, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return SendInt32Event(HREQ_CALL_GET_CALL_LIST, telRilRequest->serialId_);
}

int32_t TelRilCall::Dial(const std::string address, int32_t clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_DIAL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    DialInfo dialInfo;
    dialInfo.address = address;
    dialInfo.clir = clirMode;
    dialInfo.serial = telRilRequest->serialId_;
    int32_t ret = SendBufferEvent(HREQ_CALL_DIAL, dialInfo);
    TELEPHONY_LOGI("Send (ID:%{public}d) return: %{public}d", HREQ_CALL_DIAL, ret);
    return ret;
}

int32_t TelRilCall::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_REJECT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_REJECT, telRilRequest->serialId_);
}

int32_t TelRilCall::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_HANGUP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(gsmIndex);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_HANGUP, data, reply, option);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_ANSWER, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t ret = SendInt32Event(HREQ_CALL_ANSWER, telRilRequest->serialId_);
    TELEPHONY_LOGI("SendInt32Event(ID:%{public}d) return: %{public}d", HREQ_CALL_ANSWER, ret);
    return ret;
}

int32_t TelRilCall::HoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_HOLD_CALL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_HOLD_CALL, telRilRequest->serialId_);
}

int32_t TelRilCall::UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_UNHOLD_CALL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_UNHOLD_CALL, telRilRequest->serialId_);
}

int32_t TelRilCall::SwitchCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SWITCH_CALL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_SWITCH_CALL, telRilRequest->serialId_);
}

int32_t TelRilCall::CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_COMBINE_CONFERENCE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t ret =
        SendInt32sEvent(HREQ_CALL_COMBINE_CONFERENCE, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, callType);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_WAITING, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_GET_CALL_WAITING, telRilRequest->serialId_);
}

int32_t TelRilCall::SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_WAITING, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t ret = SendInt32sEvent(HREQ_CALL_SET_CALL_WAITING, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, activate);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::SeparateConference(
    int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SEPARATE_CONFERENCE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t ret = SendInt32sEvent(
        HREQ_CALL_SET_CALL_WAITING, HRIL_EVENT_COUNT_3, telRilRequest->serialId_, callIndex, callType);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_CALL_SUPPLEMENT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t ret = SendInt32sEvent(HREQ_CALL_CALL_SUPPLEMENT, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, type);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::GetCallTransferInfo(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_TRANSFER_INFO, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t ret =
        SendInt32sEvent(HREQ_CALL_GET_CALL_TRANSFER_INFO, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, reason);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::SetCallTransferInfo(
    int32_t reason, int32_t mode, std::string number, int32_t classx, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_TRANSFER_INFO, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    CallForwardSetInfo callForwardSetInfo;
    callForwardSetInfo.reason = reason;
    callForwardSetInfo.mode = mode;
    callForwardSetInfo.classx = classx;
    callForwardSetInfo.number = number;
    callForwardSetInfo.serial = telRilRequest->serialId_;
    int32_t ret = SendBufferEvent(HREQ_CALL_SET_CALL_TRANSFER_INFO, callForwardSetInfo);
    TELEPHONY_LOGI("Send (ID:%{public}d) return: %{public}d", HREQ_CALL_SET_CALL_TRANSFER_INFO, ret);
    return ret;
}

int32_t TelRilCall::GetClip(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CLIP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_GET_CLIP, telRilRequest->serialId_);
}

int32_t TelRilCall::SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CLIP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t ret = SendInt32sEvent(HREQ_CALL_SET_CLIP, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, action);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::GetClir(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CLIR, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_GET_CLIR, telRilRequest->serialId_);
}

int32_t TelRilCall::SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CLIR, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t ret = SendInt32sEvent(HREQ_CALL_SET_CLIR, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, action);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_RESTRICTION, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(fac.c_str());
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_GET_CALL_RESTRICTION, data, reply, option);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::SetCallRestriction(
    std::string fac, int32_t mode, std::string password, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_RESTRICTION, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(mode);
    data.WriteCString(fac.c_str());
    data.WriteCString(password.c_str());
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CALL_RESTRICTION, data, reply, option);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("TelRilCall::SendDtmf cellularRadio_ == NULL !!!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SEND_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteInt32(switchOn);
    data.WriteInt32(switchOff);
    data.WriteInt32(sDTMFCode.length());
    data.WriteCString(sDTMFCode.c_str());
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_SEND_DTMF, data, reply, option);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SEND_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    char temp[2];
    temp[0] = cDTMFCode;
    temp[1] = '\0';
    const int32_t stringLength = 1;
    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteInt32(1);
    data.WriteInt32(0);
    data.WriteInt32(stringLength);
    data.WriteCString(temp);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_SEND_DTMF, data, reply, option);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_START_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    char temp[2];
    temp[0] = cDTMFCode;
    temp[1] = '\0';
    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteCString(temp);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_START_DTMF, data, reply, option);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_STOP_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    char temp[2];
    temp[0] = 'A';
    temp[1] = '\0';
    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteCString(temp);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_STOP_DTMF, data, reply, option);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("ret StopDtmf failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::GetImsCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_IMS_CALL_LIST, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_GET_IMS_CALL_LIST, telRilRequest->serialId_);
}

int32_t TelRilCall::GetImsCallListResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<CallInfoList> callInfoList = std::make_shared<CallInfoList>();
    if (callInfoList == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfoList == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    callInfoList->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest --> pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, callInfoList);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_PREFERENCE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = SendInt32sEvent(HREQ_CALL_SET_CALL_PREFERENCE, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, mode);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return ret;
}

int32_t TelRilCall::SetCallPreferenceResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);

    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest --> pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_PREFERENCE, result);

    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = SendInt32Event(HREQ_CALL_GET_CALL_PREFERENCE, telRilRequest->serialId_);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetCallPreferenceResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> mode = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    *mode = data.ReadInt32();
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        TELEPHONY_LOGI("Execute to core_service : eventId = [%{public}d]", eventId);
        handler->SendEvent(eventId, mode);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetLteImsSwitchStatus(const int32_t active, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_LTEIMSSWITCH_STATUS, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret =
        SendInt32sEvent(HREQ_CALL_SET_LTEIMSSWITCH_STATUS, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, active);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetLteImsSwitchStatusResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);

    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest --> pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_LTEIMSSWITCH_STATUS, result);

    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = SendInt32Event(HREQ_CALL_GET_LTEIMSSWITCH_STATUS, telRilRequest->serialId_);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetLteImsSwitchStatusResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> active = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    *active = data.ReadInt32();
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest --> pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, active);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetUssd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_USSD, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        MessageParcel data;
        data.WriteInt32(slotId_);
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(str.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_SET_USSD, data, reply, option);
        TELEPHONY_LOGI("Send (ID:%{public}d) return: %{public}d", HREQ_CALL_SET_USSD, ret);
    } else {
        TELEPHONY_LOGE("ERROR : cellularRadio_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetUssdResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            result->error = radioResponseInfo->error;
            handler->SendEvent(eventId, result);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetUssd(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_USSD, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilManager GetUssd:telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_GET_USSD, telRilRequest->serialId_);
}

int32_t TelRilCall::GetUssdResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> cusd = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    *cusd = data.ReadInt32();
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, cusd);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::CallStateUpdated(MessageParcel &data)
{
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CALL_STATUS_INFO);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::CallImsServiceStatusNotice(MessageParcel &data)
{
    std::shared_ptr<CallImsServiceStatus> imsServiceStatusInfo = std::make_shared<CallImsServiceStatus>();
    if (imsServiceStatusInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : imsServiceStatusInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    imsServiceStatusInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CALL_IMS_SERVICE_STATUS, imsServiceStatusInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::CallUssdNotice(MessageParcel &data)
{
    std::shared_ptr<UssdNoticeInfo> ussdNoticeInfo = std::make_shared<UssdNoticeInfo>();
    if (ussdNoticeInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ussdNoticeInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    ussdNoticeInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CALL_USSD_NOTICE, ussdNoticeInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::CallSsNotice(MessageParcel &data)
{
    std::shared_ptr<SsNoticeInfo> ssNoticeInfo = std::make_shared<SsNoticeInfo>();
    if (ssNoticeInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ssNoticeInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    ssNoticeInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CALL_SS_NOTICE, ssNoticeInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::CallRingbackVoiceNotice(MessageParcel &data)
{
    return NotifyObserver<RingbackVoice>(RadioEvent::RADIO_CALL_RINGBACK_VOICE, data);
}

int32_t TelRilCall::SrvccStatusNotice(MessageParcel &data)
{
    return NotifyObserver<SrvccStatus>(RadioEvent::RADIO_CALL_SRVCC_STATUS, data);
}

int32_t TelRilCall::SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_MUTE, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        int32_t ret = SendInt32sEvent(HREQ_CALL_SET_MUTE, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, mute);
        TELEPHONY_LOGI("Send (ID:%{public}d) return: %{public}d", HREQ_CALL_SET_MUTE, ret);
    } else {
        TELEPHONY_LOGE("ERROR : cellularRadio_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetMuteResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            result->error = radioResponseInfo->error;
            handler->SendEvent(eventId, result);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetMute(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_MUTE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilManager GetMute :telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_GET_MUTE, telRilRequest->serialId_);
}

int32_t TelRilCall::GetMuteResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> mute = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    *mute = data.ReadInt32();
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, mute);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_EMERGENCY_LIST, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilManager GetEmergencyCallList :telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_GET_EMERGENCY_LIST, telRilRequest->serialId_);
}

int32_t TelRilCall::SetEmergencyCallList(std::vector<EmergencyCall>  &eccVec,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_LOGE("SetEmergencyCallList begin");
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_EMERGENCY_LIST, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE(" SetEmergencyCallList telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("SetEmergencyCallList %{public}s  cellularRadio_ == nullptr", __func__);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    EmergencyInfoList emergencyInfoList;
    emergencyInfoList.callSize = (int32_t)eccVec.size();
    emergencyInfoList.flag =  telRilRequest->serialId_;
    int index = 1;
    for (EmergencyCall ecc : eccVec) {
        EmergencyInfo emergencyInfo = {};
        emergencyInfo.index = index;
        emergencyInfo.total = eccVec.size();
        emergencyInfo.eccNum  = ecc.eccNum;
        emergencyInfo.category = static_cast<int32_t>(ecc.eccType);
        emergencyInfo.simpresent = static_cast<int32_t>(ecc.simpresent);
        emergencyInfo.mcc = ecc.mcc;
        emergencyInfo.abnormalService = static_cast<int32_t>(ecc.abnormalService);
        index++;
        emergencyInfoList.calls.push_back(emergencyInfo);
    }

    for (auto ecc : emergencyInfoList.calls) {
        TELEPHONY_LOGE("SetEmergencyCallList, data: eccNum %{public}s mcc %{public}s",
            ecc.eccNum.c_str(), ecc.mcc.c_str());
    }
    int32_t ret = SendBufferEvent(HREQ_CALL_SET_EMERGENCY_LIST, emergencyInfoList);
    TELEPHONY_LOGI("Send (ID:%{public}d) return: %{public}d", HREQ_CALL_SET_EMERGENCY_LIST, ret);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::SetEmergencyCallListResponse(MessageParcel &data)
{
    TELEPHONY_LOGE("SetEmergencyCallListResponse");
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            result->error = radioResponseInfo->error;
            handler->SendEvent(eventId, result);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetEmergencyCallListResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<EmergencyInfoList> emergencyCallList = std::make_shared<EmergencyInfoList>();
    if (emergencyCallList == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    emergencyCallList->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    emergencyCallList->flag = telRilRequest->pointer_->GetParam();
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, emergencyCallList);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_FAIL_REASON, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilManager GetCallFailReason:telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    return SendInt32Event(HREQ_CALL_GET_FAIL_REASON, telRilRequest->serialId_);
}

int32_t TelRilCall::GetCallFailReasonResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> callFail = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    *callFail = data.ReadInt32();
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, callFail);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilCall::CallEmergencyNotice(MessageParcel &data)
{
    std::shared_ptr<EmergencyInfoList> emergencyInfoList = std::make_shared<EmergencyInfoList>();
    if (emergencyInfoList == nullptr) {
        TELEPHONY_LOGE("ERROR : emergencyInfoList == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    emergencyInfoList->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CALL_EMERGENCY_NUMBER_REPORT, emergencyInfoList);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS