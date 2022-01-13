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

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
void TelRilCall::AddHandlerToMap()
{
    // Notification
    memberFuncMap_[HNOTI_CALL_STATE_UPDATED] = &TelRilCall::CallStateUpdated;
    memberFuncMap_[HNOTI_CALL_CRING_REPORT] = &TelRilCall::CallCringNotice;
    memberFuncMap_[HNOTI_CALL_WAITING_REPORT] = &TelRilCall::CallWaitingNotice;
    memberFuncMap_[HNOTI_CALL_CONNECT_REPORT] = &TelRilCall::CallConnectNotice;
    memberFuncMap_[HNOTI_CALL_END_REPORT] = &TelRilCall::CallEndNotice;
    memberFuncMap_[HNOTI_CALL_STATUS_INFO_REPORT] = &TelRilCall::CallStatusInfoNotice;
    memberFuncMap_[HNOTI_CALL_IMS_SERVICE_STATUS_REPORT] = &TelRilCall::CallImsServiceStatusNotice;
    memberFuncMap_[HNOTI_CALL_USSD_REPORT] = &TelRilCall::CallUssdCusdNotice;
    memberFuncMap_[HNOTI_CALL_RINGBACK_VOICE_REPORT] = &TelRilCall::CallRingbackVoiceNotice;
    memberFuncMap_[HNOTI_CALL_SRVCC_STATUS_REPORT] = &TelRilCall::SrvccStatusNotice;
    memberFuncMap_[HNOTI_CALL_EMERGENCY_NUMBER_REPORT] = &TelRilCall::CallEmergencyNotice;

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
    memberFuncMap_[HREQ_CALL_SET_USSD] = &TelRilCall::SetUssdCusdResponse;
    memberFuncMap_[HREQ_CALL_GET_USSD] = &TelRilCall::GetUssdCusdResponse;
    memberFuncMap_[HREQ_CALL_SET_MUTE] = &TelRilCall::SetMuteResponse;
    memberFuncMap_[HREQ_CALL_GET_MUTE] = &TelRilCall::GetMuteResponse;
    memberFuncMap_[HREQ_CALL_GET_EMERGENCY_LIST] = &TelRilCall::GetEmergencyCallListResponse;
    memberFuncMap_[HREQ_CALL_GET_FAIL_REASON] = &TelRilCall::GetCallFailReasonResponse;
}

TelRilCall::TelRilCall(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
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

void TelRilCall::ProcessCallRespOrNotify(uint32_t code, MessageParcel &data)
{
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

void TelRilCall::CallStateUpdated(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilCall observerHandler_ is null!!");
        return;
    }
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_STATE);
}

void TelRilCall::AnswerResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::HoldCallResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::UnHoldCallResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::SwitchCallResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall  read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::GetCallListResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    std::shared_ptr<CallInfoList> callInfo = std::make_shared<CallInfoList>();
    if (callInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return;
    }
    callInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    callInfo->flag = telRilRequest->pointer_->GetParam();
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, callInfo);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilCall::DialResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall DialResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }

    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::HangupResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall HangupResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::RejectResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall RejectResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::CombineConferenceResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall CombineConferenceResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::SeparateConferenceResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::CallSupplementResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall CallSupplementResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : CallSupplementResponse pointer is nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::GetCallWaitingResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<CallWaitResult> callWaitResult = std::make_shared<CallWaitResult>();
    callWaitResult->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, callWaitResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
    }
}

void TelRilCall::SetCallWaitingResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall SetCallWaitingResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :  radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR :  handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
    }
}

void TelRilCall::SetCallTransferInfoResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall SetCallTransferInfoResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr && telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ is nullptr !!!");
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::GetCallTransferInfoResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :  radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<CallForwardQueryResult> cFQueryResult = std::make_shared<CallForwardQueryResult>();
    cFQueryResult->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ is nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :  handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    handler->SendEvent(eventId, cFQueryResult);
}

void TelRilCall::GetClipResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<GetClipResult> getClipResult = std::make_shared<GetClipResult>();
    getClipResult->ReadFromParcel(data);

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, getClipResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
    }
}

void TelRilCall::SetClipResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
    }
}

void TelRilCall::GetClirResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<GetClirResult> getClirResult = std::make_shared<GetClirResult>();
    getClirResult->ReadFromParcel(data);

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, getClirResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
    }
}

void TelRilCall::SetClirResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
    }
}

void TelRilCall::GetCallRestrictionResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :  radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<CallRestrictionResult> result = std::make_shared<CallRestrictionResult>();
    result->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    handler->SendEvent(eventId, result);
}

void TelRilCall::SetCallRestrictionResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ is nullptr !!!");
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::SendDtmfResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }

    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::StartDtmfResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }

    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::StopDtmfResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }

    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_LIST, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    SendInt32Event(HREQ_CALL_GET_CALL_LIST, telRilRequest->serialId_);
}

void TelRilCall::Dial(const std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_DIAL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }
    MessageParcel wData = {};
    DialInfo dialInfo;
    dialInfo.address = address;
    dialInfo.clir = clirMode;
    dialInfo.serial = telRilRequest->serialId_;
    dialInfo.Marshalling(wData);
    int32_t ret = SendBufferEvent(HREQ_CALL_DIAL, wData);
    TELEPHONY_LOGI("SendBufferEvent(ID:%{public}d) return: %{public}d", HREQ_CALL_DIAL, ret);
}

void TelRilCall::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_REJECT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    SendInt32Event(HREQ_CALL_REJECT, telRilRequest->serialId_);
}

void TelRilCall::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_HANGUP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(gsmIndex);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_HANGUP, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_ANSWER, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    int ret = SendInt32Event(HREQ_CALL_ANSWER, telRilRequest->serialId_);
    TELEPHONY_LOGI("SendInt32Event(ID:%{public}d) return: %{public}d", HREQ_CALL_ANSWER, ret);
}

void TelRilCall::HoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_HOLD_CALL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    SendInt32Event(HREQ_CALL_HOLD_CALL, telRilRequest->serialId_);
}

void TelRilCall::UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_UNHOLD_CALL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    SendInt32Event(HREQ_CALL_UNHOLD_CALL, telRilRequest->serialId_);
}

void TelRilCall::SwitchCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SWITCH_CALL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    SendInt32Event(HREQ_CALL_SWITCH_CALL, telRilRequest->serialId_);
}

void TelRilCall::CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_COMBINE_CONFERENCE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(callType);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_COMBINE_CONFERENCE, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_WAITING, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    SendInt32Event(HREQ_CALL_GET_CALL_WAITING, telRilRequest->serialId_);
}

void TelRilCall::SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_WAITING, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(activate);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CALL_WAITING, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::SeparateConference(
    int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SEPARATE_CONFERENCE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ == nullptr");
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(callIndex);
    data.WriteInt32(callType);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SEPARATE_CONFERENCE, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_CALL_SUPPLEMENT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ == nullptr");
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(type);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_CALL_SUPPLEMENT, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetCallTransferInfo(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_TRANSFER_INFO, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(reason);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_GET_CALL_TRANSFER_INFO, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::SetCallTransferInfo(int32_t reason, int32_t mode, std::string number, int32_t classx,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_TRANSFER_INFO, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ == nullptr");
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel wData = {};
    CallForwardSetInfo callForwardSetInfo;
    callForwardSetInfo.reason = reason;
    callForwardSetInfo.mode = mode;
    callForwardSetInfo.classx = classx;
    callForwardSetInfo.number = number;
    callForwardSetInfo.serial = telRilRequest->serialId_;
    callForwardSetInfo.Marshalling(wData);

    int32_t ret = SendBufferEvent(HREQ_CALL_SET_CALL_TRANSFER_INFO, wData);
    TELEPHONY_LOGI("SendBufferEvent(ID:%{public}d) return: %{public}d", HREQ_CALL_SET_CALL_TRANSFER_INFO, ret);
}

void TelRilCall::GetClip(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CLIP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    SendInt32Event(HREQ_CALL_GET_CLIP, telRilRequest->serialId_);
}

void TelRilCall::SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CLIP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(action);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CLIP, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetClir(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CLIR, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    SendInt32Event(HREQ_CALL_GET_CLIR, telRilRequest->serialId_);
}

void TelRilCall::SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CLIR, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(action);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CLIR, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_RESTRICTION, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(fac.c_str());
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_GET_CALL_RESTRICTION, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::SetCallRestriction(
    std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_RESTRICTION, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(mode);
    data.WriteCString(fac.c_str());
    data.WriteCString(password.c_str());
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CALL_RESTRICTION, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("TelRilCall::SendDtmf cellularRadio_ == NULL !!!!");
        return;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SEND_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteInt32(switchOn);
    data.WriteInt32(switchOff);
    data.WriteInt32(sDTMFCode.length());
    data.WriteCString(sDTMFCode.c_str());
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SEND_DTMF, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SEND_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    char temp[2];
    temp[0] = cDTMFCode;
    temp[1] = '\0';
    const int32_t stringLength = 1;
    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteInt32(1);
    data.WriteInt32(0);
    data.WriteInt32(stringLength);
    data.WriteCString(temp);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SEND_DTMF, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_START_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    char temp[2];
    temp[0] = cDTMFCode;
    temp[1] = '\0';
    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteCString(temp);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_START_DTMF, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_STOP_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_GENERIC_FAILURE);
        return;
    }

    char temp[2];
    temp[0] = 'A';
    temp[1] = '\0';
    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteCString(temp);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_STOP_DTMF, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function StopDtmf failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetImsCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_IMS_CALL_LIST, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    SendInt32Event(HREQ_CALL_GET_IMS_CALL_LIST, telRilRequest->serialId_);
}

void TelRilCall::GetImsCallListResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<CallInfoList> callInfoList = std::make_shared<CallInfoList>();
    if (callInfoList == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfoList == nullptr !!!");
        return;
    }

    callInfoList->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest --> pointer_ == nullptr !!!");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, callInfoList);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilCall::SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_PREFERENCE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(mode);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    TELEPHONY_LOGI("mode = [%{public}d]", mode);
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CALL_PREFERENCE, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::SetCallPreferenceResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);

    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest --> pointer_ == nullptr !!!");
    }
}

void TelRilCall::GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_PREFERENCE, result);

    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_GET_CALL_PREFERENCE, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetCallPreferenceResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> mode = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    *mode = data.ReadInt32();
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        TELEPHONY_LOGI("Execute to core_service : eventId = [%{public}d]", eventId);
        handler->SendEvent(eventId, mode);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilCall::SetLteImsSwitchStatus(const int32_t active, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_LTEIMSSWITCH_STATUS, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(active);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_LTEIMSSWITCH_STATUS, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::SetLteImsSwitchStatusResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);

    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest --> pointer_ == nullptr !!!");
    }
}

void TelRilCall::GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_LTEIMSSWITCH_STATUS, result);

    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data = {};
    MessageParcel reply = {};
    data.WriteInt32(telRilRequest->serialId_);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_CALL_GET_LTEIMSSWITCH_STATUS, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetLteImsSwitchStatusResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> active = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }

    *active = data.ReadInt32();
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest --> pointer_ == nullptr !!!");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, active);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilCall::SetUssdCusd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_USSD, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(str.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_SET_USSD, data, reply, option);
        TELEPHONY_LOGI("SendBufferEvent(ID:%{public}d) return: %{public}d", HREQ_CALL_SET_USSD, ret);
    } else {
        TELEPHONY_LOGE("ERROR : cellularRadio_ == nullptr !!!");
    }
}

void TelRilCall::SetUssdCusdResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
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
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            result->error = radioResponseInfo->error;
            handler->SendEvent(eventId, result);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
    }
}

void TelRilCall::GetUssdCusd(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_USSD, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilManager GetImsCallList:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    SendInt32Event(HREQ_CALL_GET_USSD, telRilRequest->serialId_);
}

void TelRilCall::GetUssdCusdResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> cusd = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
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
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, cusd);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
    }
}

void TelRilCall::CallCringNotice(MessageParcel &data)
{
    std::shared_ptr<CallCringInfo> cringInfo = std::make_shared<CallCringInfo>();
    if (cringInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : cringInfo == nullptr !!!");
        return;
    }
    cringInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_CRING, cringInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
    }
}

void TelRilCall::CallWaitingNotice(MessageParcel &data)
{
    std::shared_ptr<CallWaitInfo> waitInfo = std::make_shared<CallWaitInfo>();
    if (waitInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : waitInfo == nullptr !!!");
        return;
    }
    waitInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_WAITING, waitInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
    }
}

void TelRilCall::CallConnectNotice(MessageParcel &data)
{
    std::shared_ptr<CallConnectInfo> connectInfo = std::make_shared<CallConnectInfo>();
    if (connectInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : connectInfo == nullptr !!!");
        return;
    }
    connectInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_CONNECT, connectInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
    }
}

void TelRilCall::CallEndNotice(MessageParcel &data)
{
    std::shared_ptr<CallEndInfo> endInfo = std::make_shared<CallEndInfo>();
    if (endInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : endInfo == nullptr !!!");
        return;
    }
    endInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_END, endInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
    }
}

void TelRilCall::CallStatusInfoNotice(MessageParcel &data)
{
    std::shared_ptr<CallStatusInfo> statusInfo = std::make_shared<CallStatusInfo>();
    if (statusInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : statusInfo == nullptr !!!");
        return;
    }
    statusInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_STATUS_INFO, statusInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
    }
}

void TelRilCall::CallImsServiceStatusNotice(MessageParcel &data)
{
    std::shared_ptr<CallImsServiceStatus> imsServiceStatusInfo = std::make_shared<CallImsServiceStatus>();
    if (imsServiceStatusInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : imsServiceStatusInfo == nullptr !!!");
        return;
    }
    imsServiceStatusInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_IMS_SERVICE_STATUS, imsServiceStatusInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
    }
}

void TelRilCall::CallUssdCusdNotice(MessageParcel &data)
{
    std::shared_ptr<UssdCusdNoticeInfo> ussdCusdNoticeInfo = std::make_shared<UssdCusdNoticeInfo>();
    if (ussdCusdNoticeInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ussdCusdNoticeInfo == nullptr !!!");
        return;
    }
    ussdCusdNoticeInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_USSD_CUSD_NOTICE, ussdCusdNoticeInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
    }
}

void TelRilCall::CallRingbackVoiceNotice(MessageParcel &data)
{
    NotifyObserver<RingbackVoice>(ObserverHandler::RADIO_CALL_RINGBACK_VOICE, data);
}

void TelRilCall::SrvccStatusNotice(MessageParcel &data)
{
    NotifyObserver<SrvccStatus>(ObserverHandler::RADIO_CALL_SRVCC_STATUS, data);
}

void TelRilCall::SetMute(const int32_t mute, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_MUTE, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(mute);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_CALL_SET_MUTE, data, reply, option);
        TELEPHONY_LOGI("SendBufferEvent(ID:%{public}d) return: %{public}d", HREQ_CALL_SET_MUTE, ret);
    } else {
        TELEPHONY_LOGE("ERROR : cellularRadio_ == nullptr !!!");
    }
}

void TelRilCall::SetMuteResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
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
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            result->error = radioResponseInfo->error;
            handler->SendEvent(eventId, result);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
    }
}

void TelRilCall::GetMute(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_MUTE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilManager GetImsCallList:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    SendInt32Event(HREQ_CALL_GET_MUTE, telRilRequest->serialId_);
}

void TelRilCall::GetMuteResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> mute = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
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
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, mute);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
    }
}

void TelRilCall::GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_EMERGENCY_LIST, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilManager GetImsCallList:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    SendInt32Event(HREQ_CALL_GET_EMERGENCY_LIST, telRilRequest->serialId_);
}

void TelRilCall::GetEmergencyCallListResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    std::shared_ptr<EmergencyInfoList> emergencyCallList = std::make_shared<EmergencyInfoList>();
    if (emergencyCallList == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return;
    }
    emergencyCallList->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    emergencyCallList->flag = telRilRequest->pointer_->GetParam();
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, emergencyCallList);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilCall::GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_FAIL_REASON, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilManager GetImsCallList:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    SendInt32Event(HREQ_CALL_GET_FAIL_REASON, telRilRequest->serialId_);
}

void TelRilCall::GetCallFailReasonResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> callFail = std::make_shared<int32_t>();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
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
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, callFail);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
    }
}

void TelRilCall::CallEmergencyNotice(MessageParcel &data)
{
    std::shared_ptr<Emergencyinfo> emergencyInfo = std::make_shared<Emergencyinfo>();
    if (emergencyInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ussdCusdNoticeInfo == nullptr !!!");
        return;
    }
    emergencyInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_EMERGENCY_NUMBER_REPORT, emergencyInfo);
    } else {
        TELEPHONY_LOGE("ERROR : observerHandler_ == nullptr !!!");
    }
}
} // namespace Telephony
} // namespace OHOS
