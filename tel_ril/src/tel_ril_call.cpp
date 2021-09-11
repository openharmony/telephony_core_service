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
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
void TelRilCall::AddHandlerToMap()
{
    // Notification
    memberFuncMap_[HNOTI_CALL_STATE_UPDATED] = &TelRilCall::CallStateUpdated;

    // Response
    memberFuncMap_[HREQ_CALL_GET_CALL_LIST] = &TelRilCall::GetCallListResponse;
    memberFuncMap_[HREQ_CALL_DIAL] = &TelRilCall::DialResponse;
    memberFuncMap_[HREQ_CALL_HANGUP] = &TelRilCall::HangupResponse;
    memberFuncMap_[HREQ_CALL_REJECT] = &TelRilCall::RejectResponse;
    memberFuncMap_[HREQ_CALL_ANSWER] = &TelRilCall::AnswerResponse;
    memberFuncMap_[HREQ_CALL_HOLD] = &TelRilCall::HoldResponse;
    memberFuncMap_[HREQ_CALL_ACTIVE] = &TelRilCall::ActiveResponse;
    memberFuncMap_[HREQ_CALL_SWAP] = &TelRilCall::SwapResponse;
    memberFuncMap_[HREQ_CALL_JOIN] = &TelRilCall::JoinResponse;
    memberFuncMap_[HREQ_CALL_SPLIT] = &TelRilCall::SplitResponse;
    memberFuncMap_[HREQ_CALL_SUPPLEMENT] = &TelRilCall::CallSupplementResponse;
    memberFuncMap_[HREQ_CALL_GET_CALL_WAIT] = &TelRilCall::GetCallWaitResponse;
    memberFuncMap_[HREQ_CALL_SET_CALL_WAIT] = &TelRilCall::SetCallWaitResponse;
    memberFuncMap_[HREQ_CALL_GET_CALL_FORWARDING] = &TelRilCall::GetCallForwardResponse;
    memberFuncMap_[HREQ_CALL_SET_CALL_FORWARDING] = &TelRilCall::SetCallForwardResponse;
    memberFuncMap_[HREQ_CALL_GET_CALL_RESTRICTION] = &TelRilCall::GetCallRestrictionResponse;
    memberFuncMap_[HREQ_CALL_SET_CALL_RESTRICTION] = &TelRilCall::SetCallRestrictionResponse;
    memberFuncMap_[HREQ_CALL_DEAL_CLIP] = &TelRilCall::GetClipResponse;
    memberFuncMap_[HREQ_CALL_SET_CLIP] = &TelRilCall::SetClipResponse;
    memberFuncMap_[HREQ_CALL_DEAL_CLIR] = &TelRilCall::GetClirResponse;
    memberFuncMap_[HREQ_CALL_SET_CLIR] = &TelRilCall::SetClirResponse;
    memberFuncMap_[HREQ_CALL_SEND_DTMF] = &TelRilCall::SendDtmfResponse;
    memberFuncMap_[HREQ_CALL_START_DTMF] = &TelRilCall::StartDtmfResponse;
    memberFuncMap_[HREQ_CALL_STOP_DTMF] = &TelRilCall::StopDtmfResponse;
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
    } else {
        TELEPHONY_LOGE("memberFuncMap_ not fund: %{public}d", code);
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
        TELEPHONY_LOGE("TelRilCall AnswerResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : AnswerResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("AnswerResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : AnswerResponse --> handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::HoldResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall HoldResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : HoldResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("HoldResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : HoldResponse --> handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::ActiveResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall ActiveResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ActiveResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("ActiveResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : ActiveResponse --> handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::SwapResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall SwapResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SwapResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("SwapResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : SwapResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("GetCallListResponse -->spBuffer == nullptr");
        return;
    }
    std::shared_ptr<CallInfoList> callInfo = std::make_shared<CallInfoList>();
    if (callInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetCallListResponse --> callInfo == nullptr !!!");
        return;
    }
    callInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetCallListResponse --> radioResponseInfo == nullptr !!!");
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
            TELEPHONY_LOGE("ERROR : GetCallListResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("ERROR : DialResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("DialResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }

    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : DialResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("ERROR : HangupResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("HangupResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : HangupResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("ERROR : RejectResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("RejectResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : RejectResponse --> handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::JoinResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall JoinResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : JoinResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("JoinResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : JoinResponse --> handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::SplitResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall SplitResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SplitResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("SplitResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : SplitResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("ERROR : CallSupplementResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "CallSupplementResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : CallSupplementResponse pointer is nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : CallSupplementResponse --> handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::GetCallWaitResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetCallWaitResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetCallWaitResponse --> radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<CallWaitResult> callWaitResult = std::make_shared<CallWaitResult>();
    callWaitResult->ReadFromParcel(data);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : GetCallWaitResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        TELEPHONY_LOGD("TelRilCall GetCallWaitResponse -->eventId: %{public}d", eventId);
        handler->SendEvent(eventId, callWaitResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::SetCallWaitResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall SetCallWaitResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetCallWaitResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "SetCallWaitResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : SetCallWaitResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::SetCallForwardResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall SetCallForwardResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetCallForwardResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "SetCallForwardResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr && telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ is nullptr !!!");
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : SetCallForwardResponse --> handler is nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    result->error = radioResponseInfo->error;
    handler->SendEvent(eventId, result);
}

void TelRilCall::GetCallForwardResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetCallForwardResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetCallForwardResponse --> radioResponseInfo == nullptr !!!");
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
        TELEPHONY_LOGE("ERROR : GetCallForwardResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("GetClipResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetClipResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<GetClipResult> getClipResult = std::make_shared<GetClipResult>();
    getClipResult->ReadFromParcel(data);

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : GetClipResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, getClipResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::SetClipResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("SetClipResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetClipResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : SetClipResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::GetClirResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetClirResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetClirResponse --> radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<GetClirResult> getClirResult = std::make_shared<GetClirResult>();
    getClirResult->ReadFromParcel(data);

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : GetClirResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, getClirResult);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::SetClirResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("SetClirResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetClirResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : SetClirResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        result->error = radioResponseInfo->error;
        handler->SendEvent(eventId, result);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::GetCallRestrictionResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall GetCallRestrictionResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetCallRestrictionResponse --> radioResponseInfo == nullptr !!!");
        return;
    }

    std::shared_ptr<CallRestrictionResult> result = std::make_shared<CallRestrictionResult>();
    result->ReadFromParcel(data);
    TELEPHONY_LOGD(
        "GetCallRestrictionResponse --> radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : GetCallRestrictionResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("TelRilCall SetCallRestrictionResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetCallRestrictionResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "SetCallRestrictionResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ is nullptr !!!");
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : SetCallForwardResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("SendDtmfResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SendDtmfResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SendDtmfResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::StartDtmfResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("StartDtmfResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : StartDtmfResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : StartDtmfResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::StopDtmfResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("StopDtmfResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : StopDtmfResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : StopDtmfResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilCall::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_LIST, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilCall GetCallList:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    TELEPHONY_LOGD("TelRilCall GetCallList:%{public}d", telRilRequest->serialId_);
    SendInt32Event(HREQ_CALL_GET_CALL_LIST, telRilRequest->serialId_);
}

void TelRilCall::Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_DIAL, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilCall Dial:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel wData;
    DialInfo dialInfo;
    dialInfo.address = address;
    dialInfo.clir = clirMode;
    dialInfo.serial = telRilRequest->serialId_;
    dialInfo.Marshalling(wData);
    int32_t ret = SendBufferEvent(HREQ_CALL_DIAL, wData);
    TELEPHONY_LOGD("HREQ_CALL_DIAL ret %{public}d", ret);
}

void TelRilCall::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_REJECT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager Reject:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    SendInt32Event(HREQ_CALL_REJECT, telRilRequest->serialId_);
}

void TelRilCall::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_HANGUP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilCall Hangup:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(gsmIndex);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_HANGUP, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function Hangup failed, error: %{public}d", ret);
    }
}

void TelRilCall::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_ANSWER, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilCall Answer:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    int ret = SendInt32Event(HREQ_CALL_ANSWER, telRilRequest->serialId_);
    TELEPHONY_LOGD("HREQ_CALL_ANSWER ret %{public}d", ret);
}

void TelRilCall::Hold(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_HOLD, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager Hold:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    TELEPHONY_LOGD("Hold --> HREQ_CALL_HOLD:%{public}d", telRilRequest->serialId_);
    SendInt32Event(HREQ_CALL_HOLD, telRilRequest->serialId_);
}

void TelRilCall::Active(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_ACTIVE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager Active:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    TELEPHONY_LOGD("Active --> HREQ_CALL_ACTIVE:%{public}d", telRilRequest->serialId_);
    SendInt32Event(HREQ_CALL_ACTIVE, telRilRequest->serialId_);
}

void TelRilCall::Swap(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SWAP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager Swap:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    TELEPHONY_LOGD("Swap --> HREQ_CALL_SWAP:%{public}d", telRilRequest->serialId_);
    SendInt32Event(HREQ_CALL_SWAP, telRilRequest->serialId_);
}

void TelRilCall::Join(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_JOIN, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilCall Join:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(callType);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_JOIN, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function Join failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetCallWait(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_WAIT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager GetCallWait:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    TELEPHONY_LOGD("GetCallWait --> HREQ_CALL_GET_CALL_WAIT:%{public}d", telRilRequest->serialId_);
    SendInt32Event(HREQ_CALL_GET_CALL_WAIT, telRilRequest->serialId_);
}

void TelRilCall::SetCallWait(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_WAIT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager SetCallWait:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    TELEPHONY_LOGD("SetCallWait --> HREQ_CALL_SET_CALL_WAIT:%{public}d", telRilRequest->serialId_);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(activate);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CALL_WAIT, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SetCallWait failed, error: %{public}d", ret);
    }
}

void TelRilCall::Split(int32_t nThCall, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SPLIT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilCall Split:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("Split  cellularRadio_ == nullptr");
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(nThCall);
    data.WriteInt32(callType);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SPLIT, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function Split failed, error: %{public}d", ret);
    }
}

void TelRilCall::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SUPPLEMENT, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("CallSupplement, telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("CallSupplement  cellularRadio_ == nullptr");
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(type);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SUPPLEMENT, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function CallSupplement failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetCallForward(int32_t reason, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_FORWARDING, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("GetCallForward telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(reason);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_GET_CALL_FORWARDING, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetCallForward failed, error: %{public}d", ret);
    }
}

void TelRilCall::SetCallForward(int32_t reason, int32_t mode, std::string number, int32_t classx,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_FORWARDING, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("SetCallForward telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("GetCallForward cellularRadio_ == nullptr");
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel wData;
    CallForwardSetInfo callForwardSetInfo;
    callForwardSetInfo.reason = reason;
    callForwardSetInfo.mode = mode;
    callForwardSetInfo.classx = classx;
    callForwardSetInfo.number = number;
    callForwardSetInfo.serial = telRilRequest->serialId_;
    callForwardSetInfo.Marshalling(wData);

    int32_t ret = SendBufferEvent(HREQ_CALL_SET_CALL_FORWARDING, wData);
    TELEPHONY_LOGD("HREQ_CALL_SET_CALL_FORWARDING ret %{public}d", ret);
}

void TelRilCall::GetClip(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_DEAL_CLIP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager GetClip:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    TELEPHONY_LOGD("GetClip --> HREQ_CALL_DEAL_CLIP:%{public}d", telRilRequest->serialId_);
    SendInt32Event(HREQ_CALL_DEAL_CLIP, telRilRequest->serialId_);
}

void TelRilCall::SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CLIP, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager SetClip:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(action);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CLIP, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SetClip failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetClir(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_DEAL_CLIR, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager GetClir:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    TELEPHONY_LOGD("GetCallRestriction --> HREQ_CALL_GET_CALL_RESTRICTION:%{public}d", telRilRequest->serialId_);
    SendInt32Event(HREQ_CALL_DEAL_CLIR, telRilRequest->serialId_);
}

void TelRilCall::SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CLIR, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager SetClir:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(action);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CLIR, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SetClir failed, error: %{public}d", ret);
    }
}

void TelRilCall::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_RESTRICTION, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager GetCallRestriction:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(fac.c_str());
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_GET_CALL_RESTRICTION, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetCallRestriction failed, error: %{public}d", ret);
    }
}

void TelRilCall::SetCallRestriction(
    std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SET_CALL_RESTRICTION, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager SetCallRestriction:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(mode);
    data.WriteCString(fac.c_str());
    data.WriteCString(password.c_str());
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SET_CALL_RESTRICTION, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SetCallRestriction failed, error: %{public}d", ret);
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
        TELEPHONY_LOGE("RilManager SendDtmf:telRilRequest is nullptr");
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteInt32(switchOn);
    data.WriteInt32(switchOff);
    data.WriteInt32(sDTMFCode.length());
    data.WriteCString(sDTMFCode.c_str());
    TELEPHONY_LOGD("TelRilCall::SendDtmf --> cDTMFCode %{public}s", sDTMFCode.c_str());
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SEND_DTMF, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SendDtmf failed, error: %{public}d", ret);
    }
}

void TelRilCall::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_SEND_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager SendDtmf:telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
    const int32_t stringLength = 1;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteInt32(1);
    data.WriteInt32(0);
    data.WriteInt32(stringLength);
    char temp[2];
    temp[0] = cDTMFCode;
    temp[1] = '\0';
    data.WriteCString(temp);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_SEND_DTMF, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SendDtmf failed, error: %{public}d", ret);
    }
}

void TelRilCall::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_START_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager StartDtmf:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    char temp[2];
    temp[0] = cDTMFCode;
    temp[1] = '\0';
    data.WriteCString(temp);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_START_DTMF, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function StartDtmf failed, error: %{public}d", ret);
    }
}

void TelRilCall::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_STOP_DTMF, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("RilManager StopDtmf:telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    char temp[2];
    temp[0] = 'A';
    temp[1] = '\0';
    data.WriteCString(temp);
    OHOS::MessageOption option;
    int ret = cellularRadio_->SendRequest(HREQ_CALL_STOP_DTMF, data, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function StopDtmf failed, error: %{public}d", ret);
    }
}
} // namespace Telephony
} // namespace OHOS
