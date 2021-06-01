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
#include "hril_modem_parcel.h"
#include "hril_data_parcel.h"

namespace OHOS {
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
}

TelRilCall::TelRilCall(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilCall::IsCallResponse(uint32_t code)
{
    return code >= HREQ_CALL_BASE && code < HREQ_SMS_BASE;
}

bool TelRilCall::IsCallNotification(uint32_t code)
{
    return code >= HNOTI_CALL_BASE && code < HNOTI_SMS_BASE;
}

bool TelRilCall::IsCallRespOrNotify(uint32_t code)
{
    return IsCallResponse(code) || IsCallNotification(code);
}

void TelRilCall::ProcessCallRespOrNotify(uint32_t code, OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG(
        "TelRilCall ProcessCallResponse code:%{public}d, GetDataSize:%{public}d", code, data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

void TelRilCall::CallStateUpdated(OHOS::MessageParcel &data)
{
    int32_t indicationType = data.ReadInt32();
    TELEPHONY_DEBUG_LOG("TelRilCall NewSmsNotify indicationType:%{public}d", indicationType);
    if (observerHandler_ != nullptr) {
        if (indicationType == static_cast<int>(HRilNotiType::HRIL_NOTIFICATION_ACK_NEED)) {
            SendRespOrNotiAck();
            TELEPHONY_DEBUG_LOG("Unsol response received; Sending ack to ril.cp");
        }
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CALL_STATE);
    }
}

void TelRilCall::AnswerResponse(OHOS::MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("TelRilCall AnswerResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "AnswerResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d,"
        " radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : AnswerResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilCall::GetCallListResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilCall GetCallListResponse -->");
    std::shared_ptr<CallInfoList> callInfo = std::make_shared<CallInfoList>();
    if (callInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : GetCallListResponse --> callInfo == nullptr !!!");
        return;
    }
    callInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("GetCallListResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        callInfo->flag = telRilRequest->pointer_->GetParam();
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : GetCallListResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, callInfo);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilCall::DialResponse(OHOS::MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("TelRilCall DialResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "DialResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d,"
        " radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : DialResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilCall::HangupResponse(OHOS::MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("TelRilCall HangupResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "HangupResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d, radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : HangupResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilCall::RejectResponse(OHOS::MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("TelRilCall RejectResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "RejectResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d,"
        " radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : RejectResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilCall::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("TelRilCall GetCallList -->");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_GET_CALL_LIST, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilCall GetCallList:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("TelRilCall GetCallList:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_CALL_GET_CALL_LIST, telRilRequest->serialId_);
    }
}

void TelRilCall::Dial(std::string address, int clirMode, UusInformation *uusInformation,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("TelRilCall::Dial --> ");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_DIAL, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilCall Dial:telRilRequest is nullptr");
            return;
        }
        OHOS::MessageParcel wData;
        DialInfo dialInfo;
        dialInfo.address = address;
        dialInfo.clir = clirMode;
        dialInfo.serial = telRilRequest->serialId_;
        dialInfo.Marshalling(wData);
        int32_t ret = SendBufferEvent(HREQ_CALL_DIAL, wData);
        TELEPHONY_INFO_LOG("HREQ_CALL_DIAL ret %{public}d", ret);
    }
}

void TelRilCall::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("TelRilCall::Reject -->");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_REJECT, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("RilManager Reject:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("Reject --> HREQ_CALL_REJECT:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_CALL_REJECT, telRilRequest->serialId_);
    }
}

void TelRilCall::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("TelRilCall Hangup  --> ");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_HANGUP, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilCall Hangup:telRilRequest is nullptr");
            return;
        }
        int status = 0;
        OHOS::MessageParcel data;
        OHOS::MessageParcel reply;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(gsmIndex);
        OHOS::MessageOption option;
        status = cellularRadio_->SendRequest(HREQ_CALL_HANGUP, data, reply, option);
    } else {
        TELEPHONY_ERR_LOG("Hangup  cellularRadio_ == nullptr");
    }
}

void TelRilCall::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("TelRilCall Answer  --> ");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_CALL_ANSWER, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilCall Answer:telRilRequest is nullptr");
            return;
        }
        int ret = SendInt32Event(HREQ_CALL_ANSWER, telRilRequest->serialId_);
        TELEPHONY_INFO_LOG("HREQ_CALL_ANSWER ret %{public}d", ret);
    }
}
} // namespace OHOS
