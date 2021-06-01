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
#include "tel_ril_sms.h"
#include "hdf_death_recipient.h"
#include "hril_modem_parcel.h"
#include "hril_sms_parcel.h"

namespace OHOS {
void TelRilSms::AddHandlerToMap()
{
    // Response
    memberFuncMap_[HREQ_SMS_SEND_SMS] = &TelRilSms::SendSmsResponse;
    memberFuncMap_[HREQ_SMS_SEND_SMS_MORE_MODE] = &TelRilSms::SendSmsMoreModeResponse;
    memberFuncMap_[HREQ_SMS_SEND_SMS_ACK] = &TelRilSms::SendSmsAckResponse;
    // Notification
    memberFuncMap_[HNOTI_SMS_NEW_SMS] = &TelRilSms::NewSmsNotify;
    memberFuncMap_[HNOTI_SMS_STATUS_REPORT] = &TelRilSms::SmsStatusReportNotify;
    memberFuncMap_[HNOTI_SMS_NEW_SMS_STORED_ON_SIM] = &TelRilSms::NewSmsStoredOnSimNotify;
}

TelRilSms::TelRilSms(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilSms::IsSmsResponse(uint32_t code)
{
    return code >= HREQ_SMS_BASE && code < HREQ_SIM_BASE;
}

bool TelRilSms::IsSmsNotification(uint32_t code)
{
    return code >= HNOTI_SMS_BASE && code < HNOTI_SIM_BASE;
}

bool TelRilSms::IsSmsRespOrNotify(uint32_t code)
{
    return IsSmsResponse(code) || IsSmsNotification(code);
}

void TelRilSms::ProcessSmsRespOrNotify(uint32_t code, OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG(
        "TelRilSms ProcessSmsRespOrNotify code:%{public}d, GetDataSize:%{public}d", code, data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

GsmSmsMessageInfo TelRilSms::ConstructGsmSendSmsRequestLinkList(std::string smscPdu, std::string pdu)
{
    GsmSmsMessageInfo msg;
    msg.smscPdu = smscPdu.empty() ? "" : smscPdu;
    msg.pdu = pdu.empty() ? "" : pdu;
    return msg;
}

void TelRilSms::SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilSms::SendSms:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("TelRilSms RilCmSendSMS:%{public}d", telRilRequest->serialId_);
        OHOS::MessageParcel data;
        GsmSmsMessageInfo mGsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smscPdu, pdu);
        mGsmSmsMessageInfo.serial = telRilRequest->serialId_;
        mGsmSmsMessageInfo.Marshalling(data);
        OHOS::MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS, data, reply, option);
        TELEPHONY_INFO_LOG("HREQ_SMS_SEND_SMS ret = %{public}d", ret);
    }
}

void TelRilSms::SendSmsMoreMode(
    std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_MORE_MODE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilSms::SendSmsMoreMode:telRilRequest is nullptr");
            return;
        }
        // Do not log function arg for privacy
        OHOS::MessageParcel data;
        GsmSmsMessageInfo gsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smscPdu, pdu);
        gsmSmsMessageInfo.serial = telRilRequest->serialId_;
        if (!gsmSmsMessageInfo.Marshalling(data)) {
            TELEPHONY_ERR_LOG("GsmSmsMessageInfo Marshalling.");
            return;
        }
        OHOS::MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS_MORE_MODE, data, reply, option);
        TELEPHONY_INFO_LOG("HREQ_SMS_SEND_SMS_MORE_MODE ret = %{public}d", ret);
    }
}

void TelRilSms::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("TelRilSms::SendSmsAck  cause: %{public}d, success: %{public}d", cause, success);
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_ACK, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("SendSmsAck:telRilRequest is nullptr");
            return;
        }
        OHOS::MessageParcel wData;
        UniInfo mUniversalInfo;
        mUniversalInfo.serial = telRilRequest->serialId_;
        mUniversalInfo.flag = success;
        mUniversalInfo.gsmIndex = cause;
        mUniversalInfo.Marshalling(wData);
        OHOS::MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS_ACK, wData, reply, option);
        TELEPHONY_INFO_LOG("HREQ_SMS_SEND_SMS_ACK ret %{public}d", ret);
    }
}

void TelRilSms::NewSmsNotify(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilSms::NewSmsNotify --> ");
    std::shared_ptr<SmsMessageInfo> smsMessage = std::make_shared<SmsMessageInfo>();
    if (smsMessage == nullptr) {
        TELEPHONY_INFO_LOG("NewSmsNotify smsMessage is nullptr");
        return;
    }
    smsMessage->ReadFromParcel(data);
    int32_t indicationType = smsMessage->indicationType;
    RilProcessIndication(indicationType);
    TELEPHONY_DEBUG_LOG("NewSmsNotify indicationType:%{public}d, size:%{public}d, PDU size:%{public}d",
        indicationType, smsMessage->size, smsMessage->pdu.size());
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_GSM_SMS, smsMessage);
    }
}

void TelRilSms::SmsStatusReportNotify(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilSms::SmsStatusReportNotify --> ");
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    if (smsMessageInfo == nullptr) {
        TELEPHONY_INFO_LOG("NewSmsNotify smsMessageInfo is nullptr");
        return;
    }
    smsMessageInfo->ReadFromParcel(data);
    int32_t indicationType = smsMessageInfo->indicationType;
    if (observerHandler_ != nullptr) {
        RilProcessIndication(indicationType);
    }
    TELEPHONY_DEBUG_LOG("SmsStatusReportNotify indicationType:%{public}d", indicationType);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SMS_STATUS, smsMessageInfo);
    }
}

void TelRilSms::NewSmsStoredOnSimNotify(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilSms::NewSmsStoredOnSimNotify --> ");
    int32_t recordNumber = data.ReadInt32();
    int32_t indicationType = data.ReadInt32();
    std::shared_ptr<int> recordNumbers = std::make_shared<int>(recordNumber);
    TELEPHONY_INFO_LOG("recordNumber:%{public}d", recordNumber);
    if (observerHandler_ != nullptr && recordNumbers != nullptr) {
        RilProcessIndication(indicationType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SMS_ON_SIM, recordNumbers);
    }
}

void TelRilSms::SendSmsResponse(OHOS::MessageParcel &data)
{
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    if (sendSmsResultInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : TelRilSms::SendSmsResponse --> sendSmsResultInfo == nullptr !!!");
        return;
    }
    sendSmsResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("TelRilSms::SendSmsResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "SendSmsResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d, "
        "radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_DEBUG_LOG("SendSmsResponse serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_,
        telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            TELEPHONY_DEBUG_LOG("SendSmsResponse GetParam start");
            sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
            TELEPHONY_DEBUG_LOG("SendSmsResponse flag:%{public}lld", telRilRequest->pointer_->GetParam());
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : SendSmsResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, sendSmsResultInfo);
            TELEPHONY_DEBUG_LOG("SendSmsResponse GetInnerEventId:%{public}d", eventId);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    } else {
        TELEPHONY_ERR_LOG("TelRilSms::SendSmsResponse telRilRequest->pointer_ is null");
    }
}

void TelRilSms::SendSmsMoreModeResponse(OHOS::MessageParcel &data)
{
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    if (sendSmsResultInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> data.ReadUnpadBuffer(readSpSize) failed !!!");
        return;
    }
    sendSmsResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("SendSmsMoreModeResponse --> read Buffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "SendSmsMoreModeResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d,"
        " radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, sendSmsResultInfo);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilSms::SendSmsAckResponse(OHOS::MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("SendSmsAckResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG("SendSmsAckResponse serial:%{public}d, error:%{public}d, type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            if (telRilRequest->pointer_ != nullptr && telRilRequest->pointer_->GetOwner() != nullptr) {
                const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler =
                    telRilRequest->pointer_->GetOwner();
                if (handler == nullptr) {
                    TELEPHONY_ERR_LOG("ERROR : TelRilSms::SendSmsAckResponse --> handler == nullptr !!!");
                    return;
                }
                uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
                handler->SendEvent(eventId);
            }
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}
} // namespace OHOS
