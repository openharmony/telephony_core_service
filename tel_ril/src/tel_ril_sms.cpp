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

namespace OHOS {
namespace Telephony {
void TelRilSms::AddHandlerToMap()
{
    // Response
    memberFuncMap_[HREQ_SMS_SEND_SMS] = &TelRilSms::SendSmsResponse;
    memberFuncMap_[HREQ_SMS_STORAGE_SMS] = &TelRilSms::StorageSmsResponse;
    memberFuncMap_[HREQ_SMS_DELETE_SMS] = &TelRilSms::DeleteSmsResponse;
    memberFuncMap_[HREQ_SMS_UPDATE_SMS] = &TelRilSms::UpdateSmsResponse;
    memberFuncMap_[HREQ_SMS_SEND_SMS_MORE_MODE] = &TelRilSms::SendSmsMoreModeResponse;
    memberFuncMap_[HREQ_SMS_SEND_SMS_ACK] = &TelRilSms::SendSmsAckResponse;
    memberFuncMap_[HREQ_SMS_SET_CENTER_ADDRESS] = &TelRilSms::SetSmsCenterAddressResponse;
    memberFuncMap_[HREQ_SMS_GET_CENTER_ADDRESS] = &TelRilSms::GetSmsCenterAddressResponse;
    memberFuncMap_[HREQ_SMS_SET_CELL_BROADCAST] = &TelRilSms::SetCellBroadcastResponse;
    // Notification
    memberFuncMap_[HNOTI_SMS_NEW_SMS] = &TelRilSms::NewSmsNotify;
    memberFuncMap_[HNOTI_SMS_STATUS_REPORT] = &TelRilSms::SmsStatusReportNotify;
    memberFuncMap_[HNOTI_SMS_NEW_SMS_STORED_ON_SIM] = &TelRilSms::NewSmsStoredOnSimNotify;
    memberFuncMap_[HNOTI_CELL_BROADCAST_REPORT] = &TelRilSms::CellBroadcastNotify;
}

TelRilSms::TelRilSms(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilSms::IsSmsResponse(uint32_t code)
{
    return ((code >= HREQ_SMS_BASE) && (code < HREQ_SIM_BASE));
}

bool TelRilSms::IsSmsNotification(uint32_t code)
{
    return ((code >= HNOTI_SMS_BASE) && (code < HNOTI_SIM_BASE));
}

bool TelRilSms::IsSmsRespOrNotify(uint32_t code)
{
    return IsSmsResponse(code) || IsSmsNotification(code);
}

void TelRilSms::ProcessSmsRespOrNotify(uint32_t code, MessageParcel &data)
{
    TELEPHONY_LOGD(
        "TelRilSms ProcessSmsRespOrNotify code:%{public}d, GetDataSize:%{public}zu", code, data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

GsmSmsMessageInfo TelRilSms::ConstructGsmSendSmsRequestLinkList(std::string smsPdu, std::string pdu)
{
    GsmSmsMessageInfo msg = {};
    msg.smscPdu = smsPdu.empty() ? "" : smsPdu;
    msg.pdu = pdu.empty() ? "" : pdu;
    return msg;
}

SmsMessageIOInfo TelRilSms::ConstructSmsMessageIOInfoRequestLinkList(std::string smsPdu, std::string pdu)
{
    SmsMessageIOInfo msg = {};
    msg.smscPdu = smsPdu.empty() ? "" : smsPdu;
    msg.pdu = pdu.empty() ? "" : pdu;
    return msg;
}

void TelRilSms::SendSms(std::string smsPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSms::SendSms:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilSms RilCmSendSMS:%{public}d", telRilRequest->serialId_);
        MessageParcel data = {};
        GsmSmsMessageInfo mGsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smsPdu, pdu);
        mGsmSmsMessageInfo.serial = telRilRequest->serialId_;
        mGsmSmsMessageInfo.Marshalling(data);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS, data, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_SEND_SMS ret = %{public}d", ret);
        }
    }
}

void TelRilSms::StorageSms(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_STORAGE_SMS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSms::StorageSms:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilSms RilCmStorageSMS:%{public}d", telRilRequest->serialId_);
        MessageParcel data = {};
        SmsMessageIOInfo mGsmSmsMessageInfo = ConstructSmsMessageIOInfoRequestLinkList(smscPdu, pdu);
        mGsmSmsMessageInfo.serial = telRilRequest->serialId_;
        mGsmSmsMessageInfo.state = status;
        mGsmSmsMessageInfo.Marshalling(data);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_STORAGE_SMS, data, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_STORAGE_SMS ret = %{public}d", ret);
        }
    }
}

void TelRilSms::DeleteSms(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_DELETE_SMS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSms::DeleteSms:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilSms RilCmDeleteSMS:%{public}d", telRilRequest->serialId_);

        MessageParcel data = {};
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(gsmIndex);

        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_DELETE_SMS, data, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_DELETE_SMS ret = %{public}d", ret);
        }
    }
}

void TelRilSms::UpdateSms(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_STORAGE_SMS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSms::UpdateSms:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilSms RilCmUpdateSms:%{public}d", telRilRequest->serialId_);
        MessageParcel data = {};
        SmsMessageIOInfo smsMessageIOInfo = ConstructSmsMessageIOInfoRequestLinkList(smscPdu, pdu);
        smsMessageIOInfo.serial = telRilRequest->serialId_;
        smsMessageIOInfo.index = gsmIndex;
        smsMessageIOInfo.state = state;
        smsMessageIOInfo.Marshalling(data);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_UPDATE_SMS, data, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_UPDATE_SMS ret = %{public}d", ret);
        }
    } else {
        TELEPHONY_LOGE("TelRilSms::UpdateSms:cellularRadio_ is nullptr");
    }
}

void TelRilSms::SetSmsCenterAddress(
    int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SET_CENTER_ADDRESS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSms::SetSmsCenterAddress:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilSms RilCmSetSmsCenterAddress:%{public}d", telRilRequest->serialId_);
        MessageParcel data = {};
        ServiceCenterAddress serCenterAddress = {};
        serCenterAddress.serial = telRilRequest->serialId_;
        serCenterAddress.address = address.empty() ? "" : address;
        serCenterAddress.tosca = tosca;
        serCenterAddress.Marshalling(data);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_SET_CENTER_ADDRESS, data, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_SET_CENTER_ADDRESS ret = %{public}d", ret);
        }
    } else {
        TELEPHONY_LOGE("TelRilSms::SetSmsCenterAddress cellularRadio_ is nullptr");
    }
}

void TelRilSms::GetSmsCenterAddress(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_GET_CENTER_ADDRESS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSms::GetSmsCenterAddress:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilSms RilCmGetSmsCenterAddress:%{public}d", telRilRequest->serialId_);

        MessageParcel data = {};
        data.WriteInt32(telRilRequest->serialId_);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_GET_CENTER_ADDRESS, data, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_GET_CENTER_ADDRESS ret = %{public}d", ret);
        }
    }
}

void TelRilSms::SendSmsMoreMode(
    std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_MORE_MODE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSms::SendSmsMoreMode:telRilRequest is nullptr");
            return;
        }
        // Do not log function arg for privacy
        MessageParcel data = {};
        GsmSmsMessageInfo gsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smscPdu, pdu);
        gsmSmsMessageInfo.serial = telRilRequest->serialId_;
        if (!gsmSmsMessageInfo.Marshalling(data)) {
            TELEPHONY_LOGE("GsmSmsMessageInfo Marshalling.");
            return;
        }
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS_MORE_MODE, data, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_SEND_SMS_MORE_MODE ret = %{public}d", ret);
        }
    }
}

void TelRilSms::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGD("TelRilSms::SendSmsAck  cause: %{public}d, success: %{public}d", cause, success);
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_ACK, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("SendSmsAck:telRilRequest is nullptr");
            return;
        }
        MessageParcel wData;
        ModeData mModeData;
        mModeData.serial = telRilRequest->serialId_;
        mModeData.result = success;
        mModeData.mode = cause;
        mModeData.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS_ACK, wData, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_SEND_SMS_ACK ret = %{public}d", ret);
        }
    }
}

void TelRilSms::SetCellBroadcast(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_MORE_MODE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSms::SetCellBroadcast:telRilRequest is nullptr");
            return;
        }
        // Do not log function arg for privacy
        MessageParcel data = {};
        CellBroadcastInfo cellBroadcastInfo = {};
        cellBroadcastInfo.serial = telRilRequest->serialId_;
        cellBroadcastInfo.mode = mode;
        cellBroadcastInfo.mids = idList.empty() ? "" : idList;
        cellBroadcastInfo.dcss = dcsList.empty() ? "" : dcsList;
        if (!cellBroadcastInfo.Marshalling(data)) {
            TELEPHONY_LOGE("cellBroadcastInfo Marshalling.");
            return;
        }
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int32_t ret = cellularRadio_->SendRequest(HREQ_SMS_SET_CELL_BROADCAST, data, reply, option);
        if (ret != ERR_NONE) {
            TELEPHONY_LOGE("HREQ_SMS_SET_CELL_BROADCAST ret = %{public}d", ret);
        }
    } else {
        TELEPHONY_LOGE("TelRilSms::SetCellBroadcast:cellularRadio_ is nullptr");
    }
}

uint8_t TelRilSms::ConvertHexCharToInt(uint8_t ch)
{
    if ((ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
        return ((ch - 'A') % HRIL_UPPER_CASE_LETTERS_OFFSET + HRIL_DEC);
    } else if (ch >= '0' && ch <= '9') {
        return (ch - '0');
    } else {
        return HRIL_INVALID_HEX_CHAR;
    }
}

uint8_t *TelRilSms::ConvertHexStringToBytes(const void *response, size_t length)
{
    const int32_t HEX_NUM_PER_BYTE = 2;
    const int32_t BIT_NUM_PER_HEX = 4;

    if (length == 0 || length % HEX_NUM_PER_BYTE != 0) {
        return nullptr;
    }
    uint8_t *bytes = (uint8_t *)calloc(length / HEX_NUM_PER_BYTE, sizeof(uint8_t));
    if (bytes == nullptr) {
        TELEPHONY_LOGE("ConvertHexStringToBytes: cannot allocate memory for bytes string");
        return nullptr;
    }
    uint8_t *hexStr = (uint8_t *)response;
    size_t i = 0;
    while (i < length) {
        uint8_t hexCh1 = ConvertHexCharToInt(hexStr[i]);
        uint8_t hexCh2 = ConvertHexCharToInt(hexStr[i + 1]);
        if (hexCh1 == HRIL_INVALID_HEX_CHAR || hexCh2 == HRIL_INVALID_HEX_CHAR) {
            free(bytes);
            return nullptr;
        }
        bytes[i / HEX_NUM_PER_BYTE] = ((hexCh1 << BIT_NUM_PER_HEX) | hexCh2);
        i += HEX_NUM_PER_BYTE;
    }
    return bytes;
}

void TelRilSms::NewSmsNotify(MessageParcel &data)
{
    std::shared_ptr<SmsMessageInfo> smsMessage = std::make_shared<SmsMessageInfo>();
    smsMessage->ReadFromParcel(data);
    int32_t indicationType = smsMessage->indicationType;
    TELEPHONY_LOGD("NewSmsNotify indicationType:%{public}d, size:%{public}d, PDU size:%{public}zu", indicationType,
        smsMessage->size, smsMessage->pdu.size());
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_GSM_SMS, smsMessage);
    }
}

void TelRilSms::SmsStatusReportNotify(MessageParcel &data)
{
    std::shared_ptr<SmsMessageInfo> smsMessage = std::make_shared<SmsMessageInfo>();
    smsMessage->ReadFromParcel(data);
    int32_t indicationType = smsMessage->indicationType;
    TELEPHONY_LOGD("SmsStatusReportNotify indicationType:%{public}d, size:%{public}d, PDU size:%{public}zu",
        indicationType, smsMessage->size, smsMessage->pdu.size());
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SMS_STATUS, smsMessage);
    }
}

void TelRilSms::NewSmsStoredOnSimNotify(MessageParcel &data)
{
    int32_t recordNumber = data.ReadInt32();
    int32_t indicationType = data.ReadInt32();
    std::shared_ptr<int> recordNumbers = std::make_shared<int>(recordNumber);
    TELEPHONY_LOGD("func :%{public}s indicationType: %{public}d", __func__, indicationType);
    if (observerHandler_ != nullptr && recordNumbers != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SMS_ON_SIM, recordNumbers);
    }
}

void TelRilSms::CellBroadcastNotify(MessageParcel &data)
{
    std::shared_ptr<CellBroadcastReportInfo> cellBroadcastInfo = std::make_shared<CellBroadcastReportInfo>();
    cellBroadcastInfo->ReadFromParcel(data);
    int32_t indicationType = cellBroadcastInfo->indicationType;
    TELEPHONY_LOGD("indicationType:%{public}d, data:%{public}p, dcs :%{public}p, pdu :%{public}p", indicationType,
        cellBroadcastInfo->data.c_str(), cellBroadcastInfo->dcs.c_str(), cellBroadcastInfo->pdu.c_str());
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CELL_BROADCAST, cellBroadcastInfo);
    }
}

void TelRilSms::SendSmsResponse(MessageParcel &data)
{
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    sendSmsResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilSms::SendSmsResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "SendSmsResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGD("SendSmsResponse serialId_:%{public}d, requestId_:%{public}d, msgRef:%{public}d,",
        telRilRequest->serialId_, telRilRequest->requestId_, sendSmsResultInfo->msgRef);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            TELEPHONY_LOGD("SendSmsResponse GetParam start");
            sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SendSmsResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, sendSmsResultInfo);
            TELEPHONY_LOGD("SendSmsResponse GetInnerEventId:%{public}d", eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("TelRilSms::SendSmsResponse telRilRequest->pointer_ is null");
    }
}

void TelRilSms::StorageSmsResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilSms::StorageSmsResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "StorageSmsResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGD("StorageSmsResponse serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_,
        telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : StorageSmsResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
            TELEPHONY_LOGD("StorageSmsResponse GetInnerEventId:%{public}d", eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("TelRilSms::StorageSmsResponse telRilRequest->pointer_ is null");
    }
}

void TelRilSms::DeleteSmsResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilSms::DeleteSmsResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "DeleteSmsResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGD("DeleteSmsResponse serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_,
        telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : DeleteSmsResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
            TELEPHONY_LOGD("DeleteSmsResponse GetInnerEventId:%{public}d", eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("TelRilSms::DeleteSmsResponse telRilRequest->pointer_ is null");
    }
}

void TelRilSms::UpdateSmsResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilSms::UpdateSmsResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "UpdateSmsResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGD("UpdateSmsResponse serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_,
        telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : UpdateSmsResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
            TELEPHONY_LOGD("UpdateSmsResponse GetInnerEventId:%{public}d", eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("TelRilSms::UpdateSmsResponse telRilRequest->pointer_ is null");
    }
}

void TelRilSms::SetSmsCenterAddressResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("--> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "--> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGD(
        "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
            TELEPHONY_LOGD("message id:%{public}d", eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::GetSmsCenterAddressResponse(MessageParcel &data)
{
    std::shared_ptr<ServiceCenterAddress> serCenterAddress = std::make_shared<ServiceCenterAddress>();
    serCenterAddress->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("--> read spBuffer failed");
        return;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "--> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGD(
        "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, serCenterAddress);
            TELEPHONY_LOGD("message id:%{public}d", eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::SendSmsMoreModeResponse(MessageParcel &data)
{
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    sendSmsResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("SendSmsMoreModeResponse --> read Buffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "SendSmsMoreModeResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SendSmsMoreModeResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, sendSmsResultInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSms::SendSmsAckResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("SendSmsAckResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD("SendSmsAckResponse serial:%{public}d, error:%{public}d", radioResponseInfo->serial,
        radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr ||
        telRilRequest->pointer_->GetOwner() == nullptr) {
        TELEPHONY_LOGE("ERROR : TelRilSms::SendSmsAckResponse --> telRilRequest == nullptr !!!");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : TelRilSms::SendSmsAckResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilSms::SetCellBroadcastResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("SetCellBroadcastResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD("SetCellBroadcastResponse serial:%{public}d, error:%{public}d", radioResponseInfo->serial,
        radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr ||
        telRilRequest->pointer_->GetOwner() == nullptr) {
        TELEPHONY_LOGE("ERROR : TelRilSms::SetCellBroadcastResponse --> telRilRequest == nullptr !!!");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : TelRilSms::SetCellBroadcastResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}
} // namespace Telephony
} // namespace OHOS
