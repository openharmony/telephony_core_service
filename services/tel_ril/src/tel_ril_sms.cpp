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

#include "hril_notification.h"
#include "hril_request.h"

namespace OHOS {
namespace Telephony {
void TelRilSms::AddHandlerToMap()
{
    // Response
    memberFuncMap_[HREQ_SMS_SEND_GSM_SMS] = &TelRilSms::SendGsmSmsResponse;
    memberFuncMap_[HREQ_SMS_SEND_CDMA_SMS] = &TelRilSms::SendCDMASmsResponse;
    memberFuncMap_[HREQ_SMS_ADD_SIM_MESSAGE] = &TelRilSms::AddSimMessageResponse;
    memberFuncMap_[HREQ_SMS_DEL_SIM_MESSAGE] = &TelRilSms::DelSimMessageResponse;
    memberFuncMap_[HREQ_SMS_UPDATE_SIM_MESSAGE] = &TelRilSms::UpdateSimMessageResponse;
    memberFuncMap_[HREQ_SMS_SEND_SMS_MORE_MODE] = &TelRilSms::SendSmsMoreModeResponse;
    memberFuncMap_[HREQ_SMS_SEND_SMS_ACK] = &TelRilSms::SendSmsAckResponse;
    memberFuncMap_[HREQ_SMS_SET_SMSC_ADDR] = &TelRilSms::SetSmscAddrResponse;
    memberFuncMap_[HREQ_SMS_GET_SMSC_ADDR] = &TelRilSms::GetSmscAddrResponse;
    memberFuncMap_[HREQ_SMS_SET_CB_CONFIG] = &TelRilSms::SetCBConfigResponse;
    memberFuncMap_[HREQ_SMS_GET_CB_CONFIG] = &TelRilSms::GetCBConfigResponse;
    memberFuncMap_[HREQ_SMS_GET_CDMA_CB_CONFIG] = &TelRilSms::GetCdmaCBConfigResponse;
    memberFuncMap_[HREQ_SMS_SET_CDMA_CB_CONFIG] = &TelRilSms::SetCdmaCBConfigResponse;
    // Notification
    memberFuncMap_[HNOTI_SMS_NEW_SMS] = &TelRilSms::NewSmsNotify;
    memberFuncMap_[HNOTI_SMS_STATUS_REPORT] = &TelRilSms::SmsStatusReportNotify;
    memberFuncMap_[HNOTI_SMS_NEW_SMS_STORED_ON_SIM] = &TelRilSms::NewSmsStoredOnSimNotify;
    memberFuncMap_[HNOTI_CB_CONFIG_REPORT] = &TelRilSms::CBConfigNotify;
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
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

GsmSmsMessageInfo TelRilSms::ConstructGsmSendSmsRequestLinkList(std::string &smsPdu, std::string &pdu)
{
    GsmSmsMessageInfo msg;
    msg.smscPdu = smsPdu.empty() ? "" : smsPdu;
    msg.pdu = pdu.empty() ? "" : pdu;
    return msg;
}

SmsMessageIOInfo TelRilSms::ConstructSmsMessageIOInfoRequestLinkList(std::string &smsPdu, std::string &pdu)
{
    SmsMessageIOInfo msg;
    msg.smscPdu = smsPdu.empty() ? "" : smsPdu;
    msg.pdu = pdu.empty() ? "" : pdu;
    return msg;
}

void TelRilSms::SendGsmSms(std::string &smsPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_GSM_SMS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        GsmSmsMessageInfo mGsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smsPdu, pdu);
        mGsmSmsMessageInfo.serial = telRilRequest->serialId_;
        mGsmSmsMessageInfo.Marshalling(data);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_SEND_GSM_SMS, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    }
}

void TelRilSms::SendCdmaSms(CdmaSmsMessageInfo &msg, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_CDMA_SMS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteUnpadBuffer(&msg, sizeof(CdmaSmsMessageInfo));
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_SEND_GSM_SMS, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    }
}

void TelRilSms::AddSimMessage(
    int32_t status, std::string &smscPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_ADD_SIM_MESSAGE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        SmsMessageIOInfo mGsmSmsMessageInfo = ConstructSmsMessageIOInfoRequestLinkList(smscPdu, pdu);
        mGsmSmsMessageInfo.serial = telRilRequest->serialId_;
        mGsmSmsMessageInfo.state = status;
        mGsmSmsMessageInfo.Marshalling(data);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_ADD_SIM_MESSAGE, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    }
}

void TelRilSms::DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_DEL_SIM_MESSAGE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }

        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(gsmIndex);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_DEL_SIM_MESSAGE, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    }
}

void TelRilSms::UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_ADD_SIM_MESSAGE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        SmsMessageIOInfo smsMessageIOInfo = ConstructSmsMessageIOInfoRequestLinkList(smscPdu, pdu);
        smsMessageIOInfo.serial = telRilRequest->serialId_;
        smsMessageIOInfo.index = gsmIndex;
        smsMessageIOInfo.state = state;
        smsMessageIOInfo.Marshalling(data);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_UPDATE_SIM_MESSAGE, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
    }
}

void TelRilSms::SetSmscAddr(
    int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SET_SMSC_ADDR, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        ServiceCenterAddress serCenterAddress;
        serCenterAddress.serial = telRilRequest->serialId_;
        serCenterAddress.address = address.empty() ? "" : address;
        serCenterAddress.tosca = tosca;
        serCenterAddress.Marshalling(data);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_SET_SMSC_ADDR, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
    }
}

void TelRilSms::GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_GET_SMSC_ADDR, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }

        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_GET_SMSC_ADDR, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    }
}

void TelRilSms::GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_SMS_GET_CDMA_CB_CONFIG, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }

        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_GET_CDMA_CB_CONFIG, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    }
}

void TelRilSms::SendSmsMoreMode(
    std::string &smscPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_MORE_MODE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        // Do not log function arg for privacy
        MessageParcel data;
        GsmSmsMessageInfo gsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smscPdu, pdu);
        gsmSmsMessageInfo.serial = telRilRequest->serialId_;
        if (!gsmSmsMessageInfo.Marshalling(data)) {
            TELEPHONY_LOGE("GsmSmsMessageInfo Marshalling.");
            return;
        }
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS_MORE_MODE, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    }
}

void TelRilSms::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_ACK, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
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
        if (cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS_ACK, wData, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    }
}

void TelRilSms::SetCBConfig(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SET_CB_CONFIG, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        // Do not log function arg for privacy
        MessageParcel data;
        CBConfigInfo cellBroadcastInfo;
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
        if (cellularRadio_->SendRequest(HREQ_SMS_SET_CB_CONFIG, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
    }
}

void TelRilSms::SetCdmaCBConfig(
    CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SET_CDMA_CB_CONFIG, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        // Do not log function arg for privacy
        MessageParcel data;
        if (!cdmaCBConfigInfoList.Marshalling(data)) {
            TELEPHONY_LOGE("cdmaCBConfigInfoList Marshalling.");
            return;
        }
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SMS_SET_CDMA_CB_CONFIG, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
    }
}

void TelRilSms::GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_GET_CB_CONFIG, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }

    SendInt32Event(HREQ_SMS_GET_CB_CONFIG, telRilRequest->serialId_);
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

uint8_t *TelRilSms::ConvertHexStringToBytes(const uint8_t *hexString, size_t length)
{
    const int32_t HEX_NUM_PER_BYTE = 2;
    const int32_t BIT_NUM_PER_HEX = 4;

    if (length % HEX_NUM_PER_BYTE != 0) {
        return nullptr;
    }
    int32_t len = length / HEX_NUM_PER_BYTE;
    if (len <= 0) {
        TELEPHONY_LOGE("hexString is null");
        return nullptr;
    }
    uint8_t *bytes = (uint8_t *)calloc(len, sizeof(uint8_t));
    if (bytes == nullptr) {
        TELEPHONY_LOGE("ConvertHexStringToBytes: cannot allocate memory for bytes string");
        return nullptr;
    }
    uint8_t *hexStr = (uint8_t *)hexString;
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
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    smsMessageInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_GSM_SMS, smsMessageInfo);
    }
}

void TelRilSms::SmsStatusReportNotify(MessageParcel &data)
{
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    smsMessageInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SMS_STATUS, smsMessageInfo);
    }
}

void TelRilSms::NewSmsStoredOnSimNotify(MessageParcel &data)
{
    int32_t recordNumber = data.ReadInt32();
    std::shared_ptr<int> recordNumbers = std::make_shared<int>(recordNumber);
    if (observerHandler_ != nullptr && recordNumbers != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SMS_ON_SIM, recordNumbers);
    }
}

void TelRilSms::CBConfigNotify(MessageParcel &data)
{
    std::shared_ptr<CBConfigReportInfo> cellBroadcastInfo = std::make_shared<CBConfigReportInfo>();
    cellBroadcastInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CELL_BROADCAST, cellBroadcastInfo);
    }
}

void TelRilSms::SendGsmSmsResponse(MessageParcel &data)
{
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    sendSmsResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, sendSmsResultInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::SendCDMASmsResponse(MessageParcel &data)
{
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    if (sendSmsResultInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :sendSmsResultInfo == nullptr !!!");
        return;
    }
    sendSmsResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
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
        if (radioResponseInfo->error == HRilErrType::NONE) {
            sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, sendSmsResultInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::AddSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::DelSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::UpdateSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::SetSmscAddrResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE(" telRilRequest->pointer_ is null");
    }
}

void TelRilSms::GetSmscAddrResponse(MessageParcel &data)
{
    std::shared_ptr<ServiceCenterAddress> serCenterAddress = std::make_shared<ServiceCenterAddress>();
    serCenterAddress->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, serCenterAddress);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::GetCBConfigResponse(MessageParcel &data)
{
    std::shared_ptr<CBConfigInfo> cellBroadcastInfo = std::make_shared<CBConfigInfo>();
    if (cellBroadcastInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :cellBroadcastInfo == nullptr !!!");
        return;
    }
    cellBroadcastInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, cellBroadcastInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
}

void TelRilSms::GetCdmaCBConfigResponse(MessageParcel &data)
{
    std::shared_ptr<CdmaCBConfigInfo> cdmaCBConfigInfo = std::make_shared<CdmaCBConfigInfo>();
    if (cdmaCBConfigInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :cellBroadcastInfo == nullptr !!!");
        return;
    }
    cdmaCBConfigInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, cdmaCBConfigInfo);
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
        TELEPHONY_LOGE("read Buffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
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
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr ||
        telRilRequest->pointer_->GetOwner() == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr !!!");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilSms::SetCBConfigResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr ||
        telRilRequest->pointer_->GetOwner() == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr !!!");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilSms::SetCdmaCBConfigResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr &&
        telRilRequest->pointer_->GetOwner() != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return;
        }
        if (radioResponseInfo->error == HRilErrType::NONE) {
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}
} // namespace Telephony
} // namespace OHOS