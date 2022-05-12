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
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
void TelRilSms::AddHandlerToMap()
{
    // Response
    memberFuncMap_[HREQ_SMS_SEND_GSM_SMS] = &TelRilSms::SendGsmSmsResponse;
    memberFuncMap_[HREQ_SMS_SEND_CDMA_SMS] = &TelRilSms::SendCdmaSmsResponse;
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
    memberFuncMap_[HREQ_SMS_ADD_CDMA_SIM_MESSAGE] = &TelRilSms::AddCdmaSimMessageResponse;
    memberFuncMap_[HREQ_SMS_DEL_CDMA_SIM_MESSAGE] = &TelRilSms::DelCdmaSimMessageResponse;
    memberFuncMap_[HREQ_SMS_UPDATE_CDMA_SIM_MESSAGE] = &TelRilSms::UpdateCdmaSimMessageResponse;

    // Notification
    memberFuncMap_[HNOTI_SMS_NEW_SMS] = &TelRilSms::NewSmsNotify;
    memberFuncMap_[HNOTI_SMS_NEW_CDMA_SMS] = &TelRilSms::NewCdmaSmsNotify;
    memberFuncMap_[HNOTI_SMS_STATUS_REPORT] = &TelRilSms::SmsStatusReportNotify;
    memberFuncMap_[HNOTI_SMS_NEW_SMS_STORED_ON_SIM] = &TelRilSms::NewSmsStoredOnSimNotify;
    memberFuncMap_[HNOTI_CB_CONFIG_REPORT] = &TelRilSms::CBConfigNotify;
}

TelRilSms::TelRilSms(int32_t slotId, sptr<IRemoteObject> cellularRadio,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, observerHandler, handler)
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

int32_t TelRilSms::SendGsmSms(std::string &smsPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_GSM_SMS, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    MessageParcel data;
    data.WriteInt32(slotId_);
    GsmSmsMessageInfo mGsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smsPdu, pdu);
    mGsmSmsMessageInfo.serial = telRilRequest->serialId_;
    mGsmSmsMessageInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_SEND_GSM_SMS, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_CDMA_SMS, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    SendCdmaSmsMessageInfo mCdmaSmsMessageInfo = {};
    MessageParcel data;
    data.WriteInt32(slotId_);
    mCdmaSmsMessageInfo.serial = telRilRequest->serialId_;
    mCdmaSmsMessageInfo.smscPdu = pdu;
    mCdmaSmsMessageInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_SEND_CDMA_SMS, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::AddSimMessage(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_ADD_SIM_MESSAGE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    MessageParcel data;
    data.WriteInt32(slotId_);
    SmsMessageIOInfo mGsmSmsMessageInfo = ConstructSmsMessageIOInfoRequestLinkList(smscPdu, pdu);
    mGsmSmsMessageInfo.serial = telRilRequest->serialId_;
    mGsmSmsMessageInfo.state = status;
    mGsmSmsMessageInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_ADD_SIM_MESSAGE, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_DEL_SIM_MESSAGE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);

    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(gsmIndex);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_DEL_SIM_MESSAGE, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_UPDATE_SIM_MESSAGE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    MessageParcel data;
    data.WriteInt32(slotId_);
    SmsMessageIOInfo smsMessageIOInfo = ConstructSmsMessageIOInfoRequestLinkList(smscPdu, pdu);
    smsMessageIOInfo.serial = telRilRequest->serialId_;
    smsMessageIOInfo.index = gsmIndex;
    smsMessageIOInfo.state = state;
    smsMessageIOInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_UPDATE_SIM_MESSAGE, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SET_SMSC_ADDR, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    MessageParcel data;
    data.WriteInt32(slotId_);
    ServiceCenterAddress serCenterAddress;
    serCenterAddress.serial = telRilRequest->serialId_;
    serCenterAddress.address = address.empty() ? "" : address;
    serCenterAddress.tosca = tosca;
    serCenterAddress.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_SET_SMSC_ADDR, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_GET_SMSC_ADDR, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);

    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_GET_SMSC_ADDR, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_GET_CDMA_CB_CONFIG, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);

    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_GET_CDMA_CB_CONFIG, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::SendSmsMoreMode(
    std::string &smscPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_MORE_MODE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    // Do not log function arg for privacy
    MessageParcel data;
    data.WriteInt32(slotId_);
    GsmSmsMessageInfo gsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smscPdu, pdu);
    gsmSmsMessageInfo.serial = telRilRequest->serialId_;
    if (!gsmSmsMessageInfo.Marshalling(data)) {
        TELEPHONY_LOGE("GsmSmsMessageInfo Marshalling.");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS_MORE_MODE, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SEND_SMS_ACK, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel wData;
    wData.WriteInt32(slotId_);
    ModeData mModeData;
    mModeData.serial = telRilRequest->serialId_;
    mModeData.result = success;
    mModeData.mode = cause;
    mModeData.Marshalling(wData);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_SEND_SMS_ACK, wData, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::SetCBConfig(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SET_CB_CONFIG, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    // Do not log function arg for privacy
    MessageParcel data;
    data.WriteInt32(slotId_);
    CBConfigInfo cellBroadcastInfo;
    cellBroadcastInfo.serial = telRilRequest->serialId_;
    cellBroadcastInfo.mode = mode;
    cellBroadcastInfo.mids = idList.empty() ? "" : idList;
    cellBroadcastInfo.dcss = dcsList.empty() ? "" : dcsList;
    if (!cellBroadcastInfo.Marshalling(data)) {
        TELEPHONY_LOGE("cellBroadcastInfo Marshalling.");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_SET_CB_CONFIG, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::SetCdmaCBConfig(
    CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_SET_CDMA_CB_CONFIG, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    // Do not log function arg for privacy
    MessageParcel data;
    data.WriteInt32(slotId_);
    if (!cdmaCBConfigInfoList.Marshalling(data)) {
        TELEPHONY_LOGE("cdmaCBConfigInfoList Marshalling.");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_SET_CDMA_CB_CONFIG, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_GET_CB_CONFIG, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    TELEPHONY_LOGI("HREQ_SMS_GET_CB_CONFIG:%{public}d", telRilRequest->serialId_);
    SendInt32Event(HREQ_SMS_GET_CB_CONFIG, telRilRequest->serialId_);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::AddCdmaSimMessage(int32_t status, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_ADD_CDMA_SIM_MESSAGE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    MessageParcel data;
    data.WriteInt32(slotId_);
    SmsMessageIOInfo mSmsMessageIOInfo = {};
    mSmsMessageIOInfo.serial = telRilRequest->serialId_;
    mSmsMessageIOInfo.state = status;
    mSmsMessageIOInfo.pdu = pdu;
    mSmsMessageIOInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_ADD_CDMA_SIM_MESSAGE, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_DEL_CDMA_SIM_MESSAGE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);

    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(cdmaIndex);

    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_DEL_CDMA_SIM_MESSAGE, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSms::UpdateCdmaSimMessage(
    int32_t cdmaIndex, int32_t state, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SMS_UPDATE_CDMA_SIM_MESSAGE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    MessageParcel data;
    data.WriteInt32(slotId_);
    SmsMessageIOInfo smsMessageIOInfo = {};
    smsMessageIOInfo.serial = telRilRequest->serialId_;
    smsMessageIOInfo.index = cdmaIndex;
    smsMessageIOInfo.state = state;
    smsMessageIOInfo.pdu = pdu;
    smsMessageIOInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SMS_UPDATE_CDMA_SIM_MESSAGE, data, reply, option)) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
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

    if (length % HEX_NUM_PER_BYTE) {
        return nullptr;
    }
    int32_t len = (int32_t)length / HEX_NUM_PER_BYTE;
    if (len <= 0) {
        TELEPHONY_LOGE("hexString is null");
        return nullptr;
    }
    uint8_t *bytes = (uint8_t *)malloc(len * sizeof(uint8_t));
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
        bytes[i / HEX_NUM_PER_BYTE] = (((uint32_t)hexCh1 << BIT_NUM_PER_HEX) | hexCh2);
        i += HEX_NUM_PER_BYTE;
    }
    return bytes;
}

int32_t TelRilSms::NewSmsNotify(MessageParcel &data)
{
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    smsMessageInfo->ReadFromParcel(data);
    int32_t indicationType = smsMessageInfo->indicationType;
    TELEPHONY_LOGI("indicationType:%{public}d, size:%{public}d, PDU size:%{public}zu", indicationType,
        smsMessageInfo->size, smsMessageInfo->pdu.size());
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_GSM_SMS, smsMessageInfo);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::NewCdmaSmsNotify(MessageParcel &data)
{
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    smsMessageInfo->ReadFromParcel(data);
    if (smsMessageInfo->pdu.empty()) {
        TELEPHONY_LOGE("NewCdmaSmsNotify readFromParcel fail");
    }
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CDMA_SMS, smsMessageInfo);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::SmsStatusReportNotify(MessageParcel &data)
{
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    smsMessageInfo->ReadFromParcel(data);
    int32_t indicationType = smsMessageInfo->indicationType;
    TELEPHONY_LOGI(" indicationType:%{public}d, size:%{public}d, PDU size:%{public}zu", indicationType,
        smsMessageInfo->size, smsMessageInfo->pdu.size());
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_SMS_STATUS, smsMessageInfo);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::NewSmsStoredOnSimNotify(MessageParcel &data)
{
    int32_t recordNumber = data.ReadInt32();
    int32_t indicationType = data.ReadInt32();
    std::shared_ptr<int32_t> recordNumbers = std::make_shared<int32_t>(recordNumber);
    TELEPHONY_LOGI("indicationType: %{public}d", indicationType);
    if (observerHandler_ != nullptr && recordNumbers != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_SMS_ON_SIM, recordNumbers);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::CBConfigNotify(MessageParcel &data)
{
    std::shared_ptr<CBConfigReportInfo> cellBroadcastInfo = std::make_shared<CBConfigReportInfo>();
    cellBroadcastInfo->ReadFromParcel(data);
    int32_t indicationType = cellBroadcastInfo->indicationType;
    TELEPHONY_LOGI("indicationType:%{public}d, data:%{public}s, dcs :%{public}s, pdu :%{public}s", indicationType,
        cellBroadcastInfo->data.c_str(), cellBroadcastInfo->dcs.c_str(), cellBroadcastInfo->pdu.c_str());
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CELL_BROADCAST, cellBroadcastInfo);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::SendGsmSmsResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    sendSmsResultInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI("serialId_:%{public}d, requestId_:%{public}d, msgRef:%{public}d,", telRilRequest->serialId_,
            telRilRequest->requestId_, sendSmsResultInfo->msgRef);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId, sendSmsResultInfo);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::SendCdmaSmsResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    if (sendSmsResultInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :sendSmsResultInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    sendSmsResultInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI("serialId_:%{public}d, requestId_:%{public}d, msgRef:%{public}d,", telRilRequest->serialId_,
            telRilRequest->requestId_, sendSmsResultInfo->msgRef);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId, sendSmsResultInfo);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::AddSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId);
            TELEPHONY_LOGI(" GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::DelSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d", eventId);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::UpdateSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::SetSmscAddrResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE(" telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::GetSmscAddrResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<ServiceCenterAddress> serCenterAddress = std::make_shared<ServiceCenterAddress>();
    serCenterAddress->ReadFromParcel(data);

    TELEPHONY_LOGI("ServiceCenterAddress->address:%{public}s, ServiceCenterAddress->tosca:%{public}d",
        serCenterAddress->address.c_str(), serCenterAddress->tosca);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId, serCenterAddress);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::GetCBConfigResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<CBConfigInfo> cellBroadcastInfo = std::make_shared<CBConfigInfo>();
    if (cellBroadcastInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :cellBroadcastInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    cellBroadcastInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId, cellBroadcastInfo);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::GetCdmaCBConfigResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<CdmaCBConfigInfo> cdmaCBConfigInfo = std::make_shared<CdmaCBConfigInfo>();
    if (cdmaCBConfigInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :cellBroadcastInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    cdmaCBConfigInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId, cdmaCBConfigInfo);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::SendSmsMoreModeResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read Buffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
    sendSmsResultInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d,radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId, sendSmsResultInfo);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::SendSmsAckResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("serial:%{public}d, error:%{public}d", radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr ||
        telRilRequest->pointer_->GetOwner() == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        int32_t ret = handler->SendEvent(eventId);
        TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
        return ret;
    } else {
        return ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

int32_t TelRilSms::SetCBConfigResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("serial:%{public}d, error:%{public}d", radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr ||
        telRilRequest->pointer_->GetOwner() == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        int32_t ret = handler->SendEvent(eventId);
        TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
        return ret;
    } else {
        return ErrorResponse(telRilRequest, *radioResponseInfo);
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::SetCdmaCBConfigResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("serial:%{public}d, error:%{public}d", radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr &&
        telRilRequest->pointer_->GetOwner() != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        if (radioResponseInfo->error == HRilErrType::NONE) {
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::AddCdmaSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::DelCdmaSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilSms::UpdateCdmaSimMessageResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI(
            "serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            int32_t ret = handler->SendEvent(eventId);
            TELEPHONY_LOGI("GetInnerEventId:%{public}d, ret=%{public}d", eventId, ret);
            return ret;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest->pointer_ is null");
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}
} // namespace Telephony
} // namespace OHOS