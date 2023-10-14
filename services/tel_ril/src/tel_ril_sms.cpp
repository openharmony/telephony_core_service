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

#include "core_service_hisysevent.h"
#include "hril_notification.h"
#include "hril_request.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
TelRilSms::TelRilSms(int32_t slotId, sptr<HDI::Ril::V1_2::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, rilInterface, observerHandler, handler)
{}

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

HDI::Ril::V1_1::GsmSmsMessageInfo TelRilSms::ConstructGsmSendSmsRequestLinkList(std::string &smsPdu, std::string &pdu)
{
    HDI::Ril::V1_1::GsmSmsMessageInfo msg;
    msg.smscPdu = smsPdu.empty() ? "" : smsPdu;
    msg.pdu = pdu.empty() ? "" : pdu;
    return msg;
}

OHOS::HDI::Ril::V1_1::SmsMessageIOInfo TelRilSms::ConstructSmsMessageIOInfoRequestLinkList(
    std::string &smsPdu, std::string &pdu)
{
    OHOS::HDI::Ril::V1_1::SmsMessageIOInfo msg;
    msg.smscPdu = smsPdu.empty() ? "" : smsPdu;
    msg.pdu = pdu.empty() ? "" : pdu;
    return msg;
}

int32_t TelRilSms::SendGsmSms(std::string &smsPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::GsmSmsMessageInfo gsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smsPdu, pdu);
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_SEND_GSM_SMS, &HDI::Ril::V1_1::IRil::SendGsmSms, gsmSmsMessageInfo);
}

int32_t TelRilSms::SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::SendCdmaSmsMessageInfo cdmaSmsMessageInfo = {};
    cdmaSmsMessageInfo.smscPdu = pdu;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_SEND_CDMA_SMS, &HDI::Ril::V1_1::IRil::SendCdmaSms,
        cdmaSmsMessageInfo);
}

int32_t TelRilSms::AddSimMessage(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::SmsMessageIOInfo mGsmSmsMessageInfo = ConstructSmsMessageIOInfoRequestLinkList(smscPdu, pdu);
    mGsmSmsMessageInfo.state = status;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_ADD_SIM_MESSAGE, &HDI::Ril::V1_1::IRil::AddSimMessage,
        mGsmSmsMessageInfo);
}

int32_t TelRilSms::DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_DEL_SIM_MESSAGE, &HDI::Ril::V1_1::IRil::DelSimMessage, gsmIndex);
}

int32_t TelRilSms::UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::SmsMessageIOInfo smsMessageIOInfo = ConstructSmsMessageIOInfoRequestLinkList(smscPdu, pdu);
    smsMessageIOInfo.index = gsmIndex;
    smsMessageIOInfo.state = state;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_UPDATE_SIM_MESSAGE,
        &HDI::Ril::V1_1::IRil::UpdateSimMessage, smsMessageIOInfo);
}

int32_t TelRilSms::SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::ServiceCenterAddress serCenterAddress;
    serCenterAddress.address = address;
    serCenterAddress.tosca = tosca;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_SET_SMSC_ADDR, &HDI::Ril::V1_1::IRil::SetSmscAddr,
        serCenterAddress);
}

int32_t TelRilSms::GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_GET_SMSC_ADDR, &HDI::Ril::V1_1::IRil::GetSmscAddr);
}

int32_t TelRilSms::GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_GET_CDMA_CB_CONFIG, &HDI::Ril::V1_1::IRil::GetCdmaCBConfig);
}

int32_t TelRilSms::SendSmsMoreMode(
    std::string &smscPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::GsmSmsMessageInfo gsmSmsMessageInfo = ConstructGsmSendSmsRequestLinkList(smscPdu, pdu);
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_SEND_SMS_MORE_MODE,
        &HDI::Ril::V1_1::IRil::SendSmsMoreMode, gsmSmsMessageInfo);
}

int32_t TelRilSms::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::ModeData mModeData;
    mModeData.result = success;
    mModeData.mode = cause;
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_SEND_SMS_ACK, &HDI::Ril::V1_1::IRil::SendSmsAck, mModeData);
}

int32_t TelRilSms::SetCBConfig(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::CBConfigInfo cellBroadcastInfo;
    cellBroadcastInfo.mode = mode;
    cellBroadcastInfo.mids = idList.empty() ? "" : idList;
    cellBroadcastInfo.dcss = dcsList.empty() ? "" : dcsList;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_SET_CB_CONFIG, &HDI::Ril::V1_1::IRil::SetCBConfig,
        cellBroadcastInfo);
}

int32_t TelRilSms::SetCdmaCBConfig(
    const CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::CdmaCBConfigInfoList iCdmaCBConfigInfoList;
    iCdmaCBConfigInfoList.size = cdmaCBConfigInfoList.size;
    for (auto &cdmaCBConfigInfo : cdmaCBConfigInfoList.list) {
        HDI::Ril::V1_1::CdmaCBConfigInfo iCdmaCBConfigInfo = {};
        iCdmaCBConfigInfo.service = cdmaCBConfigInfo.service;
        iCdmaCBConfigInfo.language = cdmaCBConfigInfo.language;
        iCdmaCBConfigInfo.checked = cdmaCBConfigInfo.checked;
        iCdmaCBConfigInfoList.list.push_back(iCdmaCBConfigInfo);
    }
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_SET_CDMA_CB_CONFIG,
        &HDI::Ril::V1_1::IRil::SetCdmaCBConfig, iCdmaCBConfigInfoList);
}

int32_t TelRilSms::GetCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_GET_CB_CONFIG, &HDI::Ril::V1_1::IRil::GetCBConfig);
}

int32_t TelRilSms::AddCdmaSimMessage(int32_t status, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::SmsMessageIOInfo mSmsMessageIOInfo = {};
    mSmsMessageIOInfo.state = status;
    mSmsMessageIOInfo.pdu = pdu;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_ADD_CDMA_SIM_MESSAGE,
        &HDI::Ril::V1_1::IRil::AddCdmaSimMessage, mSmsMessageIOInfo);
}

int32_t TelRilSms::DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_DEL_CDMA_SIM_MESSAGE,
        &HDI::Ril::V1_1::IRil::DelCdmaSimMessage, cdmaIndex);
}

int32_t TelRilSms::UpdateCdmaSimMessage(
    int32_t cdmaIndex, int32_t state, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::SmsMessageIOInfo smsMessageIOInfo = {};
    smsMessageIOInfo.index = cdmaIndex;
    smsMessageIOInfo.state = state;
    smsMessageIOInfo.pdu = pdu;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_SMS_UPDATE_CDMA_SIM_MESSAGE,
        &HDI::Ril::V1_1::IRil::UpdateCdmaSimMessage, smsMessageIOInfo);
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
        bytes[i / HEX_NUM_PER_BYTE] = ((hexCh1 << BIT_NUM_PER_HEX) | hexCh2);
        i += HEX_NUM_PER_BYTE;
    }
    return bytes;
}

int32_t TelRilSms::NewSmsNotify(const HDI::Ril::V1_1::SmsMessageInfo &iSmsMessageInfo)
{
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    if (smsMessageInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : smsMessageInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildSmsMessageInfo(smsMessageInfo, iSmsMessageInfo);
    return Notify<SmsMessageInfo>(TELEPHONY_LOG_FUNC_NAME, smsMessageInfo, RadioEvent::RADIO_GSM_SMS);
}

int32_t TelRilSms::NewCdmaSmsNotify(const HDI::Ril::V1_1::SmsMessageInfo &iSmsMessageInfo)
{
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    if (smsMessageInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : smsMessageInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildSmsMessageInfo(smsMessageInfo, iSmsMessageInfo);
    if (smsMessageInfo->pdu.empty()) {
        TELEPHONY_LOGI("pdu is empty");
    }
    return Notify<SmsMessageInfo>(TELEPHONY_LOG_FUNC_NAME, smsMessageInfo, RadioEvent::RADIO_CDMA_SMS);
}

int32_t TelRilSms::SmsStatusReportNotify(const HDI::Ril::V1_1::SmsMessageInfo &iSmsMessageInfo)
{
    std::shared_ptr<SmsMessageInfo> smsMessageInfo = std::make_shared<SmsMessageInfo>();
    if (smsMessageInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : smsMessageInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildSmsMessageInfo(smsMessageInfo, iSmsMessageInfo);
    return Notify<SmsMessageInfo>(TELEPHONY_LOG_FUNC_NAME, smsMessageInfo, RadioEvent::RADIO_SMS_STATUS);
}

int32_t TelRilSms::NewSmsStoredOnSimNotify(int32_t recordNumber, int32_t indicationType)
{
    TELEPHONY_LOGD("indicationType: %{public}d", indicationType);
    return Notify<int32_t>(
        TELEPHONY_LOG_FUNC_NAME, std::make_shared<int32_t>(recordNumber), RadioEvent::RADIO_SMS_ON_SIM);
}

int32_t TelRilSms::CBConfigNotify(const HDI::Ril::V1_1::CBConfigReportInfo &iCellBroadConfigReportInfo)
{
    std::shared_ptr<CBConfigReportInfo> cellBroadConfigReportInfo = std::make_shared<CBConfigReportInfo>();
    if (cellBroadConfigReportInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : cellBroadConfigReportInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildCBConfigReportInfo(cellBroadConfigReportInfo, iCellBroadConfigReportInfo);
    return Notify<CBConfigReportInfo>(
        TELEPHONY_LOG_FUNC_NAME, cellBroadConfigReportInfo, RadioEvent::RADIO_CELL_BROADCAST);
}

int32_t TelRilSms::SendGsmSmsResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::SendSmsResultInfo &iSendSmsResultInfo)
{
    return ResponseSendSms(responseInfo, iSendSmsResultInfo);
}

int32_t TelRilSms::SendCdmaSmsResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::SendSmsResultInfo &iSendSmsResultInfo)
{
    return ResponseSendSms(responseInfo, iSendSmsResultInfo);
}

int32_t TelRilSms::AddSimMessageResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::DelSimMessageResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::UpdateSimMessageResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::SetSmscAddrResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::GetSmscAddrResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::ServiceCenterAddress &iServiceCenterAddress)
{
    std::shared_ptr<ServiceCenterAddress> serCenterAddress = std::make_shared<ServiceCenterAddress>();
    if (serCenterAddress == nullptr) {
        TELEPHONY_LOGE("ERROR : serCenterAddress == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildServiceCenterAddress(serCenterAddress, iServiceCenterAddress);
    return Response<ServiceCenterAddress>(TELEPHONY_LOG_FUNC_NAME, responseInfo, serCenterAddress);
}

int32_t TelRilSms::GetCBConfigResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CBConfigInfo &iCellBroadcastInfo)
{
    std::shared_ptr<CBConfigInfo> cellBroadcastInfo = std::make_shared<CBConfigInfo>();
    if (cellBroadcastInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : cellBroadcastInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildCBConfigInfo(cellBroadcastInfo, iCellBroadcastInfo);
    return Response<CBConfigInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, cellBroadcastInfo);
}

int32_t TelRilSms::GetCdmaCBConfigResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CdmaCBConfigInfo &iCdmaCBConfigInfo)
{
    std::shared_ptr<CdmaCBConfigInfo> cdmaCBConfigInfo = std::make_shared<CdmaCBConfigInfo>();
    if (cdmaCBConfigInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :cdmaCBConfigInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildCdmaCBConfigInfo(cdmaCBConfigInfo, iCdmaCBConfigInfo);
    return Response<CdmaCBConfigInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, cdmaCBConfigInfo);
}

int32_t TelRilSms::SendSmsMoreModeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::SendSmsResultInfo &iSendSmsResultInfo)
{
    return ResponseSendSms(responseInfo, iSendSmsResultInfo);
}

int32_t TelRilSms::SendSmsAckResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::SetCBConfigResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::SetCdmaCBConfigResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::AddCdmaSimMessageResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::DelCdmaSimMessageResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSms::UpdateCdmaSimMessageResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

void TelRilSms::BuildSendSmsResultInfo(
    std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo, const HDI::Ril::V1_1::SendSmsResultInfo &iSendSmsResultInfo)
{
    sendSmsResultInfo->msgRef = iSendSmsResultInfo.msgRef;
    sendSmsResultInfo->pdu = iSendSmsResultInfo.pdu;
    sendSmsResultInfo->errCode = iSendSmsResultInfo.errCode;
}

void TelRilSms::BuildCBConfigInfo(
    std::shared_ptr<CBConfigInfo> cellBroadcastInfo, const HDI::Ril::V1_1::CBConfigInfo &iCellBroadcastInfo)
{
    cellBroadcastInfo->serial = iCellBroadcastInfo.serial;
    cellBroadcastInfo->mode = iCellBroadcastInfo.mode;
    cellBroadcastInfo->indicationType = iCellBroadcastInfo.indicationType;
    cellBroadcastInfo->mids = iCellBroadcastInfo.mids;
    cellBroadcastInfo->dcss = iCellBroadcastInfo.dcss;
}

void TelRilSms::BuildServiceCenterAddress(std::shared_ptr<ServiceCenterAddress> serCenterAddress,
    const HDI::Ril::V1_1::ServiceCenterAddress &iServiceCenterAddress)
{
    serCenterAddress->serial = iServiceCenterAddress.serial;
    serCenterAddress->tosca = iServiceCenterAddress.tosca;
    serCenterAddress->address = iServiceCenterAddress.address;
}

void TelRilSms::BuildCdmaCBConfigInfo(
    std::shared_ptr<CdmaCBConfigInfo> cdmaCBConfigInfo, const HDI::Ril::V1_1::CdmaCBConfigInfo &iCdmaCBConfigInfo)
{
    cdmaCBConfigInfo->service = iCdmaCBConfigInfo.service;
    cdmaCBConfigInfo->language = iCdmaCBConfigInfo.language;
    cdmaCBConfigInfo->checked = iCdmaCBConfigInfo.checked;
}

void TelRilSms::BuildSmsMessageInfo(
    std::shared_ptr<SmsMessageInfo> smsMessageInfo, const HDI::Ril::V1_1::SmsMessageInfo &iSmsMessageInfo)
{
    smsMessageInfo->indicationType = iSmsMessageInfo.indicationType;
    smsMessageInfo->size = iSmsMessageInfo.size;
    for (auto pduInfo : iSmsMessageInfo.pdu) {
        smsMessageInfo->pdu.push_back(pduInfo);
    }
}
void TelRilSms::BuildCBConfigReportInfo(std::shared_ptr<CBConfigReportInfo> cellBroadConfigReportInfo,
    const HDI::Ril::V1_1::CBConfigReportInfo &iCellBroadConfigReportInfo)
{
    cellBroadConfigReportInfo->indicationType = iCellBroadConfigReportInfo.indicationType;
    cellBroadConfigReportInfo->sn = iCellBroadConfigReportInfo.sn;
    cellBroadConfigReportInfo->mid = iCellBroadConfigReportInfo.mid;
    cellBroadConfigReportInfo->page = iCellBroadConfigReportInfo.page;
    cellBroadConfigReportInfo->pages = iCellBroadConfigReportInfo.pages;
    cellBroadConfigReportInfo->dcs = iCellBroadConfigReportInfo.dcs;
    cellBroadConfigReportInfo->data = iCellBroadConfigReportInfo.data;
    cellBroadConfigReportInfo->length = iCellBroadConfigReportInfo.length;
    cellBroadConfigReportInfo->pdu = iCellBroadConfigReportInfo.pdu;
}

int32_t TelRilSms::ResponseSendSms(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::SendSmsResultInfo &result)
{
    auto getDataFunc = [&result, this](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo = std::make_shared<SendSmsResultInfo>();
        this->BuildSendSmsResultInfo(sendSmsResultInfo, result);
        sendSmsResultInfo->flag = telRilRequest->pointer_->GetParam();
        return sendSmsResultInfo;
    };
    return Response<SendSmsResultInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, getDataFunc);
}
} // namespace Telephony
} // namespace OHOS
