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

#ifndef TEL_RIL_SMS_H
#define TEL_RIL_SMS_H

#include "hril_sms_parcel.h"
#include "tel_ril_base.h"

namespace OHOS {
namespace Telephony {
class TelRilSms : public TelRilBase {
public:
    TelRilSms(int32_t slotId, sptr<IRemoteObject> cellularRadio, sptr<HDI::Ril::V1_0::IRilInterface> rilInterface,
        std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler);
    ~TelRilSms() = default;

    uint8_t *ConvertHexStringToBytes(const uint8_t *hexString, size_t length);
    uint8_t ConvertHexCharToInt(uint8_t ch);
    bool IsSmsRespOrNotify(uint32_t code);

    int32_t SendGsmSms(std::string &smsPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t AddSimMessage(
        int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetCdmaCBConfig(
        CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetCBConfig(
        int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetCBConfig(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SendSmsMoreMode(std::string &smsPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t AddCdmaSimMessage(int32_t status, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UpdateCdmaSimMessage(
        int32_t cdmaIndex, int32_t state, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    int32_t SendGsmSmsResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISendSmsResultInfo &iSendSmsResultInfo);
    int32_t SendCdmaSmsResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISendSmsResultInfo &iSendSmsResultInfo);
    int32_t AddSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t DelSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t UpdateSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t SetSmscAddrResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t GetSmscAddrResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IServiceCenterAddress &iServiceCenterAddress);
    int32_t SetCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t GetCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICBConfigInfo &iCellBroadcastInfo);
    int32_t SetCdmaCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t GetCdmaCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICdmaCBConfigInfo &iCdmaCBConfigInfo);
    int32_t SendSmsMoreModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISendSmsResultInfo &iSendSmsResultInfo);
    int32_t SendSmsAckResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t AddCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t DelCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t UpdateCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);

    int32_t NewSmsNotify(const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo);
    int32_t NewCdmaSmsNotify(const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo);
    int32_t SmsStatusReportNotify(const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo);
    int32_t NewSmsStoredOnSimNotify(int32_t recordNumber, int32_t indicationType);
    int32_t CBConfigNotify(const HDI::Ril::V1_0::ICBConfigReportInfo &cellBroadConfigReportInfo);

private:
    bool IsSmsResponse(uint32_t code);
    bool IsSmsNotification(uint32_t code);
    HDI::Ril::V1_0::IGsmSmsMessageInfo ConstructGsmSendSmsRequestLinkList(std::string &smsPdu, std::string &pdu);
    OHOS::HDI::Ril::V1_0::ISmsMessageIOInfo ConstructSmsMessageIOInfoRequestLinkList(
        std::string &smsPdu, std::string &pdu);
    void BuildSendSmsResultInfo(std::shared_ptr<SendSmsResultInfo> sendSmsResultInfo,
        const HDI::Ril::V1_0::ISendSmsResultInfo &iSendSmsResultInfo);
    void BuildCBConfigInfo(
        std::shared_ptr<CBConfigInfo> cellBroadcastInfo, const HDI::Ril::V1_0::ICBConfigInfo &iCellBroadcastInfo);
    void BuildServiceCenterAddress(std::shared_ptr<ServiceCenterAddress> serCenterAddress,
        const HDI::Ril::V1_0::IServiceCenterAddress &iServiceCenterAddress);
    void BuildCdmaCBConfigInfo(
        std::shared_ptr<CdmaCBConfigInfo> cdmaCBConfigInfo, const HDI::Ril::V1_0::ICdmaCBConfigInfo &iCdmaCBConfigInfo);
    void BuildSmsMessageInfo(
        std::shared_ptr<SmsMessageInfo> smsMessageInfo, const HDI::Ril::V1_0::ISmsMessageInfo &iSmsMessageInfo);
    void BuildCBConfigReportInfo(std::shared_ptr<CBConfigReportInfo> cellBroadConfigReportInfo,
        const HDI::Ril::V1_0::ICBConfigReportInfo &iCellBroadConfigReportInfo);
    int32_t ResponseSendSms(
        const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ISendSmsResultInfo &result);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_SMS_H
