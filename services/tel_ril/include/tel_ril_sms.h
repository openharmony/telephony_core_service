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
    int32_t GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t SendSmsMoreMode(std::string &smsPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t AddCdmaSimMessage(int32_t status, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UpdateCdmaSimMessage(
        int32_t cdmaIndex, int32_t state, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    int32_t SendGsmSmsResponse(MessageParcel &data);
    int32_t SendCdmaSmsResponse(MessageParcel &data);
    int32_t AddSimMessageResponse(MessageParcel &data);
    int32_t DelSimMessageResponse(MessageParcel &data);
    int32_t UpdateSimMessageResponse(MessageParcel &data);
    int32_t SetSmscAddrResponse(MessageParcel &data);
    int32_t GetSmscAddrResponse(MessageParcel &data);
    int32_t SetCBConfigResponse(MessageParcel &data);
    int32_t GetCBConfigResponse(MessageParcel &data);
    int32_t GetCdmaCBConfigResponse(MessageParcel &data);
    int32_t SetCdmaCBConfigResponse(MessageParcel &data);
    int32_t SendSmsMoreModeResponse(MessageParcel &data);
    int32_t SendSmsAckResponse(MessageParcel &data);
    int32_t AddCdmaSimMessageResponse(MessageParcel &data);
    int32_t DelCdmaSimMessageResponse(MessageParcel &data);
    int32_t UpdateCdmaSimMessageResponse(MessageParcel &data);

    int32_t NewSmsNotify(MessageParcel &data);
    int32_t NewCdmaSmsNotify(MessageParcel &data);
    int32_t SmsStatusReportNotify(MessageParcel &data);
    int32_t NewSmsStoredOnSimNotify(MessageParcel &data);
    int32_t CBConfigNotify(MessageParcel &data);

private:
    void AddHandlerToMap();
    bool IsSmsResponse(uint32_t code);
    bool IsSmsNotification(uint32_t code);
    GsmSmsMessageInfo ConstructGsmSendSmsRequestLinkList(std::string &smsPdu, std::string &pdu);
    SmsMessageIOInfo ConstructSmsMessageIOInfoRequestLinkList(std::string &smsPdu, std::string &pdu);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_SMS_H
