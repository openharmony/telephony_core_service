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
    TelRilSms(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);
    ~TelRilSms() = default;

    uint8_t *ConvertHexStringToBytes(const uint8_t *hexString, size_t length);
    uint8_t ConvertHexCharToInt(uint8_t ch);
    bool IsSmsRespOrNotify(uint32_t code);
    void ProcessSmsRespOrNotify(uint32_t code, MessageParcel &data);

    void SendGsmSms(std::string &smsPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void AddSimMessage(
        int32_t status, std::string &smscPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response);
    void UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response);
    void SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response);
    void GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response);
    void SetCdmaCBConfig(
        CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response);
    void GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response);
    void SetCBConfig(
        int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response);
    void GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result);
    void SendSmsMoreMode(std::string &smsPdu, std::string &pdu, const AppExecFwk::InnerEvent::Pointer &response);
    void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response);
    void AddCdmaSimMessage(int32_t status, std::string &pdu,
        const AppExecFwk::InnerEvent::Pointer &response);
    void DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response);
    void UpdateCdmaSimMessage(int32_t cdmaIndex, int32_t state, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response);

    void SendGsmSmsResponse(MessageParcel &data);
    void SendCdmaSmsResponse(MessageParcel &data);
    void AddSimMessageResponse(MessageParcel &data);
    void DelSimMessageResponse(MessageParcel &data);
    void UpdateSimMessageResponse(MessageParcel &data);
    void SetSmscAddrResponse(MessageParcel &data);
    void GetSmscAddrResponse(MessageParcel &data);
    void SetCBConfigResponse(MessageParcel &data);
    void GetCBConfigResponse(MessageParcel &data);
    void GetCdmaCBConfigResponse(MessageParcel &data);
    void SetCdmaCBConfigResponse(MessageParcel &data);
    void SendSmsMoreModeResponse(MessageParcel &data);
    void SendSmsAckResponse(MessageParcel &data);
    void AddCdmaSimMessageResponse(MessageParcel &data);
    void DelCdmaSimMessageResponse(MessageParcel &data);
    void UpdateCdmaSimMessageResponse(MessageParcel &data);

    void NewSmsNotify(MessageParcel &data);
    void NewCdmaSmsNotify(MessageParcel &data);
    void SmsStatusReportNotify(MessageParcel &data);
    void NewSmsStoredOnSimNotify(MessageParcel &data);
    void CBConfigNotify(MessageParcel &data);

private:
    void AddHandlerToMap();
    bool IsSmsResponse(uint32_t code);
    bool IsSmsNotification(uint32_t code);
    GsmSmsMessageInfo ConstructGsmSendSmsRequestLinkList(std::string &smsPdu, std::string &pdu);
    SmsMessageIOInfo ConstructSmsMessageIOInfoRequestLinkList(std::string &smsPdu, std::string &pdu);

    using Func = void (TelRilSms::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_SMS_H
