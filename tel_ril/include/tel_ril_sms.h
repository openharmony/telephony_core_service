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

#include <memory>
#include <map>
#include <unordered_map>
#include "observer_handler.h"
#include "telephony_log.h"
#include "tel_ril_base.h"
#include "i_tel_ril_manager.h"
#include "hril_sms_parcel.h"

namespace OHOS {
class TelRilSms : public TelRilBase {
public:
    TelRilSms(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);

    ~TelRilSms() = default;

    /**
     * @brief  Send Sms
     */
    void SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    /**
     * @brief Send Sms ExpectMore
     */
    void SendSmsMoreMode(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response);

    /**
     * @brief  Construct GSM Sms  send message request link list
     * @return the value of  GsmSmsMessageInfo
     */
    GsmSmsMessageInfo ConstructGsmSendSmsRequestLinkList(std::string smscPdu, std::string pdu);

    /**
     * @brief Receive NewSms response
     *
     * @param data is HDF service callback message
     */
    void NewSmsNotify(OHOS::MessageParcel &data);

    /**
     * @brief Report NewSms Status response
     *
     * @param data is HDF service callback message
     */
    void SmsStatusReportNotify(OHOS::MessageParcel &data);

    /**
     * @brief Stored NewSms To Sim response
     *
     * @param data is HDF service callback message
     */
    void NewSmsStoredOnSimNotify(OHOS::MessageParcel &data);

    /**
     * @brief Send SMS response
     *
     * @param data is HDF service callback message
     */
    void SendSmsResponse(OHOS::MessageParcel &data);

    /**
     * @brief SSend SMS response, it is expected that there will be multiple SMS sent,
     * so keep MSG dependent protocol connection open.
     *
     * @param data is HDF service callback message
     */
    void SendSmsMoreModeResponse(OHOS::MessageParcel &data);

    /**
     * @brief Sending ACK message response of newly received CDMA SMS
     *
     * @param data is HDF service callback message
     */
    void SendSmsAckResponse(OHOS::MessageParcel &data);

    bool IsSmsRespOrNotify(uint32_t code);

    void ProcessSmsRespOrNotify(uint32_t code, OHOS::MessageParcel &data);

private:
    bool IsSmsResponse(uint32_t code);
    bool IsSmsNotification(uint32_t code);
    void AddHandlerToMap();

private:
    using Func = void (TelRilSms::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace OHOS
#endif // TEL_RIL_SMS_H
