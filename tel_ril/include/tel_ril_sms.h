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

    /**
     * @brief  Send Sms
     */
    void SendSms(std::string smsPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    /**
     * @brief  Storage Sms
     */
    void StorageSms(
        int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    /**
     * @brief  Delete Sms
     */
    void DeleteSms(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response);

    void UpdateSms(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
        const AppExecFwk::InnerEvent::Pointer &response);

    void GetSmsCenterAddress(const AppExecFwk::InnerEvent::Pointer &response);

    void SetSmsCenterAddress(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response);

    void SetCellBroadcast(
        int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response);

    uint8_t *ConvertHexStringToBytes(const void *response, size_t length);

    uint8_t ConvertHexCharToInt(uint8_t ch);

    /**
     * @brief Send Sms ExpectMore
     */
    void SendSmsMoreMode(std::string smsPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response);

    void SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response);

    /**
     * @brief  Construct GSM Sms  send message request link list
     * @return the value of  GsmSmsMessageInfo
     */
    GsmSmsMessageInfo ConstructGsmSendSmsRequestLinkList(std::string smsPdu, std::string pdu);

    SmsMessageIOInfo ConstructSmsMessageIOInfoRequestLinkList(std::string smsPdu, std::string pdu);

    /**
     * @brief Receive NewSms response
     *
     * @param data is HDF service callback message
     */
    void NewSmsNotify(MessageParcel &data);

    /**
     * @brief Report NewSms Status response
     *
     * @param data is HDF service callback message
     */
    void SmsStatusReportNotify(MessageParcel &data);

    /**
     * @brief Report NewSms Status response
     *
     * @param data is HDF service callback message
     */
    void NewSmsStoredOnSimNotify(MessageParcel &data);

    /**
     * @brief Cell Broadcast Notify response
     *
     * @param data is HDF service callback message
     */
    void CellBroadcastNotify(MessageParcel &data);

    /**
     * @brief Send SMS response
     *
     * @param data is HDF service callback message
     */
    void SendSmsResponse(MessageParcel &data);

    /**
     * @brief Storage SMS response
     *
     * @param data is HDF service callback message
     */
    void StorageSmsResponse(MessageParcel &data);

    /**
     * @brief Delete SMS response
     *
     * @param data is HDF service callback message
     */
    void DeleteSmsResponse(MessageParcel &data);

    /**
     * @brief Update SMS response
     *
     * @param data is HDF service callback message
     */
    void UpdateSmsResponse(MessageParcel &data);

    /**
     * @brief Set Sms Center Address response
     *
     * @param data is HDF service callback message
     */
    void SetSmsCenterAddressResponse(MessageParcel &data);

    /**
     * @brief Get Sms Center Address response
     *
     * @param data is HDF service callback message
     */
    void GetSmsCenterAddressResponse(MessageParcel &data);

    /**
     * @brief Set Cell Broadcast response
     *
     * @param data is HDF service callback message
     */
    void SetCellBroadcastResponse(MessageParcel &data);

    /**
     * @brief SSend SMS response, it is expected that there will be multiple SMS sent,
     * so keep MSG dependent protocol connection open.
     *
     * @param data is HDF service callback message
     */
    void SendSmsMoreModeResponse(MessageParcel &data);

    /**
     * @brief Sending ACK message response of newly received CDMA SMS
     *
     * @param data is HDF service callback message
     */
    void SendSmsAckResponse(MessageParcel &data);

    bool IsSmsRespOrNotify(uint32_t code);

    void ProcessSmsRespOrNotify(uint32_t code, MessageParcel &data);

private:
    bool IsSmsResponse(uint32_t code);
    bool IsSmsNotification(uint32_t code);
    void AddHandlerToMap();

private:
    using Func = void (TelRilSms::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_SMS_H
