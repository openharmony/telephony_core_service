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
#include "sms_service_proxy.h"
#include <cstdlib>
namespace OHOS {
namespace SMS {
SmsServiceProxy::SmsServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ISmsServiceInterface>(impl) {}

void SmsServiceProxy::SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
    const std::u16string text, const sptr<ISendShortMessageCallback> &sendCallback,
    const sptr<IDeliveryShortMessageCallback> &deliverCallback)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    printf("SmsServiceProxy::RegisterCallBack SmsServiceProxy call start 1.\n");

    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        printf("SmsServiceProxy::RegisterCallBack write descriptor fail.\n");
    }

    dataParcel.WriteInt32(slotId);
    dataParcel.WriteString16(desAddr);
    dataParcel.WriteString16(scAddr);
    dataParcel.WriteString16(text);
    if (sendCallback != nullptr) {
        if (!dataParcel.WriteRemoteObject(sendCallback->AsObject().GetRefPtr())) {
            printf("write sendcallback fail\r\n");
        }
    }
    if (deliverCallback != nullptr) {
        if (!dataParcel.WriteRemoteObject(deliverCallback->AsObject().GetRefPtr())) {
            printf("write delivercalllback fail\r\n");
        }
    }
    printf("call  sms service proxy\r\n");
    Remote()->SendRequest(TEXT_BASED_SMS_DELIVERY, dataParcel, replyParcel, option);
};

void SmsServiceProxy::SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
    uint16_t port, const uint8_t *data, uint16_t dataLen, const sptr<ISendShortMessageCallback> &sendCallback,
    const sptr<IDeliveryShortMessageCallback> &deliverCallback)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;

    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        printf("SmsServiceProxy::RegisterCallBack write descriptor fail.\n");
    }

    dataParcel.WriteInt32(slotId);
    dataParcel.WriteString16(desAddr);
    dataParcel.WriteString16(scAddr);
    dataParcel.WriteInt16(port);
    if (sendCallback != nullptr) {
        if (!dataParcel.WriteRemoteObject(sendCallback->AsObject().GetRefPtr())) {
            printf("write sendcallback fail\r\n");
        }
    }
    if (deliverCallback != nullptr) {
        if (!dataParcel.WriteRemoteObject(deliverCallback->AsObject().GetRefPtr())) {
            printf("write delivercalllback fail\r\n");
        }
    }
    dataParcel.WriteInt16(dataLen);
    dataParcel.WriteRawData(data, dataLen);
    Remote()->SendRequest(DATA_BASED_SMS_DELIVERY, dataParcel, replyParcel, option);
};

bool SmsServiceDeathRecipient::gotDeathRecipient_ = false;

bool SmsServiceDeathRecipient::GotDeathRecipient()
{
    return gotDeathRecipient_;
}

void SmsServiceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    gotDeathRecipient_ = true;
}

SmsServiceDeathRecipient::SmsServiceDeathRecipient() {}

SmsServiceDeathRecipient::~SmsServiceDeathRecipient() {}
} // namespace SMS
} // namespace OHOS