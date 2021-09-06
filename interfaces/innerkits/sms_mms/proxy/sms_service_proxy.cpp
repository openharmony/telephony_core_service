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

#include "parcel.h"

namespace OHOS {
namespace Telephony {
SmsServiceProxy::SmsServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ISmsServiceInterface>(impl) {}

void SmsServiceProxy::SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
    const std::u16string text, const sptr<ISendShortMessageCallback> &sendCallback,
    const sptr<IDeliveryShortMessageCallback> &deliverCallback)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return;
    }

    dataParcel.WriteInt32(slotId);
    dataParcel.WriteString16(desAddr);
    dataParcel.WriteString16(scAddr);
    dataParcel.WriteString16(text);
    if (sendCallback != nullptr) {
        dataParcel.WriteRemoteObject(sendCallback->AsObject().GetRefPtr());
    }
    if (deliverCallback != nullptr) {
        dataParcel.WriteRemoteObject(deliverCallback->AsObject().GetRefPtr());
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return;
    }
    remote->SendRequest(TEXT_BASED_SMS_DELIVERY, dataParcel, replyParcel, option);
};

void SmsServiceProxy::SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
    uint16_t port, const uint8_t *data, uint16_t dataLen, const sptr<ISendShortMessageCallback> &sendCallback,
    const sptr<IDeliveryShortMessageCallback> &deliverCallback)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return;
    }

    dataParcel.WriteInt32(slotId);
    dataParcel.WriteString16(desAddr);
    dataParcel.WriteString16(scAddr);
    dataParcel.WriteInt16(port);
    if (sendCallback != nullptr) {
        dataParcel.WriteRemoteObject(sendCallback->AsObject().GetRefPtr());
    }
    if (deliverCallback != nullptr) {
        dataParcel.WriteRemoteObject(deliverCallback->AsObject().GetRefPtr());
    }
    dataParcel.WriteInt16(dataLen);
    dataParcel.WriteRawData(data, dataLen);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return;
    }
    remote->SendRequest(DATA_BASED_SMS_DELIVERY, dataParcel, replyParcel, option);
};

bool SmsServiceProxy::SetSmscAddr(int32_t slotId, const std::u16string &scAddr)
{
    bool result = false;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteString16(scAddr);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(SET_SMSC_ADDRESS, dataParcel, replyParcel, option);
    return replyParcel.ReadBool();
}

std::u16string SmsServiceProxy::GetSmscAddr(int32_t slotId)
{
    std::u16string result;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    dataParcel.WriteInt32(slotId);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(GET_SMSC_ADDRESS, dataParcel, replyParcel, option);
    return replyParcel.ReadString16();
}

bool SmsServiceProxy::AddSimMessage(
    int32_t slotId, const std::u16string &smsc, const std::u16string &pdu, SimMessageStatus status)
{
    bool result = false;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteString16(smsc);
    dataParcel.WriteString16(pdu);
    dataParcel.WriteUint32(status);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(ADD_SIM_MESSAGE, dataParcel, replyParcel, option);
    return replyParcel.ReadBool();
}

bool SmsServiceProxy::DelSimMessage(int32_t slotId, uint32_t msgIndex)
{
    bool result = false;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteUint32(msgIndex);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(DEL_SIM_MESSAGE, dataParcel, replyParcel, option);
    return replyParcel.ReadBool();
}

bool SmsServiceProxy::UpdateSimMessage(int32_t slotId, uint32_t msgIndex, SimMessageStatus newStatus,
    const std::u16string &pdu, const std::u16string &smsc)
{
    bool result = false;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteUint32(msgIndex);
    dataParcel.WriteUint32(newStatus);
    dataParcel.WriteString16(pdu);
    dataParcel.WriteString16(smsc);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(UPDATE_SIM_MESSAGE, dataParcel, replyParcel, option);
    return replyParcel.ReadBool();
}

std::vector<ShortMessage> SmsServiceProxy::GetAllSimMessages(int32_t slotId)
{
    std::vector<ShortMessage> result;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    dataParcel.WriteInt32(slotId);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(GET_ALL_SIM_MESSAGE, dataParcel, replyParcel, option);

    int32_t resultLen = replyParcel.ReadInt32();
    for (int32_t i = 0; i < resultLen; i++) {
        result.emplace_back(ShortMessage::UnMarshalling(replyParcel));
    }
    return result;
}

bool SmsServiceProxy::SetCBConfig(
    int32_t slotId, bool enable, uint32_t fromMsgId, uint32_t toMsgId, uint8_t netType)
{
    bool result = false;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteBool(enable);
    dataParcel.WriteUint32(fromMsgId);
    dataParcel.WriteUint32(toMsgId);
    dataParcel.WriteUint8(netType);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(SET_CB_CONFIG, dataParcel, replyParcel, option);
    return replyParcel.ReadBool();
}

bool SmsServiceProxy::SetDefaultSmsSlotId(int32_t slotId)
{
    bool result = false;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    dataParcel.WriteInt32(slotId);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(SET_DEFAULT_SMS_SLOT_ID, dataParcel, replyParcel, option);
    return replyParcel.ReadBool();
}

int32_t SmsServiceProxy::GetDefaultSmsSlotId()
{
    int32_t result = -1;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option(MessageOption::TF_SYNC);
    if (!dataParcel.WriteInterfaceToken(SmsServiceProxy::GetDescriptor())) {
        return result;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return result;
    }
    remote->SendRequest(GET_DEFAULT_SMS_SLOT_ID, dataParcel, replyParcel, option);
    return replyParcel.ReadInt32();
}

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
} // namespace Telephony
} // namespace OHOS
