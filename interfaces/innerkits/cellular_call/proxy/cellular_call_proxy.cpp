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

#include "cellular_call_proxy.h"

namespace OHOS {
namespace Telephony {
int CellularCallProxy::Dial(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(DIAL, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::End(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return ERR_SYSTEM_INVOKE;
    }

    int error = Remote()->SendRequest(END, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::Reject(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(REJECT, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::Answer(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(ANSWER, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::Hold()
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(HOLD, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::Active()
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(ACTIVE, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::Swap()
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(SWAP, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback)
{
    if (callback == nullptr) {
        return ERR_PARAMETER_INVALID;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!data.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return ERR_SYSTEM_INVOKE;
    }

    int32_t error = Remote()->SendRequest(REGISTER_CALLBACK, data, reply, option);
    if (error == ERR_NONE) {
        return reply.ReadInt32();
    }
    return error;
}

int CellularCallProxy::UnRegisterCallManagerCallBack()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!data.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    int32_t error = Remote()->SendRequest(UNREGISTER_CALLBACK, data, reply, option);
    if (error == ERR_NONE) {
        return reply.ReadInt32();
    }
    return error;
}

int CellularCallProxy::IsUrgentCall(const std::string &phoneNum, int32_t slotId, int32_t &errorCode)
{
    MessageParcel in;
    MessageParcel out;
    MessageOption option;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteString(phoneNum)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(slotId)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(errorCode)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(URGENT_CALL, in, out, option);
    if (error == ERR_NONE) {
        error = out.ReadInt32();
        errorCode = out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::Join()
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(JOIN, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::Split(const std::string &splitString, int32_t index)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteString(splitString)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(index)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(SPLIT, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::CallSupplement(CallSupplementType type)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(type)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(CALL_SUPPLEMENT, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::InitiateDTMF(char cDTMFCode, const std::string &phoneNum)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteCString(&cDTMFCode)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteString(phoneNum)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(INITIATE_DTMF, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::CeaseDTMF(const std::string &phoneNum)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteString(phoneNum)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(CEASE_DTMF, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int CellularCallProxy::TransmitDTMF(char cDTMFCode, const std::string &phoneNum)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteCString(&cDTMFCode)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteString(phoneNum)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(TRANSMIT_DTMF, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::TransmitDTMFString(
    const std::string &dtmfCodeStr, const std::string &phoneNum, int32_t switchOn, int32_t switchOff)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteString(dtmfCodeStr)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteString(phoneNum)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(switchOn)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(switchOff)) {
        return ERR_SYSTEM_INVOKE;
    }
    int32_t error = Remote()->SendRequest(TRANSMIT_DTMF_STRING, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetCallTransfer(const CallTransferInfo &ctInfo, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&ctInfo, sizeof(CallTransferInfo))) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(slotId)) {
        return ERR_SYSTEM_INVOKE;
    }
    int32_t error = Remote()->SendRequest(SET_CALL_TRANSFER, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::InquireCallTransfer(CallTransferType type, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(type)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(slotId)) {
        return ERR_SYSTEM_INVOKE;
    }
    int32_t error = Remote()->SendRequest(INQUIRE_CALL_TRANSFER, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetCallWaiting(bool activate, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteBool(activate)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(slotId)) {
        return ERR_SYSTEM_INVOKE;
    }
    int32_t error = Remote()->SendRequest(SET_CALL_WAITING, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::InquireCallWaiting(int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(slotId)) {
        return ERR_SYSTEM_INVOKE;
    }
    int32_t error = Remote()->SendRequest(INQUIRE_CALL_WAITING, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetCallRestriction(const CallRestrictionInfo &crInfo, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&crInfo, sizeof(CallRestrictionInfo))) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(slotId)) {
        return ERR_SYSTEM_INVOKE;
    }
    int32_t error = Remote()->SendRequest(SET_CALL_RESTRICTION, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::InquireCallRestriction(CallRestrictionType facType, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(DATA_SIZE)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(facType)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(slotId)) {
        return ERR_SYSTEM_INVOKE;
    }
    int32_t error = Remote()->SendRequest(INQUIRE_CALL_RESTRICTION, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}
} // namespace Telephony
} // namespace OHOS