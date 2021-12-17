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
int32_t CellularCallProxy::Dial(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::DIAL), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::HangUp(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::HANG_UP), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::Reject(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::REJECT), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::Answer(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::ANSWER), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::HoldCall(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::HOLD_CALL), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::UnHoldCall(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::UN_HOLD_CALL), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SwitchCall(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::SWITCH_CALL), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::RegisterCallManagerCallBack(const sptr<ICallStatusCallback> &callback)
{
    if (callback == nullptr) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::REGISTER_CALLBACK), data, reply, option);
    if (error == ERR_NONE) {
        return reply.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::UnRegisterCallManagerCallBack()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!data.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::UNREGISTER_CALLBACK), data, reply, option);
    if (error == ERR_NONE) {
        return reply.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::IsEmergencyPhoneNumber(const std::string &phoneNum, int32_t slotId, int32_t &errorCode)
{
    MessageParcel in;
    MessageParcel out;
    MessageOption option;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(phoneNum)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(errorCode)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t ret = Remote()->SendRequest(static_cast<uint32_t>(OperationType::EMERGENCY_CALL), in, out, option);
    if (ret == ERR_NONE) {
        ret = out.ReadInt32();
        errorCode = out.ReadInt32();
    }
    return ret;
}

int32_t CellularCallProxy::CombineConference(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::COMBINE_CONFERENCE), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SeparateConference(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::SEPARATE_CONFERENCE), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::CallSupplement(CallSupplementType type)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(type)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::CALL_SUPPLEMENT), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::StartDtmf(char cDtmfCode, const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteCString(&cDtmfCode)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::START_DTMF), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::StopDtmf(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::STOP_DTMF), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SendDtmf(char cDtmfCode, const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteCString(&cDtmfCode)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::SEND_DTMF), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SendDtmfString(
    const std::string &dtmfCodeStr, const std::string &phoneNum, int32_t switchOn, int32_t switchOff)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(dtmfCodeStr)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString(phoneNum)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(switchOn)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(switchOff)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::SEND_DTMF_STRING), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetCallTransferInfo(const CallTransferInfo &ctInfo, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&ctInfo, sizeof(CallTransferInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_CALL_TRANSFER), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::GetCallTransferInfo(CallTransferType type, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(type)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::GET_CALL_TRANSFER), in, out, option);
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
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteBool(activate)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_CALL_WAITING), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::GetCallWaiting(int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::GET_CALL_WAITING), in, out, option);
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
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteRawData((const void *)&crInfo, sizeof(CallRestrictionInfo))) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_CALL_RESTRICTION), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::GetCallRestriction(CallRestrictionType facType, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(facType)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::GET_CALL_RESTRICTION), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetCallPreferenceMode(int32_t slotId, int32_t mode)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(mode)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_CALL_PREFERENCE_MODE), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::GetCallPreferenceMode(int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::GET_CALL_PREFERENCE_MODE), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetLteImsSwitchStatus(int32_t slotId, bool active)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteBool(active)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_LTE_IMS_SWITCH_STATUS), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::GetLteImsSwitchStatus(int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::GET_LTE_IMS_SWITCH_STATUS), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::CtrlCamera(
    const std::u16string &cameraId, const std::u16string &callingPackage, int32_t callingUid, int32_t callingPid)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString16(cameraId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString16(callingPackage)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(callingUid)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(callingPid)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::CTRL_CAMERA), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetPreviewWindow(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(x)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(y)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(z)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(width)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(height)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_PREVIEW_WINDOW), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetDisplayWindow(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(x)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(y)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(z)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(width)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(height)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_DISPLAY_WINDOW), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetCameraZoom(float zoomRatio)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteFloat(zoomRatio)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_CAMERA_ZOOM), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetPauseImage(const std::u16string &path)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteString16(path)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_PAUSE_IMAGE), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

int32_t CellularCallProxy::SetDeviceDirection(int32_t rotation)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(MAX_SIZE)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteInt32(rotation)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(OperationType::SET_DEVICE_DIRECTION), in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}
} // namespace Telephony
} // namespace OHOS