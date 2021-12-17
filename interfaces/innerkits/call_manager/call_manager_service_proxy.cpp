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

#include "call_manager_service_proxy.h"

#include "message_option.h"
#include "message_parcel.h"

#include "call_manager_errors.h"

namespace OHOS {
namespace Telephony {
CallManagerServiceProxy::CallManagerServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICallManagerService>(impl)
{}

int32_t CallManagerServiceProxy::RegisterCallBack(
    const sptr<ICallAbilityCallback> &callback, std::u16string &bundleName)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteRemoteObject(callback->AsObject().GetRefPtr());
    dataParcel.WriteString16(bundleName);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_REGISTER_CALLBACK, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function RegisterCallBack! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::UnRegisterCallBack(std::u16string &bundleName)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(bundleName);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_UNREGISTER_CALLBACK, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function RegisterCallBack! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::DialCall(std::u16string number, AppExecFwk::PacMap &extras)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(number);
    int32_t accountId = extras.GetIntValue("accountId");
    int32_t videoState = extras.GetIntValue("videoState");
    int32_t dialScene = extras.GetIntValue("dialScene");
    int32_t dialType = extras.GetIntValue("dialType");
    int32_t callType = extras.GetIntValue("callType");
    dataParcel.WriteInt32(accountId);
    dataParcel.WriteInt32(videoState);
    dataParcel.WriteInt32(dialScene);
    dataParcel.WriteInt32(dialType);
    dataParcel.WriteInt32(callType);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_DIAL_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function DialCall call failed!");
        return error;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::AnswerCall(int32_t callId, int32_t videoState)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteInt32(videoState);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_ANSWER_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function AnswerCall call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::RejectCall(int32_t callId, bool rejectWithMessage, std::u16string textMessage)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }

    dataParcel.WriteInt32(callId);
    dataParcel.WriteBool(rejectWithMessage);
    dataParcel.WriteString16(textMessage);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_REJECT_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function RejectCall call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::HangUpCall(int32_t callId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_DISCONNECT_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function HangUpCall call failed! errCode:%{public}d", error);
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::GetCallState()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_GET_CALL_STATE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetCallState! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::HoldCall(int32_t callId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_HOLD_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function HoldCall call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    // return err code
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::UnHoldCall(int32_t callId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_UNHOLD_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function UnHoldCall call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SwitchCall(int32_t callId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SWAP_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function UnHoldCall call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

bool CallManagerServiceProxy::HasCall()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return false;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_HAS_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetAudioDevice! errCode:%{public}d", error);
        return false;
    }
    return replyParcel.ReadBool();
}

bool CallManagerServiceProxy::IsNewCallAllowed()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return false;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_IS_NEW_CALL_ALLOWED, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetAudioDevice! errCode:%{public}d", error);
        return false;
    }
    return replyParcel.ReadBool();
}

int32_t CallManagerServiceProxy::SetMuted(bool isMute)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteBool(isMute);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_MUTE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SetMute failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::MuteRinger()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_MUTE_RINGER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function MuteRinger failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetAudioDevice(AudioDevice deviceType)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32((int32_t)deviceType);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_AUDIO_DEVICE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SetAudioDevice failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

bool CallManagerServiceProxy::IsRinging()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return false;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_IS_RINGING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function IsRinging errCode:%{public}d", error);
        return false;
    }
    return replyParcel.ReadBool();
}

bool CallManagerServiceProxy::IsInEmergencyCall()
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return false;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_IS_EMERGENCY_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function IsInEmergencyCall errCode:%{public}d", error);
        return false;
    }
    return replyParcel.ReadBool();
}

int32_t CallManagerServiceProxy::StartDtmf(int32_t callId, char str)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteInt8(str);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_START_DTMF, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function StartDtmf! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SendDtmf(int32_t callId, char str)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteInt8(str);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SEND_DTMF, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SendDtmf! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SendBurstDtmf(int32_t callId, std::u16string str, int32_t on, int32_t off)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteString16(str);
    dataParcel.WriteInt32(on);
    dataParcel.WriteInt32(off);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SEND_DTMF_BUNCH, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SendBurstDtmf! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::StopDtmf(int32_t callId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_STOP_DTMF, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function StopDtmf! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::GetCallWaiting(int32_t slotId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_GET_CALL_WAITING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function GetCallWaiting! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetCallWaiting(int32_t slotId, bool activate)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteBool(activate);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_CALL_WAITING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetCallWaiting! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::GetCallRestriction(int32_t slotId, CallRestrictionType type)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteInt32(type);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_GET_CALL_RESTRICTION, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function GetCallRestriction! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetCallRestriction(int32_t slotId, CallRestrictionInfo &info)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteRawData((const void *)&info, sizeof(CallRestrictionInfo));
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_CALL_RESTRICTION, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetCallRestriction! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::GetCallTransferInfo(int32_t slotId, CallTransferType type)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteInt32(type);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_GET_CALL_TRANSFER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function GetCallTransfer! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetCallTransferInfo(int32_t slotId, CallTransferInfo &info)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteRawData((const void *)&info, sizeof(CallTransferInfo));
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_CALL_TRANSFER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetCallTransfer! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetCallPreferenceMode(int32_t slotId, int32_t mode)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteInt32(mode);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SETCALL_PREFERENCEMODE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetCallPreferenceMode! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::CombineConference(int32_t mainCallId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(mainCallId);
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_COMBINE_CONFERENCE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function CombineConference failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SeparateConference(int32_t callId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SEPARATE_CONFERENCE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SeparateConference call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::ControlCamera(std::u16string cameraId, std::u16string callingPackage)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(cameraId);
    dataParcel.WriteString16(callingPackage);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_CTRL_CAMERA, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function CtrlCamera call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetPreviewWindow(VideoWindow &window)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteRawData((const void *)&window, sizeof(VideoWindow));
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_PREVIEW_WINDOW, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetPreviewWindow call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetDisplayWindow(VideoWindow &window)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteRawData((const void *)&window, sizeof(VideoWindow));
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_DISPLAY_WINDOW, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetDisplayWindow call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetCameraZoom(float zoomRatio)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteFloat(zoomRatio);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_CAMERA_ZOOM, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetCameraZoom call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetPausePicture(std::u16string path)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(path);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_PAUSE_PICTURE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetPausePicture call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::SetDeviceDirection(int32_t rotation)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(rotation);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_SET_DEVICE_DIRECTION, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetDeviceDirection call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

bool CallManagerServiceProxy::IsEmergencyPhoneNumber(std::u16string &number, int32_t slotId, int32_t &errorCode)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return false;
    }
    dataParcel.WriteString16(number);
    dataParcel.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return false;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_IS_EMERGENCY_NUMBER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function IsEmergencyPhoneNumber call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    bool result = replyParcel.ReadBool();
    errorCode = replyParcel.ReadInt32();
    return result;
}

int32_t CallManagerServiceProxy::FormatPhoneNumber(
    std::u16string &number, std::u16string &countryCode, std::u16string &formatNumber)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(number);
    dataParcel.WriteString16(countryCode);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_IS_FORMAT_NUMBER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function FormatPhoneNumber call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    formatNumber = replyParcel.ReadString16();
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::FormatPhoneNumberToE164(
    std::u16string &number, std::u16string &countryCode, std::u16string &formatNumber)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(number);
    dataParcel.WriteString16(countryCode);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_IS_FORMAT_NUMBER_E164, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function FormatPhoneNumberToE164 call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    formatNumber = replyParcel.ReadString16();
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::GetMainCallId(int32_t callId)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_GET_MAINID, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function StartConference call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

std::vector<std::u16string> CallManagerServiceProxy::GetSubCallIdList(int32_t callId)
{
    std::vector<std::u16string> list;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return list;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return list;
    }
    int32_t error = Remote()->SendRequest(
        (uint32_t)CallManagerSurfaceCode::INTERFACE_GET_SUBCALL_LIST_ID, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function GetSubCallIdList call failed! errCode:%{public}d", error);
        return list;
    }
    replyParcel.ReadString16Vector(&list);
    return list;
}

std::vector<std::u16string> CallManagerServiceProxy::GetCallIdListForConference(int32_t callId)
{
    std::vector<std::u16string> list;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return list;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return list;
    }
    int32_t error =
        Remote()->SendRequest((uint32_t)CallManagerSurfaceCode::INTERFACE_GET_CALL_LIST_ID_FOR_CONFERENCE,
            dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function GetCallIdListForConference call failed! errCode:%{public}d", error);
        return list;
    }
    replyParcel.ReadString16Vector(&list);
    return list;
}

int32_t CallManagerServiceProxy::CancelMissedCallsNotification(int32_t id)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    dataParcel.WriteInt32(id);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int32_t error =
        Remote()->SendRequest((uint32_t)CallManagerSurfaceCode::INTERFACE_CANCEL_MISSED_CALLS_NOTIFICATION,
            dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function HangUpCall call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}
} // namespace Telephony
} // namespace OHOS
