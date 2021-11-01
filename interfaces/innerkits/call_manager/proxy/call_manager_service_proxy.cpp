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

int32_t CallManagerServiceProxy::RegisterCallBack(const sptr<ICallAbilityCallback> &callback,
    std::u16string &bundleName)
{
    int32_t error = TELEPHONY_REGISTER_CALLBACK_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteRemoteObject(callback->AsObject().GetRefPtr());
    dataParcel.WriteString16(bundleName);
    error = Remote()->SendRequest(INTERFACE_REGISTER_CALLBACK, dataParcel, replyParcel, option);
    TELEPHONY_LOGD("error = %{public}d", error);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function RegisterCallBack! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::DialCall(std::u16string number, AppExecFwk::PacMap &extras)
{
    int32_t error = CALL_MANAGER_DIAL_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(number);
    int32_t accountId = extras.GetIntValue("accountId");
    int32_t videoState = extras.GetIntValue("videoState");
    int32_t dialScene = extras.GetIntValue("dialScene");
    int32_t dialType = extras.GetIntValue("dialType");
    dataParcel.WriteInt32(accountId);
    dataParcel.WriteInt32(videoState);
    dataParcel.WriteInt32(dialScene);
    dataParcel.WriteInt32(dialType);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_DIAL_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function DialCall call failed!");
        return error;
    }
    error = replyParcel.ReadInt32();

    return error;
}

int32_t CallManagerServiceProxy::AnswerCall(int32_t callId, int32_t videoState)
{
    int32_t error = CALL_MANAGER_ACCEPT_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteInt32(videoState);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_ANSWER_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function AnswerCall call failed! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::RejectCall(int32_t callId, bool rejectWithMessage, std::u16string textMessage)
{
    int32_t error = CALL_MANAGER_REJECT_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }

    dataParcel.WriteInt32(callId);
    dataParcel.WriteBool(rejectWithMessage);
    dataParcel.WriteString16(textMessage);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_REJECT_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function RejectCall call failed! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::HangUpCall(int32_t callId)
{
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_DISCONNECT_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function HangUpCall call failed! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::GetCallState()
{
    int32_t error = TELEPHONY_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_GET_CALL_STATE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetCallState! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::HoldCall(int32_t callId)
{
    int32_t error = CALL_MANAGER_HOLD_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_HOLD_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function HoldCall call failed! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::UnHoldCall(int32_t callId)
{
    int32_t error = CALL_MANAGER_UNHOLD_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_UNHOLD_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function UnHoldCall call failed! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::SwitchCall(int32_t callId)
{
    int32_t error = CALL_MANAGER_SWAP_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_SWAP_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function UnHoldCall call failed! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

bool CallManagerServiceProxy::HasCall()
{
    int error = TELEPHONY_FAIL;
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
    error = Remote()->SendRequest(INTERFACE_HAS_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetAudioDevice! errCode:%{public}d", error);
        return false;
    }
    return replyParcel.ReadBool();
}

bool CallManagerServiceProxy::IsNewCallAllowed()
{
    int error = TELEPHONY_FAIL;
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
    error = Remote()->SendRequest(INTERFACE_IS_NEW_CALL_ALLOWED, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetAudioDevice! errCode:%{public}d", error);
        return false;
    }
    return replyParcel.ReadBool();
}

bool CallManagerServiceProxy::IsRinging()
{
    int32_t error = CALL_MANAGER_GET_IS_RINGING_FAILED;
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
    error = Remote()->SendRequest(INTERFACE_IS_RINGING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function IsRinging errCode:%{public}d", error);
        return false;
    }
    return replyParcel.ReadBool();
}

bool CallManagerServiceProxy::IsInEmergencyCall()
{
    int32_t error = CALL_MANAGER_GET_IS_RINGING_FAILED;
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
    error = Remote()->SendRequest(INTERFACE_IS_EMERGENCY_CALL, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function IsInEmergencyCall errCode:%{public}d", error);
        return false;
    }
    return replyParcel.ReadBool();
}

int32_t CallManagerServiceProxy::StartDtmf(int32_t callId, char str)
{
    int32_t error = CALL_MANAGER_START_DTMF_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteInt8(str);
    error = Remote()->SendRequest(
        TelephonyCallManagerSurfaceCode::INTERFACE_START_DTMF, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function StartDtmf! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::SendDtmf(int32_t callId, char str)
{
    int32_t error = CALL_MANAGER_SEND_DTMF_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteInt8(str);
    error = Remote()->SendRequest(
        TelephonyCallManagerSurfaceCode::INTERFACE_SEND_DTMF, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SendDtmf! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::SendBurstDtmf(int32_t callId, std::u16string str, int32_t on, int32_t off)
{
    int32_t error = CALL_MANAGER_SEND_DTMF_BUNCH_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteString16(str);
    dataParcel.WriteInt32(on);
    dataParcel.WriteInt32(off);
    error = Remote()->SendRequest(
        TelephonyCallManagerSurfaceCode::INTERFACE_SEND_DTMF_BUNCH, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SendBurstDtmf! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::StopDtmf(int32_t callId)
{
    int32_t error = CALL_MANAGER_STOP_DTMF_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    error = Remote()->SendRequest(
        TelephonyCallManagerSurfaceCode::INTERFACE_STOP_DTMF, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function StopDtmf! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::GetCallWaiting(int32_t slotId)
{
    int32_t error = TELEPHONY_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    error = Remote()->SendRequest(
        TelephonyCallManagerSurfaceCode::INTERFACE_GET_CALL_WAITING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function GetCallWaiting! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::SetCallWaiting(int32_t slotId, bool activate)
{
    int32_t error = TELEPHONY_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    dataParcel.WriteInt32(slotId);
    dataParcel.WriteBool(activate);
    error = Remote()->SendRequest(
        TelephonyCallManagerSurfaceCode::INTERFACE_SET_CALL_WAITING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function SetCallWaiting! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallManagerServiceProxy::CombineConference(int32_t mainCallId)
{
    int32_t error = TELEPHONY_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(mainCallId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_COMBINE_CONFERENCE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function CombineConference failed! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}

bool CallManagerServiceProxy::IsEmergencyPhoneNumber(std::u16string &number, int32_t slotId, int32_t &errorCode)
{
    int32_t error = TELEPHONY_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(number);
    dataParcel.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return false;
    }
    error = Remote()->SendRequest(INTERFACE_IS_EMERGENCY_NUMBER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function IsEmergencyPhoneNumber call failed! errCode:%{public}d", error);
    }
    bool result = replyParcel.ReadBool();
    errorCode = replyParcel.ReadInt32();
    return result;
}

int32_t CallManagerServiceProxy::FormatPhoneNumber(
    std::u16string &number, std::u16string &countryCode, std::u16string &formatNumber)
{
    int32_t error = TELEPHONY_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(number);
    dataParcel.WriteString16(countryCode);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_IS_FORMAT_NUMBER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function FormatPhoneNumber call failed! errCode:%{public}d", error);
    }
    formatNumber = replyParcel.ReadString16();
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::FormatPhoneNumberToE164(
    std::u16string &number, std::u16string &countryCode, std::u16string &formatNumber)
{
    int32_t error = TELEPHONY_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteString16(number);
    dataParcel.WriteString16(countryCode);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_IS_FORMAT_NUMBER_E164, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function FormatPhoneNumberToE164 call failed! errCode:%{public}d", error);
    }
    formatNumber = replyParcel.ReadString16();
    return replyParcel.ReadInt32();
}

int32_t CallManagerServiceProxy::GetMainCallId(int32_t callId)
{
    int32_t error = TELEPHONY_FAIL;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(callId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(INTERFACE_GET_MAINID, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function StartConference call failed! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    if (error == TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetMainCallId call failed!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    return error;
}

std::vector<std::u16string> CallManagerServiceProxy::GetSubCallIdList(int32_t callId)
{
    int32_t error = TELEPHONY_FAIL;
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
    error = Remote()->SendRequest(INTERFACE_GET_SUBCALL_LIST_ID, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function GetSubCallIdList call failed! errCode:%{public}d", error);
    }
    replyParcel.ReadString16Vector(&list);
    return list;
}

std::vector<std::u16string> CallManagerServiceProxy::GetCallIdListForConference(int32_t callId)
{
    int32_t error = TELEPHONY_FAIL;
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
    error = Remote()->SendRequest(INTERFACE_GET_CALL_LIST_ID_FOR_CONFERENCE, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function GetCallIdListForConference call failed! errCode:%{public}d", error);
    }
    replyParcel.ReadString16Vector(&list);
    return list;
}

int32_t CallManagerServiceProxy::InsertData()
{
    TELEPHONY_LOGD("CallManagerServiceProxy InsertData");
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return false;
    }
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }

    int32_t error = Remote()->SendRequest(INTERFACE_INSERT_DATA, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Function InsertData! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    return error;
}
} // namespace Telephony
} // namespace OHOS