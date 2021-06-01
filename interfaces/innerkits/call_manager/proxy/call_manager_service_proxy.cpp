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
#include "call_manager_log.h"

namespace OHOS {
namespace TelephonyCallManager {
CallManagerServiceProxy::CallManagerServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICallManagerService>(impl)
{}

int32_t CallManagerServiceProxy::DialCall(std::u16string number, AppExecFwk::PacMap &extras, int32_t &callId)
{
    CALLMANAGER_DEBUG_LOG("CallManagerServiceProxy::DialCall Enter --> ");
    int32_t error = CALL_MANAGER_DIAL_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        CALLMANAGER_ERR_LOG("write descriptor fail");
        return TELEPHONY_WRITE_DISCRIPTOR_TOKEN_FAIL;
    }
    callId = TELEPHONY_NO_ERROR;
    dataParcel.WriteString16(number);
    int32_t accountId = extras.GetIntValue("accountId");
    int32_t videoState = extras.GetIntValue("vedioState");
    int32_t dialScene = extras.GetIntValue("dialScene");
    dataParcel.WriteInt32(accountId);
    dataParcel.WriteInt32(videoState);
    dataParcel.WriteInt32(dialScene);
    error = Remote()->SendRequest(INTERFACE_DIAL_CALL, dataParcel, replyParcel, option);
    CALLMANAGER_DEBUG_LOG("error = %{public}d", error);
    if (error != TELEPHONY_NO_ERROR) {
        CALLMANAGER_DEBUG_LOG("Function DialCall call failed!");
        return error;
    }
    error = replyParcel.ReadInt32();
    callId = replyParcel.ReadInt32();
    if (callId == TELEPHONY_NO_ERROR) {
        CALLMANAGER_DEBUG_LOG("Function DialCall call failed!");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    CALLMANAGER_DEBUG_LOG("get callId from call manager server, callId = %{public}d", callId);
    CALLMANAGER_DEBUG_LOG("Leave");
    return error;
}

int32_t CallManagerServiceProxy::AcceptCall(int32_t callId, int32_t videoState)
{
    CALLMANAGER_DEBUG_LOG("CallManagerServiceProxy::AcceptCall Enter -->");
    int32_t error = CALL_MANAGER_ACCPET_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        CALLMANAGER_ERR_LOG("write descriptor fail");
        return TELEPHONY_WRITE_DISCRIPTOR_TOKEN_FAIL;
    }

    if (videoState != 0 && videoState != 1) {
        return CALL_MANAGER_VIDEO_MODE_ERR;
    }
    dataParcel.WriteInt32(callId);
    dataParcel.WriteInt32(videoState);
    error = Remote()->SendRequest(INTERFACE_ANSWER_CALL, dataParcel, replyParcel, option);
    CALLMANAGER_DEBUG_LOG("error = %{public}d", error);
    if (error != TELEPHONY_NO_ERROR) {
        CALLMANAGER_DEBUG_LOG("Function AcceptCall call failed! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    CALLMANAGER_DEBUG_LOG("Leave");
    return error;
}

int32_t CallManagerServiceProxy::RejectCall(int32_t callId, bool isSendSms, std::u16string content)
{
    CALLMANAGER_DEBUG_LOG("CallManagerServiceProxy::RejectCall Enter --> ");
    int32_t error = CALL_MANAGER_REJECT_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        CALLMANAGER_ERR_LOG("write descriptor fail");
        return TELEPHONY_WRITE_DISCRIPTOR_TOKEN_FAIL;
    }

    dataParcel.WriteInt32(callId);
    dataParcel.WriteBool(isSendSms);
    dataParcel.WriteString16(content);
    error = Remote()->SendRequest(INTERFACE_REJECT_CALL, dataParcel, replyParcel, option);
    CALLMANAGER_DEBUG_LOG("error = %{public}d", error);
    if (error != TELEPHONY_NO_ERROR) {
        CALLMANAGER_DEBUG_LOG("Function RejectCall call failed! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    CALLMANAGER_DEBUG_LOG("Leave");
    return error;
}

int32_t CallManagerServiceProxy::HangUpCall(int32_t callId)
{
    CALLMANAGER_DEBUG_LOG("CallManagerServiceProxy::HangUpCall Enter -->");
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        CALLMANAGER_ERR_LOG("write descriptor fail");
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    dataParcel.WriteInt32(callId);
    error = Remote()->SendRequest(INTERFACE_DISCONNECT_CALL, dataParcel, replyParcel, option);
    CALLMANAGER_DEBUG_LOG("error = %{public}d", error);
    if (error != TELEPHONY_NO_ERROR) {
        CALLMANAGER_DEBUG_LOG("Function HangUpCall call failed! errCode:%{public}d", error);
    }
    error = replyParcel.ReadInt32();
    CALLMANAGER_DEBUG_LOG("Leave");
    return error;
}

int32_t CallManagerServiceProxy::GetCallState()
{
    CALLMANAGER_DEBUG_LOG("CallManagerServiceProxy::GetCallState Enter -->");
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(CallManagerServiceProxy::GetDescriptor())) {
        CALLMANAGER_ERR_LOG("write descriptor fail");
        return TELEPHONY_WRITE_DISCRIPTOR_TOKEN_FAIL;
    }

    error = Remote()->SendRequest(INTERFACE_GET_CALL_STATE, dataParcel, replyParcel, option);
    CALLMANAGER_DEBUG_LOG("error = %{public}d", error);
    if (error != TELEPHONY_NO_ERROR) {
        CALLMANAGER_DEBUG_LOG("Function GetCallState! errCode:%{public}d", error);
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    CALLMANAGER_DEBUG_LOG("Leave");
    return replyParcel.ReadInt32();
}
} // namespace TelephonyCallManager
} // namespace OHOS