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

#include "call_status_callback_proxy.h"

#include "message_option.h"
#include "message_parcel.h"

#include "telephony_log_wrapper.h"
#include "call_manager_errors.h"

namespace OHOS {
namespace Telephony {
CallStatusCallbackProxy::CallStatusCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICallStatusCallback>(impl)
{}

int32_t CallStatusCallbackProxy::UpdateCallReportInfo(const CallReportInfo &info)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallReportInfo);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&info, length);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_CALL_INFO, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateCallsReportInfo(const CallsReportInfo &info)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t length = sizeof(CallReportInfo);
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(info.callVec.size());
    for (auto &it : info.callVec) {
        dataParcel.WriteInt32(length);
        dataParcel.WriteRawData((const void *)&it, length);
    }
    dataParcel.WriteInt32(info.slotId);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_CALLS_INFO, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateDisconnectedCause(const DisconnectedDetails &cause)
{
    return TELEPHONY_SUCCESS;
}

int32_t CallStatusCallbackProxy::UpdateEventResultInfo(const CellularCallEventInfo &info)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CellularCallEventInfo);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&info, length);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_EVENT_RESULT_INFO, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateGetWaitingResult(const CallWaitResponse &callWaitResponse)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallWaitResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&callWaitResponse, length);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_GET_WAITING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateSetWaitingResult(int32_t result)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(result);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_SET_WAITING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateGetRestrictionResult(const CallRestrictionResponse &callRestrictionResult)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallRestrictionResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&callRestrictionResult, length);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_GET_RESTRICTION, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateSetRestrictionResult(int32_t result)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(result);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_SET_RESTRICTION, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateGetTransferResult(const CallTransferResponse &callTransferResponse)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallTransferResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&callTransferResponse, length);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_GET_TRANSFER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateSetTransferResult(int32_t result)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(result);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_SET_TRANSFER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateGetCallClipResult(const ClipResponse &clipResponse)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(ClipResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&clipResponse, length);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_GET_CALL_CLIP, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateGetCallClirResult(const ClirResponse &clirResponse)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(ClirResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&clirResponse, length);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_GET_CALL_CLIR, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::UpdateSetCallClirResult(int32_t result)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_ERR_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(result);
    if (Remote() == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = Remote()->SendRequest(
        (uint32_t)CallManagerCallStatusCode::UPDATE_SET_CALL_CLIR, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}
} // namespace Telephony
} // namespace OHOS
