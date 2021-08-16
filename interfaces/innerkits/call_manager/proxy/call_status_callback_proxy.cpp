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
#include "call_manager_errors.h"

#include "message_option.h"
#include "message_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
CallStatusCallbackProxy::CallStatusCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ICallStatusCallback>(impl)
{}

int32_t CallStatusCallbackProxy::OnUpdateCallReportInfo(const CallReportInfo &info)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallReportInfo);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&info, length);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_CALL_INFO, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateCallsReportInfo(const CallsReportInfo &info)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t length = sizeof(CallReportInfo);
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(info.callVec.size());
    for (auto &it : info.callVec) {
        dataParcel.WriteInt32(length);
        dataParcel.WriteRawData((const void *)&it, length);
    }
    dataParcel.WriteInt32(info.slotId);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_CALLS_INFO, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateDisconnectedCause(const DisconnectedDetails &cause)
{
    return TELEPHONY_SUCCESS;
}

int32_t CallStatusCallbackProxy::OnUpdateEventResultInfo(const CellularCallEventInfo &info)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CellularCallEventInfo);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&info, length);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_EVENT_RESULT_INFO, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateGetWaitingResult(const CallWaitResponse &callWaitResponse)
{
    TELEPHONY_LOGE("OnUpdateGetWaitingResult on");
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallWaitResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&callWaitResponse, length);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_GET_WAITING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateSetWaitingResult(int32_t result)
{
    TELEPHONY_LOGE("OnUpdateSetWaitingResult on");
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(result);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_SET_WAITING, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateGetRestrictionResult(const CallRestrictionResponse &callLimitResult)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallRestrictionResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&callLimitResult, length);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_GET_RESTRICTION, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateSetRestrictionResult(int32_t result)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(result);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_SET_RESTRICTION, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateGetTransferResult(const CallTransferResponse &callTransferResponse)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(CallTransferResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&callTransferResponse, length);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_GET_TRANSFER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateSetTransferResult(int32_t result)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(result);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_SET_TRANSFER, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateGetCallClipResult(const ClipResponse &clipResponse)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(ClipResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&clipResponse, length);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_GET_CALL_CLIP, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateGetCallClirResult(const ClirResponse &clirResponse)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    int32_t length = sizeof(ClirResponse);
    dataParcel.WriteInt32(length);
    dataParcel.WriteRawData((const void *)&clirResponse, length);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_GET_CALL_CLIR, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}

int32_t CallStatusCallbackProxy::OnUpdateSetCallClirResult(int32_t result)
{
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = CALL_MANAGER_HANGUP_FAILED;
    if (!dataParcel.WriteInterfaceToken(CallStatusCallbackProxy::GetDescriptor())) {
        return TELEPHONY_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    dataParcel.WriteInt32(result);
    if (Remote() == nullptr) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = Remote()->SendRequest(UPDATE_SET_CALL_CLIR, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        return TELEPHONY_CONNECT_SYSTEM_ABILITY_STUB_FAIL;
    }
    error = replyParcel.ReadInt32();
    return error;
}
} // namespace Telephony
} // namespace OHOS
