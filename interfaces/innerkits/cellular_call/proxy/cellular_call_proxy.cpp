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
namespace CellularCall {
int CellularCallProxy::Dial(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(DIAL, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return 0;
}

int CellularCallProxy::End(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return ERR_SYSTEM_INVOKE;
    }

    int error = Remote()->SendRequest(END, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return 0;
}

int CellularCallProxy::Reject(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(REJECT, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return 0;
}

int CellularCallProxy::Answer(const CellularCallInfo &callInfo)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteRawData((const void *)&callInfo, sizeof(CellularCallInfo))) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(ANSWER, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return 0;
}

int CellularCallProxy::IsUrgentCall(const std::string &phoneNum, int32_t slotId)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;

    if (!in.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteString(phoneNum)) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!in.WriteInt32(slotId)) {
        return ERR_SYSTEM_INVOKE;
    }
    int error = Remote()->SendRequest(EMERGENCY_CALL, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return 0;
}

int CellularCallProxy::RegisterCallManagerCallBack(const sptr<TelephonyCallManager::ICallStatusCallback> &callback)
{
    if (callback == nullptr) {
        return -1;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return ERR_SYSTEM_INVOKE;
    }

    int32_t error = Remote()->SendRequest(REGISTER_CALLBACK, data, reply, option);
    if (error != ERR_NONE) {
        return error;
    }
    return reply.ReadInt32();
}

int CellularCallProxy::UnRegisterCallManagerCallBack()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CellularCallProxy::GetDescriptor())) {
        return ERR_SYSTEM_INVOKE;
    }

    int32_t error = Remote()->SendRequest(UNREGISTER_CALLBACK, data, reply, option);
    if (error != ERR_NONE) {
        return error;
    }
    return reply.ReadInt32();
}
} // namespace CellularCall
} // namespace OHOS