/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "ims_core_service_proxy.h"

#include "message_option.h"
#include "message_parcel.h"
#include "telephony_errors.h"
#include "telephony_permission.h"

namespace OHOS {
namespace Telephony {
int32_t ImsCoreServiceProxy::GetImsRegistrationStatus(int32_t slotId)
{
    if (!TelephonyPermission::CheckPermission(Permission::GET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("[slot%{public}d]Permission denied!", slotId);
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCoreServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d]Write descriptor token fail!", slotId);
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d]Write slotId fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null", slotId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error = remote->SendRequest(IMS_GET_REGISTRATION_STATUS, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, error:%{public}d", slotId, error);
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t ImsCoreServiceProxy::RegisterImsCoreServiceCallback(const sptr<ImsCoreServiceCallbackInterface> &callback)
{
    if (!TelephonyPermission::CheckPermission(Permission::SET_TELEPHONY_STATE)) {
        TELEPHONY_LOGE("Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback is nullptr!");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageParcel in;
    if (!in.WriteInterfaceToken(ImsCoreServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("Write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        TELEPHONY_LOGE("Write ImsCoreServiceCallbackInterface fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageParcel out;
    MessageOption option;
    int32_t error = remote->SendRequest(IMS_REGISTER_CALLBACK, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("SendRequest fail, error:%{public}d", error);
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

sptr<IRemoteObject> ImsCoreServiceProxy::GetProxyObjectPtr(ImsServiceProxyType proxyType)
{
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(ImsCoreServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return nullptr;
    }
    dataParcel.WriteInt32(static_cast<int32_t>(proxyType));
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return nullptr;
    }
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = remote->SendRequest(IMS_GET_PROXY_OBJECT_PTR, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetProxyObjectPtr failed! errCode:%{public}d", error);
        return nullptr;
    }
    return replyParcel.ReadRemoteObject();
}
} // namespace Telephony
} // namespace OHOS
