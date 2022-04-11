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

#include "telephony_errors.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Telephony {
int32_t ImsCoreServiceProxy::RegisterImsCoreServiceCallback(const sptr<ImsCoreServiceCallbackInterface> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("ImsCoreServiceProxy::RegisterImsCoreServiceCallback return, callback is nullptr");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(ImsCoreServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("ImsCoreServiceProxy::RegisterImsCoreServiceCallback return, write descriptor token fail!");
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        TELEPHONY_LOGE("ImsCoreServiceProxy::RegisterImsCoreServiceCallback return, write data fail!");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    int32_t error = Remote()->SendRequest(IMS_REGISTER_CALLBACK, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    return error;
}

sptr<IRemoteObject> ImsCoreServiceProxy::GetProxyObjectPtr(ImsServiceProxyType proxyType)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    if (!dataParcel.WriteInterfaceToken(ImsCoreServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return nullptr;
    }
    dataParcel.WriteInt32(static_cast<int32_t>(proxyType));
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return nullptr;
    }
    int32_t error = Remote()->SendRequest(IMS_GET_PROXY_OBJECT_PTR, dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetProxyObjectPtr failed! errCode:%{public}d", error);
        return nullptr;
    }
    return replyParcel.ReadRemoteObject();
}
} // namespace Telephony
} // namespace OHOS