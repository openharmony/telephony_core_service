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

#include "ims_core_service_callback_proxy.h"

#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Telephony {
ImsCoreServiceCallbackProxy::ImsCoreServiceCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ImsCoreServiceCallbackInterface>(impl) {}

int32_t ImsCoreServiceCallbackProxy::UpdateImsServiceStatusChanged(
    int32_t slotId, const ImsServiceStatus &imsServiceStatus)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(__FUNCTION__, in, slotId);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("[slot%{public}d]Write imsServiceStatus fail!", slotId);
        return ret;
    }
    if (!in.WriteRawData((const void *)&imsServiceStatus, sizeof(ImsServiceStatus))) {
        TELEPHONY_LOGE("[slot%{public}d]Write imsServiceStatus fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, slotId, ImsCoreServiceInterfaceCode::IMS_SERVICE_STATUS_REPORT);
}

int32_t ImsCoreServiceCallbackProxy::GetImsRegistrationStatusResponse(
    int32_t slotId, const ImsRegistrationStatus &imsRegStatus)
{
    MessageParcel in;
    int32_t ret = WriteCommonInfo(__FUNCTION__, in, slotId);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("[slot%{public}d]Write WriteCommonInfo fail!", slotId);
        return ret;
    }
    if (!in.WriteRawData((const void *)&imsRegStatus, sizeof(ImsRegistrationStatus))) {
        TELEPHONY_LOGE("[slot%{public}d]Write imsRegStatus fail!", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return SendRequest(in, slotId, ImsCoreServiceInterfaceCode::IMS_GET_REGISTRATION_STATUS);
}

int32_t ImsCoreServiceCallbackProxy::WriteCommonInfo(std::string funcName, MessageParcel &in, int32_t slotId)
{
    if (!in.WriteInterfaceToken(ImsCoreServiceCallbackProxy::GetDescriptor())) {
        TELEPHONY_LOGE("[slot%{public}d] %{public}s Write descriptor token fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] %{public}s Write slotId fail!", slotId, funcName.c_str());
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceCallbackProxy::SendRequest(MessageParcel &in, int32_t slotId, int32_t eventId)
{
    MessageParcel out;
    MessageOption option;

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d]Remote is null, eventId:%{public}d", slotId, eventId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }

    int32_t error = remote->SendRequest(eventId, in, out, option);
    if (error == ERR_NONE) {
        return out.ReadInt32();
    }
    TELEPHONY_LOGE("[slot%{public}d]SendRequest fail, eventId:%{public}d, error:%{public}d", slotId, eventId, error);
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}
} // namespace Telephony
} // namespace OHOS
