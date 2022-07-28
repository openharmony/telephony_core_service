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

#include "ims_reg_info_callback_proxy.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
ImsRegInfoCallbackProxy::ImsRegInfoCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ImsRegInfoCallback>(impl)
{}

int32_t ImsRegInfoCallbackProxy::OnImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info)
{
    MessageParcel data;
    MessageOption option;
    MessageParcel replyParcel;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("remote is nullptr!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    data.WriteInt32(slotId);
    data.WriteInt32(static_cast<int32_t>(info.imsRegState));
    data.WriteInt32(static_cast<int32_t>(info.imsRegTech));
    return remote->SendRequest(imsSrvType, data, replyParcel, option);
}
} // namespace Telephony
} // namespace OHOS