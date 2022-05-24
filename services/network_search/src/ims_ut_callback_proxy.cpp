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

#include "ims_ut_callback_proxy.h"

namespace OHOS {
namespace Telephony {
ImsUtCallbackProxy::ImsUtCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ImsUtCallback>(impl)
{}
int32_t ImsUtCallbackProxy::OnImsStateCallback(const ImsRegInfo &info)
{
    TELEPHONY_LOGI("ImsUtCallbackProxy ENTER!!  ");
    MessageParcel data;
    MessageOption option;
    MessageParcel replyParcel;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("remote is null!");
    }
    data.WriteInt32(static_cast<int32_t>(info.imsRegState));
    data.WriteInt32(static_cast<int32_t>(info.imsRegTech));
    return remote->SendRequest(IMS_UT, data, replyParcel, option);
}
}  // namespace Telephony
}  // namespace OHOS