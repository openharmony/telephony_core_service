/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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
#include "raw_parcel_callback_proxy.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
void RawParcelCallbackProxy::Transfer(std::function<void(MessageParcel&)> func, MessageParcel &data)
{
    MessageOption option{MessageOption::TF_ASYNC};
    MessageParcel reply;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("remote is nullptr!");
        return;
    }
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TELEPHONY_LOGE("write interface token failed");
        return;
    }
    if (func != nullptr) {
        func(data);
    }
    remote->SendRequest(0, data, reply, option);
}
} // namespace Telephony
} // namespace OHOS