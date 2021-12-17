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

#include "network_search_callback_proxy.h"

namespace OHOS {
namespace Telephony {
NetworkSearchCallBackProxy::NetworkSearchCallBackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<INetworkSearchCallback>(impl)
{}
int32_t NetworkSearchCallBackProxy::OnNetworkSearchCallback(
    NetworkSearchCallback requestId, MessageParcel &callBackParcel)
{
    MessageOption option;
    MessageParcel replyParcel;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERROR;
    }
    return remote->SendRequest(static_cast<uint32_t>(requestId), callBackParcel, replyParcel, option);
}
} // namespace Telephony
} // namespace OHOS
