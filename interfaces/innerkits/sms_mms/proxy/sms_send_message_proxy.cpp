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

#include "sms_send_message_proxy.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace Telephony {
SmsSendMessageProxy::SmsSendMessageProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ISendShortMessageCallback>(impl)
{}

void SmsSendMessageProxy::OnSmsSendResult(const SmsSendResult result)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    dataParcel.WriteInt32(result);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return;
    }
    remote->SendRequest(ON_SMS_SEND_RESULT, dataParcel, replyParcel, option);
}
} // namespace Telephony
} // namespace OHOS