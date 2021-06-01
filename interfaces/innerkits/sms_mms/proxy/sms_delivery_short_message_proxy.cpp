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
#include "sms_delivery_short_message_proxy.h"
#include "message_option.h"
#include "message_parcel.h"
namespace OHOS {
namespace SMS {
SmsDeliveryShortMessageProxy::SmsDeliveryShortMessageProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<SMS::IDeliveryShortMessageCallback>(impl)
{}

int32_t SmsDeliveryShortMessageProxy::OnSmsDeliveryResult(const std::u16string pdu)
{
    MessageOption option;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    dataParcel.WriteString16(pdu);
    Remote()->SendRequest(ON_SMS_DELIVERY_RESULT, dataParcel, replyParcel, option);
    return 0;
}
} // namespace SMS
} // namespace OHOS