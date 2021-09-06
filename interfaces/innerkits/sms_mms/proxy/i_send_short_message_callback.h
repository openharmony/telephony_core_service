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

#ifndef I_SEND_SHORT_MESSAGE_CALLBACK_H
#define I_SEND_SHORT_MESSAGE_CALLBACK_H

#include "iremote_broker.h"

namespace OHOS {
namespace Telephony {
class ISendShortMessageCallback : public IRemoteBroker {
public:
    virtual ~ISendShortMessageCallback() = default;
    enum SmsSendResult {
        /**
         *  Indicates that the SMS message is successfully sent.
         */
        SEND_SMS_SUCCESS = 0,
        /**
         * Indicates that sending the SMS message fails due to an unknown reason.
         */
        SEND_SMS_FAILURE_UNKNOWN = 1,
        /**
         * Indicates that sending the SMS fails because the modem is powered off.
         */
        SEND_SMS_FAILURE_RADIO_OFF = 2,
        /**
         * Indicates that sending the SMS message fails because the network is unavailable
         * or does not support sending or reception of SMS messages.
         */
        SEND_SMS_FAILURE_SERVICE_UNAVAILABLE = 3
    };

    enum SendCallback { ON_SMS_SEND_RESULT };

    virtual void OnSmsSendResult(const SmsSendResult result) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ISendShortMessageCallback");
};
} // namespace Telephony
} // namespace OHOS
#endif