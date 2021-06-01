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
#ifndef SMS_SERVICE_INTERFACE_H
#define SMS_SERVICE_INTERFACE_H
#include "i_delivery_short_message_callback.h"
#include "i_send_short_message_callback.h"
#include "iremote_broker.h"
namespace OHOS {
namespace SMS {
class ISmsServiceInterface : public IRemoteBroker {
public:
    enum MessageID {
        TEXT_BASED_SMS_DELIVERY = 0,
        SEND_SMS_TEXT_WITEOUT_SAVE,
        DATA_BASED_SMS_DELIVERY,
    };

    virtual ~ISmsServiceInterface() = default;
    virtual void SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
        const std::u16string text, const sptr<ISendShortMessageCallback> &sendCallback,
        const sptr<IDeliveryShortMessageCallback> &deliverCallback) = 0;

    virtual void SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
        uint16_t port, const uint8_t *data, uint16_t dataLen, const sptr<ISendShortMessageCallback> &sendCallback,
        const sptr<IDeliveryShortMessageCallback> &deliverCallback) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ipc.ISmsServiceInterface");
};
} // namespace SMS
} // namespace OHOS
#endif
