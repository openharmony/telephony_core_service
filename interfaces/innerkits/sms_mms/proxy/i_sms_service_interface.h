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
#include "short_message.h"

namespace OHOS {
namespace Telephony {
class ISmsServiceInterface : public IRemoteBroker {
public:
    enum MessageID {
        TEXT_BASED_SMS_DELIVERY = 0,
        SEND_SMS_TEXT_WITHOUT_SAVE,
        DATA_BASED_SMS_DELIVERY,
        SET_SMSC_ADDRESS,
        GET_SMSC_ADDRESS,
        ADD_SIM_MESSAGE,
        DEL_SIM_MESSAGE,
        UPDATE_SIM_MESSAGE,
        GET_ALL_SIM_MESSAGE,
        SET_CB_RANGE_CONFIG,
        SET_CB_CONFIG,
        SET_DEFAULT_SMS_SLOT_ID,
        GET_DEFAULT_SMS_SLOT_ID,
    };

    /**
     * @brief SimMessageStatus
     * from 3GPP TS 27.005 V4.1.0 (2001-09) section 3 Parameter Definitions
     */
    using SimMessageStatus = enum {
        SIM_MESSAGE_STATUS_UNREAD = 0, // 0 REC UNREAD received unread message
        SIM_MESSAGE_STATUS_READ = 1, // 1	REC READ received read message
        SIM_MESSAGE_STATUS_UNSENT = 2, // 2 "STO UNSENT" stored unsent message (only applicable to SMs)
        SIM_MESSAGE_STATUS_SENT = 3, // 3	"STO SENT" stored sent message (only applicable to SMs)
    };

    virtual ~ISmsServiceInterface() = default;
    virtual void SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
        const std::u16string text, const sptr<ISendShortMessageCallback> &sendCallback,
        const sptr<IDeliveryShortMessageCallback> &deliverCallback) = 0;

    virtual void SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
        uint16_t port, const uint8_t *data, uint16_t dataLen, const sptr<ISendShortMessageCallback> &sendCallback,
        const sptr<IDeliveryShortMessageCallback> &deliverCallback) = 0;
    virtual bool SetSmscAddr(int32_t slotId, const std::u16string &scAddr) = 0;
    virtual std::u16string GetSmscAddr(int32_t slotId) = 0;
    virtual bool AddSimMessage(
        int32_t slotId, const std::u16string &smsc, const std::u16string &pdu, SimMessageStatus status) = 0;
    virtual bool DelSimMessage(int32_t slotId, uint32_t msgIndex) = 0;
    virtual bool UpdateSimMessage(int32_t slotId, uint32_t msgIndex, SimMessageStatus newStatus,
        const std::u16string &pdu, const std::u16string &smsc) = 0;
    virtual std::vector<ShortMessage> GetAllSimMessages(int32_t slotId) = 0;
    virtual bool SetCBConfig(
        int32_t slotId, bool enable, uint32_t fromMsgId, uint32_t toMsgId, uint8_t netType) = 0;
    virtual bool SetDefaultSmsSlotId(int32_t slotId) = 0;
    virtual int32_t GetDefaultSmsSlotId() = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ISmsServiceInterface");
};
} // namespace Telephony
} // namespace OHOS
#endif
