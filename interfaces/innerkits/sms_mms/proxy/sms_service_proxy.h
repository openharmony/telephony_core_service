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

#ifndef SMS_SERVICE_PROXY_H
#define SMS_SERVICE_PROXY_H

#include "i_sms_service_interface.h"

#include "iremote_object.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Telephony {
class SmsServiceProxy : public IRemoteProxy<ISmsServiceInterface> {
public:
    explicit SmsServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~SmsServiceProxy() = default;
    void SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr,
        const std::u16string text, const sptr<ISendShortMessageCallback> &sendCallback,
        const sptr<IDeliveryShortMessageCallback> &deliverCallback) override;
    void SendMessage(int32_t slotId, const std::u16string desAddr, const std::u16string scAddr, uint16_t port,
        const uint8_t *data, uint16_t dataLen, const sptr<ISendShortMessageCallback> &sendCallback,
        const sptr<IDeliveryShortMessageCallback> &deliverCallback) override;
    bool SetSmscAddr(int32_t slotId, const std::u16string &scAddr) override;
    std::u16string GetSmscAddr(int32_t slotId) override;
    bool AddSimMessage(
        int32_t slotId, const std::u16string &smsc, const std::u16string &pdu, SimMessageStatus status) override;
    bool DelSimMessage(int32_t slotId, uint32_t msgIndex) override;
    bool UpdateSimMessage(int32_t slotId, uint32_t msgIndex, SimMessageStatus newStatus, const std::u16string &pdu,
        const std::u16string &smsc) override;
    std::vector<ShortMessage> GetAllSimMessages(int32_t slotId) override;
    bool SetCBConfig(int32_t slotId, bool enable, uint32_t fromMsgId, uint32_t toMsgId, uint8_t netType) override;
    bool SetDefaultSmsSlotId(int32_t slotId) override;
    int32_t GetDefaultSmsSlotId() override;

private:
    static inline BrokerDelegator<SmsServiceProxy> delegator_;
};

class SmsServiceDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
    SmsServiceDeathRecipient();
    virtual ~SmsServiceDeathRecipient();
    static bool GotDeathRecipient();
    static bool gotDeathRecipient_;
};
} // namespace Telephony
} // namespace OHOS
#endif // SMS_SERVICE_PROXY_H
