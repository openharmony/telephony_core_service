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

#ifndef OHOS_SIM_CARD_INTERFACE_H
#define OHOS_SIM_CARD_INTERFACE_H

#include <cstdint>
#include <mutex>
#include <string>
#include "i_core_service.h"
#include "iremote_object.h"
#include "refbase.h"
#include "network_state.h"

namespace OHOS {
namespace Telephony {
class SimCardInterface {
public:
    SimCardInterface();
    ~SimCardInterface();
    SimCardInterface(const SimCardInterface &) = delete;
    SimCardInterface &operator=(const SimCardInterface &) = delete;
    bool GetServiceProxy();
    void ResetServiceProxy();
    bool HasSimCard(int32_t slotId);
    int32_t GetSimState(int32_t slotId);
    std::u16string GetISOCountryCodeForSim(int32_t slotId);
    std::u16string GetSimOperatorNumeric(int32_t slotId);
    std::u16string GetSimSpn(int32_t slotId);
    std::u16string GetLocaleFromDefaultSim();
    std::u16string GetSimGid1(int32_t slotId);
    bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    bool SetDefaultVoiceSlotId(int32_t slotId);
    int32_t GetDefaultVoiceSlotId();
    int32_t RefreshSimState(int32_t slotId);
    std::u16string GetIMSI(int32_t slotId);
    std::u16string GetSimIccId(int32_t slotId);
    bool IsSimActive(int32_t slotId);
    bool SetActiveSim(const int32_t slotId, int32_t enable);
    bool SetShowNumber(int32_t slotId, const std::u16string number);
    std::u16string GetShowNumber(int32_t slotId);
    bool SetShowName(int32_t slotId, const std::u16string name);
    std::u16string GetShowName(int32_t slotId);
    bool GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);
    bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    bool UnlockPin(int32_t slotId, std::u16string pin, LockStatusResponse &response);
    bool UnlockPuk(int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response);
    bool AlterPin(int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response);
    bool SetLockState(int32_t slotId, std::u16string pin, int32_t enable, LockStatusResponse &response);
    bool UnlockPin2(int32_t slotId, std::u16string pin2, LockStatusResponse &response);
    bool UnlockPuk2(int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response);
    bool AlterPin2(int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response);
    std::u16string GetSimTelephoneNumber(int32_t slotId);
    std::u16string GetVoiceMailIdentifier(int32_t slotId);
    std::u16string GetVoiceMailNumber(int32_t slotId);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int32_t slotId, int32_t type);
    bool AddIccDiallingNumbers(
        int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool DelIccDiallingNumbers(
        int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool UpdateIccDiallingNumbers(
        int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);
    int32_t GetMaxSimCount();

private:
    static std::mutex mutex_;
    sptr<ICoreService> simCardService_;
    sptr<IRemoteObject::DeathRecipient> recipient_;
};
} // namespace Telephony
} // namespace OHOS

#endif