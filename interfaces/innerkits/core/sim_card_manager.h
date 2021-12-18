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

#ifndef OHOS_SIM_CARD_MANAGER_H
#define OHOS_SIM_CARD_MANAGER_H

#include "i_core_service.h"
#include "iremote_object.h"
#include "refbase.h"

namespace OHOS {
namespace Telephony {
class SimCardManager {
public:
    static bool HasSimCard(int32_t slotId);
    static int32_t GetSimState(int32_t slotId);
    static std::u16string GetIsoCountryCodeForSim(int32_t slotId);
    static std::u16string GetSimOperatorNumeric(int32_t slotId);
    static std::u16string GetSimSpn(int32_t slotId);
    static std::u16string GetLocaleFromDefaultSim();
    static std::u16string GetSimGid1(int32_t slotId);
    static bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    static bool SetDefaultVoiceSlotId(int32_t slotId);
    static int32_t GetDefaultVoiceSlotId();
    static int32_t RefreshSimState(int32_t slotId);
    static std::u16string GetIMSI(int32_t slotId);
    static std::u16string GetSimIccId(int32_t slotId);
    static bool IsSimActive(int32_t slotId);
    static bool SetActiveSim(int32_t slotId, int32_t enable);
    static bool SetShowNumber(int32_t slotId, const std::u16string number);
    static std::u16string GetShowNumber(int32_t slotId);
    static bool SetShowName(int32_t slotId, const std::u16string name);
    static std::u16string GetShowName(int32_t slotId);
    static bool GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);
    static bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    static bool UnlockPin(int32_t slotId, std::u16string pin, LockStatusResponse &response);
    static bool UnlockPuk(int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response);
    static bool AlterPin(
        int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response);
    static bool SetLockState(int32_t slotId, std::u16string pin, int32_t enable, LockStatusResponse &response);
    static bool UnlockPin2(int32_t slotId, std::u16string pin2, LockStatusResponse &response);
    static bool UnlockPuk2(
        int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response);
    static bool AlterPin2(
        int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response);
    static std::u16string GetSimTelephoneNumber(int32_t slotId);
    static std::u16string GetVoiceMailIdentifier(int32_t slotId);
    static std::u16string GetVoiceMailNumber(int32_t slotId);
    static std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int32_t slotId, int32_t type);
    static bool AddIccDiallingNumbers(
        int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    static bool DelIccDiallingNumbers(
        int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    static bool UpdateIccDiallingNumbers(
        int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    static bool SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber);
    static int32_t GetMaxSimCount();
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_CARD_MANAGER_H