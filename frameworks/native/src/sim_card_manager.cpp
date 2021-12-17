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

#include "sim_card_manager.h"
#include "sim_card_interface.h"
#include "singleton.h"

namespace OHOS {
namespace Telephony {
bool SimCardManager::HasSimCard(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->HasSimCard(slotId);
}

int32_t SimCardManager::GetSimState(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetSimState(slotId);
}

std::u16string SimCardManager::GetIsoCountryCodeForSim(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetISOCountryCodeForSim(slotId);
}

std::u16string SimCardManager::GetSimOperatorNumeric(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetSimOperatorNumeric(slotId);
}

std::u16string SimCardManager::GetSimSpn(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetSimSpn(slotId);
}

std::u16string SimCardManager::GetLocaleFromDefaultSim()
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetLocaleFromDefaultSim();
}

std::u16string SimCardManager::GetSimGid1(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetSimGid1(slotId);
}

bool SimCardManager::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetSimAccountInfo(slotId, info);
}

bool SimCardManager::SetDefaultVoiceSlotId(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->SetDefaultVoiceSlotId(slotId);
}

int32_t SimCardManager::GetDefaultVoiceSlotId()
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetDefaultVoiceSlotId();
}

int32_t SimCardManager::RefreshSimState(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->RefreshSimState(slotId);
}

std::u16string SimCardManager::GetIMSI(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetIMSI(slotId);
}

std::u16string SimCardManager::GetSimIccId(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetSimIccId(slotId);
}

bool SimCardManager::IsSimActive(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->IsSimActive(slotId);
}

bool SimCardManager::SetActiveSim(int32_t slotId, int32_t enable)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->SetActiveSim(slotId, enable);
}

bool SimCardManager::SetShowNumber(int32_t slotId, const std::u16string number)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->SetShowNumber(slotId, number);
}

std::u16string SimCardManager::GetShowNumber(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetShowNumber(slotId);
}

bool SimCardManager::SetShowName(int32_t slotId, const std::u16string name)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->SetShowName(slotId, name);
}

std::u16string SimCardManager::GetShowName(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetShowName(slotId);
}

bool SimCardManager::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetOperatorConfigs(slotId, poc);
}

bool SimCardManager::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetActiveSimAccountInfoList(iccAccountInfoList);
}

bool SimCardManager::UnlockPin(int32_t slotId, std::u16string pin, LockStatusResponse &response)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->UnlockPin(slotId, pin, response);
}

bool SimCardManager::UnlockPuk(
    int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->UnlockPuk(slotId, newPin, puk, response);
}

bool SimCardManager::AlterPin(
    int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->AlterPin(slotId, newPin, oldPin, response);
}

bool SimCardManager::SetLockState(int32_t slotId, std::u16string pin, int32_t enable, LockStatusResponse &response)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->SetLockState(slotId, pin, enable, response);
}

bool SimCardManager::UnlockPin2(int32_t slotId, std::u16string pin2, LockStatusResponse &response)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->UnlockPin2(slotId, pin2, response);
}

bool SimCardManager::UnlockPuk2(
    int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->UnlockPuk2(slotId, newPin2, puk2, response);
}

bool SimCardManager::AlterPin2(
    int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->AlterPin2(slotId, newPin2, oldPin2, response);
}

std::u16string SimCardManager::GetSimTelephoneNumber(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetSimTelephoneNumber(slotId);
}

std::u16string SimCardManager::GetVoiceMailIdentifier(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetVoiceMailIdentifier(slotId);
}

std::u16string SimCardManager::GetVoiceMailNumber(int32_t slotId)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetVoiceMailNumber(slotId);
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> SimCardManager::QueryIccDiallingNumbers(
    int32_t slotId, int32_t type)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->QueryIccDiallingNumbers(slotId, type);
}

bool SimCardManager::AddIccDiallingNumbers(
    int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

bool SimCardManager::DelIccDiallingNumbers(
    int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

bool SimCardManager::UpdateIccDiallingNumbers(
    int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->UpdateIccDiallingNumbers(
        slotId, type, diallingNumber);
}

bool SimCardManager::SetVoiceMailInfo(
    int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

int32_t SimCardManager::GetMaxSimCount()
{
    return DelayedSingleton<SimCardInterface>::GetInstance()->GetMaxSimCount();
}
} // namespace Telephony
} // namespace OHOS
