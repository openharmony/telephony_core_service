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

#include "sim_card_interface.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "service_interface_death_recipient.h"
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
constexpr int32_t INVALID_VALUE = -1;
} // namespace

std::mutex SimCardInterface::mutex_;

SimCardInterface::SimCardInterface() : simCardService_(nullptr) {}

SimCardInterface::~SimCardInterface() {}

bool SimCardInterface::GetServiceProxy()
{
    if (!simCardService_) {
        std::lock_guard<std::mutex> lock(mutex_);
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityManager) {
            TELEPHONY_LOGE(" Get system ability mgr failed.");
            return false;
        }
        sptr<IRemoteObject> remoteObject =
            systemAbilityManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
        if (!remoteObject) {
            TELEPHONY_LOGE("Get Service Failed.");
            return false;
        }
        simCardService_ = iface_cast<ICoreService>(remoteObject);
        if ((!simCardService_) || (!simCardService_->AsObject())) {
            TELEPHONY_LOGE("Get Service Proxy Failed.");
            return false;
        }
        recipient_ = new ServiceInterfaceDeathRecipient<SimCardInterface>();
        if (!recipient_) {
            TELEPHONY_LOGE("Failed to create death Recipient ptr ServiceInterfaceDeathRecipient!");
            return false;
        }
        simCardService_->AsObject()->AddDeathRecipient(recipient_);
        TELEPHONY_LOGI("simCardService_ init success!");
    }
    return true;
}
void SimCardInterface::ResetServiceProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((simCardService_ != nullptr) && (simCardService_->AsObject() != nullptr)) {
        simCardService_->AsObject()->RemoveDeathRecipient(recipient_);
    }
    simCardService_ = nullptr;
}

bool SimCardInterface::HasSimCard(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->HasSimCard(slotId);
    }
    return false;
}

int32_t SimCardInterface::GetSimState(int32_t slotId)
{
    if (GetServiceProxy()) {
        return static_cast<int32_t>(simCardService_->GetSimState(slotId));
    }
    return INVALID_VALUE;
}

std::u16string SimCardInterface::GetISOCountryCodeForSim(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetISOCountryCodeForSim(slotId);
    }
    return u"";
}

std::u16string SimCardInterface::GetSimOperatorNumeric(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetSimOperatorNumeric(slotId);
    }
    return u"";
}

std::u16string SimCardInterface::GetSimSpn(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetSimSpn(slotId);
    }
    return u"";
}

std::u16string SimCardInterface::GetLocaleFromDefaultSim()
{
    if (GetServiceProxy()) {
        return simCardService_->GetLocaleFromDefaultSim();
    }
    return u"";
}

std::u16string SimCardInterface::GetSimGid1(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetSimGid1(slotId);
    }
    return u"";
}

bool SimCardInterface::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    if (GetServiceProxy()) {
        return simCardService_->GetSimAccountInfo(slotId, info);
    }
    return false;
}

bool SimCardInterface::SetDefaultVoiceSlotId(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->SetDefaultVoiceSlotId(slotId);
    }
    return false;
}

int32_t SimCardInterface::GetDefaultVoiceSlotId()
{
    if (GetServiceProxy()) {
        return simCardService_->GetDefaultVoiceSlotId();
    }
    return INVALID_VALUE;
}

bool SimCardInterface::UnlockPin(int32_t slotId, std::u16string pin, LockStatusResponse &response)
{
    if (GetServiceProxy()) {
        return simCardService_->UnlockPin(slotId, pin, response);
    }
    return false;
}

bool SimCardInterface::UnlockPuk(
    int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response)
{
    if (GetServiceProxy()) {
        return simCardService_->UnlockPuk(slotId, newPin, puk, response);
    }
    return false;
}

bool SimCardInterface::AlterPin(
    int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response)
{
    if (GetServiceProxy()) {
        return simCardService_->AlterPin(slotId, newPin, oldPin, response);
    }
    return false;
}

bool SimCardInterface::SetLockState(
    int32_t slotId, std::u16string pin, int32_t enable, LockStatusResponse &response)
{
    if (GetServiceProxy()) {
        return simCardService_->SetLockState(slotId, pin, enable, response);
    }
    return false;
}

int32_t SimCardInterface::RefreshSimState(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->RefreshSimState(slotId);
    }
    return INVALID_VALUE;
}

std::u16string SimCardInterface::GetSimIccId(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetSimIccId(slotId);
    }
    return u"";
}

bool SimCardInterface::IsSimActive(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->IsSimActive(slotId);
    }
    return false;
}

bool SimCardInterface::SetActiveSim(const int32_t slotId, int32_t enable)
{
    if (GetServiceProxy()) {
        return simCardService_->SetActiveSim(slotId, enable);
    }
    return false;
}

std::u16string SimCardInterface::GetIMSI(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetIMSI(slotId);
    }
    return u"";
}

bool SimCardInterface::UnlockPin2(int32_t slotId, std::u16string pin2, LockStatusResponse &response)
{
    if (GetServiceProxy()) {
        return simCardService_->UnlockPin2(slotId, pin2, response);
    }
    return false;
}

bool SimCardInterface::UnlockPuk2(
    int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response)
{
    if (GetServiceProxy()) {
        return simCardService_->UnlockPuk2(slotId, newPin2, puk2, response);
    }
    return false;
}

bool SimCardInterface::AlterPin2(
    int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response)
{
    if (GetServiceProxy()) {
        return simCardService_->AlterPin2(slotId, newPin2, oldPin2, response);
    }
    return false;
}

bool SimCardInterface::SetShowNumber(int32_t slotId, const std::u16string number)
{
    if (GetServiceProxy()) {
        return simCardService_->SetShowNumber(slotId, number);
    }
    return false;
}

std::u16string SimCardInterface::GetShowNumber(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetShowNumber(slotId);
    }
    return u"";
}

bool SimCardInterface::SetShowName(int32_t slotId, const std::u16string name)
{
    if (GetServiceProxy()) {
        return simCardService_->SetShowName(slotId, name);
    }
    return false;
}

std::u16string SimCardInterface::GetShowName(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetShowName(slotId);
    }
    return u"";
}

bool SimCardInterface::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if (GetServiceProxy()) {
        return simCardService_->GetOperatorConfigs(slotId, poc);
    }
    return false;
}

bool SimCardInterface::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    if (GetServiceProxy()) {
        return simCardService_->GetActiveSimAccountInfoList(iccAccountInfoList);
    }
    return false;
}

std::u16string SimCardInterface::GetSimTelephoneNumber(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetSimTelephoneNumber(slotId);
    }
    return u"";
}

std::u16string SimCardInterface::GetVoiceMailIdentifier(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetVoiceMailIdentifier(slotId);
    }
    return u"";
}

std::u16string SimCardInterface::GetVoiceMailNumber(int32_t slotId)
{
    if (GetServiceProxy()) {
        return simCardService_->GetVoiceMailNumber(slotId);
    }
    return u"";
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> SimCardInterface::QueryIccDiallingNumbers(int slotId, int type)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    if (GetServiceProxy()) {
        result = simCardService_->QueryIccDiallingNumbers(slotId, type);
    }
    return result;
}

bool SimCardInterface::AddIccDiallingNumbers(
    int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (GetServiceProxy()) {
        return simCardService_->AddIccDiallingNumbers(slotId, type, diallingNumber);
    }
    return false;
}

bool SimCardInterface::DelIccDiallingNumbers(
    int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (GetServiceProxy()) {
        return simCardService_->DelIccDiallingNumbers(slotId, type, diallingNumber);
    }
    return false;
}

bool SimCardInterface::UpdateIccDiallingNumbers(
    int32_t slotId, int32_t type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (GetServiceProxy()) {
        return simCardService_->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
    }
    return false;
}

bool SimCardInterface::SetVoiceMailInfo(
    int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (GetServiceProxy()) {
        return simCardService_->SetVoiceMailInfo(slotId, mailName, mailNumber);
    }
    return false;
}

int32_t SimCardInterface::GetMaxSimCount()
{
    if (GetServiceProxy()) {
        return simCardService_->GetMaxSimCount();
    }
    return INVALID_VALUE;
}
} // namespace Telephony
} // namespace OHOS