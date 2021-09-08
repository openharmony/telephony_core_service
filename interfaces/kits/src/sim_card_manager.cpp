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
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "napi_sim_type.h"
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const int VALID_VALUE = 0;
const int INVALID_VALUE = -1;

SimState SimTypeConverted(ExternalState state)
{
    switch (state) {
        case EX_READY:
            return SIM_STATE_READY;
        case EX_PIN_LOCKED:
        case EX_PUK_LOCKED:
        case EX_SIMLOCK:
        case EX_BLOCKED_PERM:
            return SIM_STATE_LOCKED;
        case EX_ICC_ERROR:
        case EX_ICC_RESTRICTED:
        case EX_UNREADY:
            return SIM_STATE_NOT_READY;
        case EX_ABSENT:
            return SIM_STATE_NOT_PRESENT;
        default:
            return SIM_STATE_UNKNOWN;
    }
}
} // namespace

SimCardManager::SimCardManager() : simManagerInterface_(nullptr) {}

bool SimCardManager::IsConnect()
{
    return simManagerInterface_ != nullptr;
}

SimCardManager::~SimCardManager() {}

bool SimCardManager::HasSimCard(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->HasSimCard(slotId);
    }
    return false;
}

int32_t SimCardManager::GetSimState(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        int32_t result = simManagerInterface_->GetSimState(slotId);
        if ((result >= EX_UNKNOWN) && (result <= EX_ICC_RESTRICTED)) {
            ExternalState state = static_cast<ExternalState>(result);
            return static_cast<int32_t>(SimTypeConverted(state));
        }
    }
    return INVALID_VALUE;
}

std::u16string SimCardManager::GetIsoCountryCodeForSim(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetIsoCountryCodeForSim(slotId);
    }
    return u"";
}

std::u16string SimCardManager::GetSimOperatorNumeric(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetSimOperatorNumeric(slotId);
    }
    return u"";
}

std::u16string SimCardManager::GetSimSpn(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetSimSpn(slotId);
    }
    return u"";
}

int32_t SimCardManager::ConnectService()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        return INVALID_VALUE;
    }
    sptr<IRemoteObject> object = systemAbilityManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (object != nullptr) {
        simManagerInterface_ = iface_cast<ICoreService>(object);
    }
    return (simManagerInterface_ == nullptr) ? INVALID_VALUE : VALID_VALUE;
}

std::u16string SimCardManager::getLocaleFromDefaultSim()
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetLocaleFromDefaultSim();
    }
    return u"";
}

std::u16string SimCardManager::GetSimGid1(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetSimGid1(slotId);
    }
    return u"";
}

bool SimCardManager::GetSimAccountInfo(int32_t subId, IccAccountInfo &info)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetSimAccountInfo(subId, info);
    }
    return false;
}

bool SimCardManager::SetDefaultVoiceSlotId(int32_t subId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->SetDefaultVoiceSlotId(subId);
    }
    return false;
}

int32_t SimCardManager::GetDefaultVoiceSlotId()
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetDefaultVoiceSlotId();
    }
    return INVALID_VALUE;
}

bool SimCardManager::UnlockPin(std::u16string pin, LockStatusResponse &response, int32_t phoneId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->UnlockPin(pin, response, phoneId);
    }
    return false;
}

bool SimCardManager::UnlockPuk(
    std::u16string newPin, std::u16string puk, LockStatusResponse &response, int32_t phoneId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->UnlockPuk(newPin, puk, response, phoneId);
    }
    return false;
}

bool SimCardManager::AlterPin(
    std::u16string newPin, std::u16string oldPin, LockStatusResponse &response, int32_t phoneId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->AlterPin(newPin, oldPin, response, phoneId);
    }
    return false;
}

bool SimCardManager::SetLockState(std::u16string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->SetLockState(pin, enable, response, phoneId);
    }
    return false;
}

int32_t SimCardManager::RefreshSimState(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->RefreshSimState(slotId);
    }
    return INVALID_VALUE;
}

std::u16string SimCardManager::GetSimIccId(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetSimIccId(slotId);
    }
    return u"";
}

bool SimCardManager::IsSimActive(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->IsSimActive(slotId);
    }
    return false;
}

std::u16string SimCardManager::GetIMSI(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetIMSI(slotId);
    }
    return u"";
}
} // namespace Telephony
} // namespace OHOS
