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
#include "kit_core_service_hilog_wrapper.h"
#include "system_ability_definition.h"
namespace OHOS {
SimCardManager::SimCardManager()
{
    int32_t connectResult = ConnectService();
    HILOG_DEBUG("SimCardManager::SimCardManager when ConnectService() result = %{public}d", connectResult);
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
        return simManagerInterface_->GetSimState(slotId);
    }
    return -1;
}

std::u16string SimCardManager::GetIsoCountryCode(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetIsoCountryCode(slotId);
    }
    return u"";
}

std::u16string SimCardManager::GetOperatorNumeric(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetOperatorNumeric(slotId);
    }
    return u"";
}

std::u16string SimCardManager::GetSpn(int32_t slotId)
{
    if (simManagerInterface_ != nullptr) {
        return simManagerInterface_->GetSpn(slotId);
    }
    return u"";
}

int32_t SimCardManager::ConnectService()
{
    auto systemAblilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAblilityManager == nullptr) {
        return -1;
    }
    sptr<IRemoteObject> object = systemAblilityManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (object != nullptr) {
        simManagerInterface_ = iface_cast<ICoreService>(object);
    }
    return (simManagerInterface_ == nullptr) ? -1 : 0;
}
} // namespace OHOS
