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

#include "radio_network_manager.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "kit_core_service_hilog_wrapper.h"
#include "system_ability_definition.h"

namespace OHOS {
RadioNetworkManager::RadioNetworkManager()
{
    ConnectService();
}

RadioNetworkManager::~RadioNetworkManager() {}

int32_t RadioNetworkManager::GetPsRadioTech(int32_t slotId)
{
    if (radioNetworkService_ != nullptr) {
        return radioNetworkService_->GetPsRadioTech(slotId);
    }
    return -1;
}

int32_t RadioNetworkManager::GetCsRadioTech(int32_t slotId)
{
    if (radioNetworkService_ != nullptr) {
        return radioNetworkService_->GetCsRadioTech(slotId);
    }
    return -1;
}

std::vector<sptr<OHOS::SignalInformation>> RadioNetworkManager::GetSignalInfoList(int32_t slotId)
{
    if (radioNetworkService_ != nullptr) {
        return radioNetworkService_->GetSignalInfoList(slotId);
    }
    return std::vector<sptr<OHOS::SignalInformation>>();
}

std::u16string RadioNetworkManager::GetOperatorNumeric(int32_t slotId)
{
    if (radioNetworkService_ != nullptr) {
        return radioNetworkService_->GetOperatorNumeric(slotId);
    }
    return u"";
}

std::u16string RadioNetworkManager::GetOperatorName(int32_t slotId)
{
    if (radioNetworkService_ != nullptr) {
        return radioNetworkService_->GetOperatorName(slotId);
    }
    return u"";
}

sptr<NetworkState> RadioNetworkManager::GetNetworkStatus(int32_t slotId)
{
    if (radioNetworkService_ != nullptr) {
        return sptr<NetworkState>(radioNetworkService_->GetNetworkStatus(slotId));
    }
    return nullptr;
}

int32_t RadioNetworkManager::ConnectService()
{
    auto abilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityManager == nullptr) {
        HILOG_ERROR("RadioNetworkManager::GetInstance().GetSystemAbilityManager() null\n");
        return -1;
    }

    sptr<IRemoteObject> object = abilityManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (object != nullptr) {
        HILOG_ERROR("RadioNetworkManager::ConnectService() IRemoteObject != null\n");
        radioNetworkService_ = iface_cast<ICoreService>(object);
    }
    if (radioNetworkService_ == nullptr) {
        HILOG_ERROR("radioNetworkService_ null\n");
        return -1;
    }
    HILOG_ERROR("RadioNetworkManager ConnectService success\n");
    return 0;
}
} // namespace OHOS
