/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "sim_account_manager.h"

#include "string_ex.h"

namespace OHOS {
namespace Telephony {
SimAccountManager::SimAccountManager(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
    std::shared_ptr<SimStateManager> simStateManager, std::shared_ptr<SimFileManager> simFileManager)
    : telRilManager_(telRilManager), simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("SimAccountManager construct");
}

SimAccountManager::~SimAccountManager()
{
    if (simStateTracker_ != nullptr) {
        simStateTracker_->UnRegisterForIccLoaded();
        simStateTracker_->UnRegisterOpkeyLoaded();
        simStateTracker_->UnregisterOperatorCacheDel();
    }
    if (operatorConfigCache_ != nullptr) {
        operatorConfigCache_->UnRegisterForIccChange();
    }
}

void SimAccountManager::Init(int32_t slotId)
{
    TELEPHONY_LOGI("SimAccountManager::Init = %{public}d", slotId);
    if ((telRilManager_ == nullptr) || (simFileManager_ == nullptr) || (simStateManager_ == nullptr)) {
        TELEPHONY_LOGE("can not init simAccountManager");
        return;
    }
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("SimAccountManager::init SimAccountManager invalid slotId = %{public}d", slotId);
        return;
    }
    operatorConfigCache_ =
        std::make_shared<OperatorConfigCache>(std::weak_ptr<SimFileManager>(simFileManager_), slotId);
    if (operatorConfigCache_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::operatorConfigCache_ is null");
        return;
    }
    operatorConfigCache_->RegisterForIccChange();
    simStateTracker_ =
        std::make_shared<SimStateTracker>(std::weak_ptr<SimFileManager>(simFileManager_), operatorConfigCache_, slotId);
    if (simStateTracker_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::simStateTracker_ is null");
        return;
    }
    simStateTracker_->RegisterForIccLoaded();
    simStateTracker_->RegisterOpkeyLoaded();
    simStateTracker_->RegisterOperatorCacheDel();
}

int32_t SimAccountManager::GetOperatorConfigs(int32_t slotId, OHOS::Telephony::OperatorConfig &poc)
{
    TELEPHONY_LOGD("SimAccountManager::GetOperatorConfigs");
    if (operatorConfigCache_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetOperatorConfigs operatorConfigCache_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return operatorConfigCache_->GetOperatorConfigs(static_cast<int32_t>(slotId), poc);
}

int32_t SimAccountManager::UpdateOperatorConfigs(int32_t slotId)
{
    if (operatorConfigCache_ == nullptr) {
        TELEPHONY_LOGE("operatorConfigCache_ is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return operatorConfigCache_->UpdateOperatorConfigs(slotId);
}

bool SimAccountManager::IsValidSlotId(int32_t slotId)
{
    int32_t count = SIM_SLOT_COUNT;
    if ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < count)) {
        return true;
    } else {
        TELEPHONY_LOGE("SimAccountManager slotId is InValid = %{public}d", slotId);
        return false;
    }
}

bool SimAccountManager::IsValidSlotIdForDefault(int32_t slotId)
{
    int32_t count = SIM_SLOT_COUNT;
    if ((slotId >= DEFAULT_SIM_SLOT_ID_REMOVE) && (slotId < count)) {
        return true;
    } else {
        return false;
    }
}

int32_t SimAccountManager::HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges)
{
    TELEPHONY_LOGD("SimAccountManager::HasOperatorPrivileges begin");
    if (privilegeController_ != nullptr) {
        return privilegeController_->HasOperatorPrivileges(hasOperatorPrivileges);
    }
    if ((telRilManager_ == nullptr) || (simStateManager_ == nullptr)) {
        TELEPHONY_LOGE("has nullptr at telRilManager_ or simStateManager_");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto controller = std::make_shared<IccOperatorPrivilegeController>(telRilManager_, simStateManager_);
    if (controller == nullptr) {
        TELEPHONY_LOGE("Make IccOperatorPrivilegeController fail!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    controller->Init(slotId);
    privilegeController_ = controller;
    return controller->HasOperatorPrivileges(hasOperatorPrivileges);
}
} // namespace Telephony
} // namespace OHOS
