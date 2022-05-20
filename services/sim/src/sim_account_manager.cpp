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

SimAccountManager::~SimAccountManager() {}

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
    TELEPHONY_LOGI("SimAccountManager::make MultiSimController");
    controllerRunner_ = AppExecFwk::EventRunner::Create("MultiSimController");
    if (controllerRunner_.get() == nullptr) {
        TELEPHONY_LOGE("get controllerRunner_ failed");
        return;
    }
    multiSimController_ = std::make_shared<MultiSimController>(
        telRilManager_, simStateManager_, simFileManager_, controllerRunner_, slotId);
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager:: multiSimController is null");
        return;
    }
    multiSimController_->Init();
    monitorRunner_ = AppExecFwk::EventRunner::Create("MultiSimMonitor");
    if (monitorRunner_.get() == nullptr) {
        TELEPHONY_LOGE("get monitorRunner_ failed");
        return;
    }
    multiSimMonitor_ = std::make_shared<MultiSimMonitor>(
        monitorRunner_, multiSimController_, simStateManager_, simFileManager_, slotId);
    simStateTracker_ = std::make_shared<SimStateTracker>(monitorRunner_, simFileManager_, slotId);
    if (multiSimMonitor_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager:: multiSimMonitor is null");
        return;
    }
    multiSimMonitor_->Init();
    multiSimMonitor_->RegisterForIccLoaded();
    if (simStateTracker_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::simStateTracker_ is null");
        return;
    }
    simStateTracker_->RegisterForIccLoaded();
}

void SimAccountManager::SetNetworkSearchManager(std::shared_ptr<INetworkSearch> networkSearchManager)
{
    TELEPHONY_LOGI("SimAccountManager::SetNetworkSearchManager");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::SetNetworkSearchManager failed by nullptr");
        return;
    }
    multiSimController_->SetNetworkSearchManager(networkSearchManager);
}

void SimAccountManager::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    if (multiSimMonitor_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::RegisterCoreNotify failed by nullptr");
        return;
    }
    multiSimMonitor_->RegisterCoreNotify(handler, what);
}

bool SimAccountManager::IsSimActive(int32_t slotId)
{
    TELEPHONY_LOGI("SimAccountManager::IsSimActive");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::IsSimActive failed by nullptr");
        return false;
    }
    return multiSimController_->IsSimActive(slotId);
}

bool SimAccountManager::IsSimActivatable(int32_t slotId)
{
    TELEPHONY_LOGI("SimAccountManager::IsSimActivatable");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::IsSimActivatable failed by nullptr");
        return false;
    }
    return multiSimController_->IsSimActivatable(slotId);
}

bool SimAccountManager::SetActiveSim(int32_t slotId, int32_t enable)
{
    TELEPHONY_LOGI("SimAccountManager::SetActiveSim");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::SetActiveSim failed by nullptr");
        return false;
    }
    return multiSimController_->SetActiveSim(slotId, enable);
}

bool SimAccountManager::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetSimAccountInfo failed by nullptr");
        return false;
    }
    return multiSimController_->GetSimAccountInfo(slotId, info);
}

bool SimAccountManager::SetDefaultVoiceSlotId(int32_t slotId)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::SetDefaultVoiceSlotId failed by nullptr");
        return false;
    }
    return multiSimController_->SetDefaultVoiceSlotId(slotId);
}

bool SimAccountManager::SetDefaultSmsSlotId(int32_t slotId)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::SetDefaultSmsSlotId failed by nullptr");
        return false;
    }
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("SimAccountManager::SetDefaultSmsSlotId invalid slotId = %{public}d", slotId);
        return false;
    }
    return multiSimController_->SetDefaultSmsSlotId(slotId);
}

int32_t SimAccountManager::GetDefaultVoiceSlotId()
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetDefaultVoiceSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    return multiSimController_->GetDefaultVoiceSlotId();
}

int32_t SimAccountManager::GetDefaultSmsSlotId()
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetDefaultSmsSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    return multiSimController_->GetDefaultSmsSlotId();
}

bool SimAccountManager::SetDefaultCellularDataSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("SetDefaultCellularDataSlotId");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::SetDefaultCellularDataSlotId failed by nullptr");
        return false;
    }
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("SimAccountManager::SetDefaultCellularDataSlotId invalid slotId = %{public}d", slotId);
        return false;
    }
    return multiSimController_->SetDefaultCellularDataSlotId(slotId);
}

bool SimAccountManager::SetPrimarySlotId(int32_t slotId)
{
    TELEPHONY_LOGI("SetPrimarySlotId");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::SetPrimarySlotId failed by nullptr");
        return false;
    }
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("SimAccountManager::SetPrimarySlotId invalid slotId = %{public}d", slotId);
        return false;
    }
    return multiSimController_->SetPrimarySlotId(slotId);
}

int32_t SimAccountManager::GetDefaultCellularDataSlotId()
{
    TELEPHONY_LOGI("SimAccountManager::GetDefaultCellularDataSlotId");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetDefaultCellularDataSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    return multiSimController_->GetDefaultCellularDataSlotId();
}

int32_t SimAccountManager::GetPrimarySlotId()
{
    TELEPHONY_LOGI("SimAccountManager::GetPrimarySlotId");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetPrimarySlotId failed by nullptr");
        return INVALID_VALUE;
    }
    return multiSimController_->GetPrimarySlotId();
}

bool SimAccountManager::SetShowNumber(int32_t slotId, const std::u16string number)
{
    TELEPHONY_LOGI("SimAccountManager::SetShowNumber");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::SetShowNumber failed by nullptr");
        return false;
    }
    return multiSimController_->SetShowNumber(slotId, number);
}

std::u16string SimAccountManager::GetShowNumber(int32_t slotId)
{
    TELEPHONY_LOGI("SimAccountManager::GetShowNumber");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetShowNumber failed by nullptr");
        return u"";
    }
    return multiSimController_->GetShowNumber(slotId);
}

bool SimAccountManager::SetShowName(int32_t slotId, const std::u16string name)
{
    TELEPHONY_LOGI("SimAccountManager::SetShowName");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::SetShowName failed by nullptr");
        return false;
    }
    return multiSimController_->SetShowName(slotId, name);
}

std::u16string SimAccountManager::GetShowName(int32_t slotId)
{
    TELEPHONY_LOGI("SimAccountManager::GetShowName");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetShowName failed by nullptr");
        return u"";
    }
    return multiSimController_->GetShowName(slotId);
}

bool SimAccountManager::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    TELEPHONY_LOGI("SimAccountManager::GetActiveSimAccountInfoList");
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetActiveSimAccountInfoList failed by nullptr");
        return false;
    }
    if (multiSimController_->RefreshActiveIccAccountInfoList()) {
        iccAccountInfoList.clear();
        std::vector<IccAccountInfo>::iterator it = multiSimController_->iccAccountInfoList_.begin();
        while (it != multiSimController_->iccAccountInfoList_.end()) {
            TELEPHONY_LOGI("SimAccountManager::GetActiveSimAccountInfoList slotIndex=%{public}d", it->slotIndex);
            iccAccountInfoList.emplace_back(*it);
            it++;
        }
    } else {
        TELEPHONY_LOGE("SimAccountManager::GetActiveSimAccountInfoList refresh failed");
        return false;
    }
    if (iccAccountInfoList.size() > 0) {
        return true;
    } else {
        TELEPHONY_LOGE("SimAccountManager::GetActiveSimAccountInfoList nothing actived");
        return false;
    }
}

bool SimAccountManager::GetOperatorConfigs(int slotId, OHOS::Telephony::OperatorConfig &poc)
{
    TELEPHONY_LOGI("SimAccountManager::GetOperatorConfigs");
    if (simStateTracker_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager::GetOperatorConfigs failed by nullptr");
        return false;
    }
    return simStateTracker_->GetOperatorConfigs(slotId, poc);
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

bool SimAccountManager::HasOperatorPrivileges(const int32_t slotId)
{
    TELEPHONY_LOGI("SimAccountManager::HasOperatorPrivileges begin");
    if (privilegeController_ != nullptr) {
        return privilegeController_->HasOperatorPrivileges();
    }
    if (privilegesRunner_.get() == nullptr) {
        TELEPHONY_LOGE("make privilegesRunner_");
        privilegesRunner_ = AppExecFwk::EventRunner::Create("PrivilegeController");
    }
    if ((privilegesRunner_ == nullptr) || (telRilManager_ == nullptr) || (simStateManager_ == nullptr)) {
        TELEPHONY_LOGE("has nullptr at privilegesRunner_ or telRilManager_ or simStateManager_");
        return false;
    }
    auto controller =
        std::make_shared<IccOperatorPrivilegeController>(privilegesRunner_, telRilManager_, simStateManager_);
    if (controller == nullptr) {
        TELEPHONY_LOGE("Make IccOperatorPrivilegeController fail!!");
        return false;
    }
    controller->Init(slotId);
    privilegeController_ = controller;
    return controller->HasOperatorPrivileges();
}
} // namespace Telephony
} // namespace OHOS