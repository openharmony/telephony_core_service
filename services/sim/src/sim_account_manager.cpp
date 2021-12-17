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
SimAccountManager::SimAccountManager(std::shared_ptr<ISimStateManager> simStateManager,
    std::shared_ptr<ISimFileManager> simFileManager, std::shared_ptr<INetworkSearch> networkSearchManager)
    : simStateManager_(simStateManager), simFileManager_(simFileManager),
    netWorkSearchManager_(networkSearchManager)
{
    TELEPHONY_LOGI("SimAccountManager construct");
}

SimAccountManager::~SimAccountManager() {}

void SimAccountManager::Init(int32_t slotId)
{
    TELEPHONY_LOGI("SimAccountManager::Init = %{public}d", slotId);
    if (simFileManager_ == nullptr || simStateManager_ == nullptr || netWorkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("can not init simAccountManager");
        return;
    }
    TELEPHONY_LOGI("SimAccountManager::make MultiSimController");
    multiSimController_ =
        std::make_shared<MultiSimController>(simStateManager_, simFileManager_, netWorkSearchManager_, slotId);
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager:: multiSimController is null");
        return;
    }
    runner_ = AppExecFwk::EventRunner::Create("SimAccountManager");
    if (runner_.get() == nullptr) {
        TELEPHONY_LOGE("get runner_ failed");
        return;
    }
    multiSimMonitor_ =
        std::make_shared<MultiSimMonitor>(runner_, multiSimController_, simStateManager_, simFileManager_);
    simStateTracker_ = std::make_shared<SimStateTracker>(runner_, simFileManager_);
    if (multiSimMonitor_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager:: multiSimMonitor is null");
        return;
    }
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("SimAccountManager::init multiSimMonitor invalid slotId = %d", slotId);
        return;
    }
    multiSimMonitor_->Init(slotId);
    multiSimMonitor_->RegisterForIccLoaded();
    if (simStateTracker_ == nullptr) {
        TELEPHONY_LOGE("SimAccountManager:: simStateTracker_ is null");
        return;
    }
    simStateTracker_->RegisterForIccLoaded();
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
        TELEPHONY_LOGE("SimAccountManager::SetDefaultSmsSlotId invalid slotId = %d", slotId);
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
        TELEPHONY_LOGE("SimAccountManager::SetDefaultCellularDataSlotId invalid slotId = %d", slotId);
        return false;
    }
    return multiSimController_->SetDefaultCellularDataSlotId(slotId);
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
    int32_t count = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetMaxSimCount();
    if ((slotId >= CoreManager::DEFAULT_SLOT_ID) && (slotId < count)) {
        return true;
    } else {
        TELEPHONY_LOGE("SimAccountManager slotId is InValid = %d", slotId);
        return false;
    }
}
} // namespace Telephony
} // namespace OHOS