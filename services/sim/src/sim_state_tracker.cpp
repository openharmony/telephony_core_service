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

#include "sim_state_tracker.h"

#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "radio_event.h"
#include "telephony_types.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t OPKEY_VMSG_LENTH = 3;
constexpr const char *IS_UPDATE_OPERATORCONFIG = "telephony.is_update_operatorconfig";
constexpr const char *IS_BLOCK_LOAD_OPERATORCONFIG = "telephony.is_block_load_operatorconfig";
SimStateTracker::SimStateTracker(std::weak_ptr<SimFileManager> simFileManager,
    std::shared_ptr<OperatorConfigCache> operatorConfigCache, int32_t slotId)
    : TelEventHandler("SimStateTracker"), simFileManager_(simFileManager), operatorConfigCache_(operatorConfigCache),
      slotId_(slotId)
{
    if (simFileManager.lock() == nullptr) {
        TELEPHONY_LOGE("can not make OperatorConfigLoader");
    }
    operatorConfigLoader_ = std::make_shared<OperatorConfigLoader>(simFileManager, operatorConfigCache);
}

SimStateTracker::~SimStateTracker()
{
    if (statusChangeListener_ != nullptr) {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy != nullptr) {
            samgrProxy->UnSubscribeSystemAbility(OHOS::SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, statusChangeListener_);
            samgrProxy->UnSubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, statusChangeListener_);
            statusChangeListener_ = nullptr;
        }
    }
}

void SimStateTracker::ProcessSimRecordLoad(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto slotId = event->GetParam();
    if (slotId != slotId_) {
        TELEPHONY_LOGE("is not current slotId");
        return;
    }
    std::string key = "";
    char isBlockLoadOperatorConfig[SYSPARA_SIZE] = { 0 };
    GetParameter(key.append(IS_BLOCK_LOAD_OPERATORCONFIG).append(std::to_string(slotId)).c_str(),
        "false", isBlockLoadOperatorConfig, SYSPARA_SIZE);
    if (strcmp(isBlockLoadOperatorConfig, "true") == 0) {
        TELEPHONY_LOGE("slotId: %{public}d BlockLoadOperatorConfig is true", slotId_);
        return;
    }
    if (operatorConfigLoader_ == nullptr) {
        TELEPHONY_LOGE("operatorConfigLoader is null!");
        return;
    }
    TELEPHONY_LOGI("slotId: %{public}d need trigger LoadOperatorConfig", slotId_);
    if (IsNeedUpdateCarrierConfig()) {
        operatorConfigLoader_->LoadOperatorConfig(slotId_, operatorConfigCache_->STATE_PARA_UPDATE);
        ResetNeedUpdateCarrierConfig();
    } else {
        operatorConfigLoader_->LoadOperatorConfig(slotId_, operatorConfigCache_->STATE_PARA_LOADED);
    }
}

void SimStateTracker::ProcessSimOpkeyLoad(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<std::vector<std::string>> msgObj = event->GetSharedObject<std::vector<std::string>>();
    if ((msgObj == nullptr) || ((*msgObj).size() != OPKEY_VMSG_LENTH)) {
        TELEPHONY_LOGI("argument count error");
        return;
    }
    int slotId;
    if (!StrToInt((*msgObj)[0], slotId)) {
        return;
    }
    if (slotId != slotId_) {
        TELEPHONY_LOGE("is not current slotId");
        return;
    }
    std::string key = "";
    char isBlockLoadOperatorConfig[SYSPARA_SIZE] = { 0 };
    GetParameter(key.append(IS_BLOCK_LOAD_OPERATORCONFIG).append(std::to_string(slotId)).c_str(),
        "false", isBlockLoadOperatorConfig, SYSPARA_SIZE);
    if (strcmp(isBlockLoadOperatorConfig, "true") == 0) {
        TELEPHONY_LOGE("slotId: %{public}d BlockLoadOperatorConfig is true", slotId_);
        return;
    }
    std::string opkey = (*msgObj)[1];
    std::string opName = (*msgObj)[2];
    TELEPHONY_LOGI("OnOpkeyLoad slotId, %{public}d opkey: %{public}s opName: %{public}s",
        slotId, opkey.data(), opName.data());
    if (!opkey.empty() && !opName.empty()) {
        auto simFileManager = simFileManager_.lock();
        if (simFileManager != nullptr) {
            simFileManager->SetOpKey(opkey);
            simFileManager->SetOpName(opName);
        }
        ReloadOperatorConfigCache();
    } else {
        auto simFileManager = simFileManager_.lock();
        if (simFileManager != nullptr) {
            simFileManager->SetOpKey("");
            simFileManager->SetOpName("");
        }
        bool hasSimCard = false;
        CoreManagerInner::GetInstance().HasSimCard(slotId_, hasSimCard);
        if (!hasSimCard) {
            TELEPHONY_LOGE("sim is not exist");
            return;
        }
        ReloadOperatorConfig();
    }
}

void SimStateTracker::ProcessOperatorCacheDel(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto slotId = event->GetParam();
    if (slotId != slotId_) {
        TELEPHONY_LOGE("is not current slotId");
        return;
    }
    if (operatorConfigCache_ == nullptr) {
        TELEPHONY_LOGE("operatorConfigCache is nullptr");
        return;
    }
    TELEPHONY_LOGI("need Clear memory and opkey, slotId: %{public}d", slotId_);
    operatorConfigCache_->ClearOperatorValue(slotId);
}

void SimStateTracker::ProcessOperatorConfigUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto slotId = event->GetParam();
    if (slotId != slotId_) {
        TELEPHONY_LOGE("is not current slotId");
        return;
    }
    bool hasSimCard = false;
    CoreManagerInner::GetInstance().HasSimCard(slotId_, hasSimCard);
    if (operatorConfigLoader_ == nullptr || operatorConfigCache_ == nullptr || !hasSimCard) {
        TELEPHONY_LOGE("operatorConfigLoader or operatorConfigCache is nullptr");
        return;
    }
    TELEPHONY_LOGI("need Clear opkey and reload operatorconfig, slotId: %{public}d", slotId_);
    operatorConfigCache_->ClearOperatorValue(slotId);
    CoreManagerInner::GetInstance().ResetDataShareError();
    std::string key = "";
    char isBlockLoadOperatorConfig[SYSPARA_SIZE] = { 0 };
    GetParameter(key.append(IS_BLOCK_LOAD_OPERATORCONFIG).append(std::to_string(slotId)).c_str(),
        "false", isBlockLoadOperatorConfig, SYSPARA_SIZE);
    if (strcmp(isBlockLoadOperatorConfig, "true") == 0) {
        SetParameter(key.c_str(), "false");
        operatorConfigLoader_->LoadOperatorConfig(slotId_, operatorConfigCache_->STATE_PARA_UPDATE);
    } else {
        operatorConfigLoader_->LoadOperatorConfig(slotId_, operatorConfigCache_->STATE_PARA_LOADED);
    }
}

void SimStateTracker::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    auto eventId = event->GetInnerEventId();
    switch (eventId) {
        case RadioEvent::RADIO_SIM_RECORDS_LOADED:
            ProcessSimRecordLoad(event);
            break;
        case RadioEvent::RADIO_SIM_OPKEY_LOADED:
            ProcessSimOpkeyLoad(event);
            break;
        case RadioEvent::RADIO_OPERATOR_CACHE_DELETE:
            ProcessOperatorCacheDel(event);
            break;
        case RadioEvent::RADIO_OPERATOR_CONFIG_UPDATE:
            ProcessOperatorConfigUpdate(event);
            break;
        default:
            TELEPHONY_LOGI("ProcessEvent default");
    }
}

bool SimStateTracker::RegisterForIccLoaded()
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not get SimFileManager");
        return false;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool SimStateTracker::RegisterOpkeyLoaded()
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_OPKEY_LOADED);
    return true;
}

bool SimStateTracker::RegisterOperatorCacheDel()
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_OPERATOR_CACHE_DELETE);
    return true;
}

bool SimStateTracker::RegisterOperatorConfigUpdate()
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_OPERATOR_CONFIG_UPDATE);
    return true;
}

bool SimStateTracker::UnRegisterForIccLoaded()
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not get SimFileManager");
        return false;
    }
    simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool SimStateTracker::UnRegisterOpkeyLoaded()
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_OPKEY_LOADED);
    return true;
}

bool SimStateTracker::UnregisterOperatorCacheDel()
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_OPERATOR_CACHE_DELETE);
    return true;
}

bool SimStateTracker::UnRegisterOperatorConfigUpdate()
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not get SimFileManager");
        return false;
    }
    simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_OPERATOR_CONFIG_UPDATE);
    return true;
}
 
bool SimStateTracker::IsNeedUpdateCarrierConfig()
{
    char isNeedUpdateCarrierConfig[SYSPARA_SIZE] = { 0 };
    std::string key = "";
    GetParameter(key.append(IS_UPDATE_OPERATORCONFIG).append(std::to_string(slotId_)).c_str(),
        "", isNeedUpdateCarrierConfig, SYSPARA_SIZE);
    bool result = strcmp(isNeedUpdateCarrierConfig, "true") == 0;
    return result;
}
 
void SimStateTracker::ResetNeedUpdateCarrierConfig()
{
    std::string key = "";
    SetParameter(key.append(IS_UPDATE_OPERATORCONFIG).append(std::to_string(slotId_)).c_str(), "false");
}
 
void SimStateTracker::ReloadOperatorConfigCache()
{
    if (operatorConfigCache_ == nullptr) {
        TELEPHONY_LOGE("operatorConfigCache is null!");
        return;
    }
    OperatorConfig opc;
    if (IsNeedUpdateCarrierConfig()) {
        operatorConfigCache_->LoadOperatorConfig(slotId_, opc, operatorConfigCache_->STATE_PARA_UPDATE);
        ResetNeedUpdateCarrierConfig();
    } else {
        operatorConfigCache_->LoadOperatorConfig(slotId_, opc, operatorConfigCache_->STATE_PARA_LOADED);
    }
}
 
void SimStateTracker::ReloadOperatorConfig()
{
    if (operatorConfigLoader_ == nullptr) {
        TELEPHONY_LOGE("operatorConfigLoader is null!");
        return;
    }
    if (IsNeedUpdateCarrierConfig()) {
        operatorConfigLoader_->LoadOperatorConfig(slotId_, operatorConfigCache_->STATE_PARA_UPDATE);
        ResetNeedUpdateCarrierConfig();
    } else {
        operatorConfigLoader_->LoadOperatorConfig(slotId_, operatorConfigCache_->STATE_PARA_LOADED);
    }
}
} // namespace Telephony
} // namespace OHOS
