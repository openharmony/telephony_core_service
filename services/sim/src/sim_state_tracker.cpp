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

#include "core_manager_inner.h"
#include "radio_event.h"
#include "thread"

namespace OHOS {
namespace Telephony {
SimStateTracker::SimStateTracker(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    std::shared_ptr<SimFileManager> simFileManager, std::shared_ptr<OperatorConfigCache> operatorConfigCache,
    int32_t slotId)
    : AppExecFwk::EventHandler(runner), simFileManager_(simFileManager), operatorConfigCache_(operatorConfigCache),
      slotId_(slotId)
{
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not make OperatorConfigLoader");
    }
    operatorConfigLoader_ = std::make_shared<OperatorConfigLoader>(simFileManager, operatorConfigCache);
    InitListener();
}

void SimStateTracker::InitListener()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(slotId_, operatorConfigLoader_);
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("samgrProxy or statusChangeListener_ is nullptr");
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, statusChangeListener_);
    TELEPHONY_LOGI("SubscribeSystemAbility DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID result:%{public}d", ret);
}

void SimStateTracker::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    if (operatorConfigLoader_ == nullptr) {
        TELEPHONY_LOGE("operatorConfigLoader_ is null!");
        return;
    }
    if (event->GetInnerEventId() == RadioEvent::RADIO_SIM_RECORDS_LOADED) {
        TELEPHONY_LOGI("SimStateTracker::Refresh config");
        auto slotId = event->GetParam();
        if (slotId != slotId_) {
            TELEPHONY_LOGE("is not current slotId");
            return;
        }
        bool hasSimCard = false;
        CoreManagerInner::GetInstance().HasSimCard(slotId_, hasSimCard);
        if (!hasSimCard) {
            TELEPHONY_LOGE("sim is not exist");
            return;
        }
        std::thread loadOperatorConfigTask([&]() {
            pthread_setname_np(pthread_self(), "load_operator_config");
            operatorConfigLoader_->LoadOperatorConfig(slotId_);
        });
        loadOperatorConfigTask.detach();
    }
}

bool SimStateTracker::RegisterForIccLoaded()
{
    TELEPHONY_LOGI("SimStateTracker::RegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("SimStateTracker::can not get SimFileManager");
        return false;
    }
    simFileManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool SimStateTracker::UnRegisterForIccLoaded()
{
    TELEPHONY_LOGI("SimStateTracker::UnRegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("SimStateTracker::can not get SimFileManager");
        return false;
    }
    simFileManager_->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

SimStateTracker::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    int32_t slotId, std::shared_ptr<OperatorConfigLoader> configLoader)
    : slotId_(slotId), configLoader_(configLoader)
{}

void SimStateTracker::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId == DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID && configLoader_ != nullptr) {
        TELEPHONY_LOGI("SystemAbilityStatusChangeListener::LoadOperatorConfig");
        configLoader_->LoadOperatorConfig(slotId_);
    }
}

void SimStateTracker::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId == DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        TELEPHONY_LOGE("DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID stopped");
    }
}
} // namespace Telephony
} // namespace OHOS
