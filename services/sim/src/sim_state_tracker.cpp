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
    operatorConfigLoader_ = std::make_unique<OperatorConfigLoader>(simFileManager, operatorConfigCache);
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
        if (!CoreManagerInner::GetInstance().HasSimCard(slotId_)) {
            TELEPHONY_LOGE("sim is not exist");
            return;
        }
        operatorConfigLoader_->LoadOperatorConfig(slotId_);
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
} // namespace Telephony
} // namespace OHOS
