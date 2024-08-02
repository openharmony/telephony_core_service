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
#include "telephony_ext_wrapper.h"
#include "thread"

namespace OHOS {
namespace Telephony {
constexpr int32_t OPKEY_VMSG_LENTH = 3;
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
    TelFFRTUtils::Submit([&]() { operatorConfigLoader_->LoadOperatorConfig(slotId_); });
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
    std::string opkey = (*msgObj)[1];
    std::string opName = (*msgObj)[2];
    TELEPHONY_LOGI("OnOpkeyLoad slotId, %{public}d opkey: %{public}s opName: %{public}s",
        slotId, opkey.data(), opName.data());
    if (!opkey.empty()) {
        auto simFileManager = simFileManager_.lock();
        if (simFileManager != nullptr) {
            simFileManager->SetOpKey(opkey);
            simFileManager->SetOpName(opName);
        }
        TelFFRTUtils::Submit([&]() {
            OperatorConfig opc;
            operatorConfigCache_->LoadOperatorConfig(slotId_, opc);
        });
    } else {
        bool hasSimCard = false;
        CoreManagerInner::GetInstance().HasSimCard(slotId_, hasSimCard);
        if (!hasSimCard) {
            TELEPHONY_LOGE("sim is not exist");
            return;
        }
        TelFFRTUtils::Submit([&]() { operatorConfigLoader_->LoadOperatorConfig(slotId_); });
    }
}

void SimStateTracker::ProcessOperatorCacheDel(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("SimStateTracker::ProcessOperatorCacheDel");
    auto slotId = event->GetParam();
    if (slotId != slotId_) {
        TELEPHONY_LOGE("is not current slotId");
        return;
    }
    if (operatorConfigCache_ == nullptr) {
        TELEPHONY_LOGE("operatorConfigCache is nullptr");
        return;
    }
    operatorConfigCache_->ClearMemoryAndOpkey(slotId);
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
        ProcessSimRecordLoad(event);
    }

    if (event->GetInnerEventId() == RadioEvent::RADIO_SIM_OPKEY_LOADED) {
        ProcessSimOpkeyLoad(event);
    }

    if (event->GetInnerEventId() == RadioEvent::RADIO_OPERATOR_CACHE_DELETE) {
        ProcessOperatorCacheDel(event);
    }
}

bool SimStateTracker::RegisterForIccLoaded()
{
    TELEPHONY_LOGI("SimStateTracker::RegisterForIccLoaded");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("SimStateTracker::can not get SimFileManager");
        return false;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool SimStateTracker::RegisterOpkeyLoaded()
{
    TELEPHONY_LOGI("SimStateTracker::RegisterOpkeyLoaded");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("simFileManager::can not get simFileManager");
        return false;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_OPKEY_LOADED);
    return true;
}

bool SimStateTracker::RegisterOperatorCacheDel()
{
    TELEPHONY_LOGI("SimStateTracker::RegisterOperatorCacheDel");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("simFileManager::can not get simFileManager");
        return false;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_OPERATOR_CACHE_DELETE);
    return true;
}

bool SimStateTracker::UnRegisterForIccLoaded()
{
    TELEPHONY_LOGI("SimStateTracker::UnRegisterForIccLoaded");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("SimStateTracker::can not get SimFileManager");
        return false;
    }
    simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool SimStateTracker::UnRegisterOpkeyLoaded()
{
    TELEPHONY_LOGI("SimStateTracker::UnRegisterOpkeyLoaded");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("simFileManager::can not get simFileManager");
        return false;
    }
    simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_OPKEY_LOADED);
    return true;
}

bool SimStateTracker::UnregisterOperatorCacheDel()
{
    TELEPHONY_LOGI("SimStateTracker::UnregisterOperatorCacheDel");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("simFileManager::can not get simFileManager");
        return false;
    }
    simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_OPERATOR_CACHE_DELETE);
    return true;
}
} // namespace Telephony
} // namespace OHOS
