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
#include "os_account_manager_wrapper.h"
#include "radio_event.h"
#include "thread"

namespace OHOS {
namespace Telephony {
const int32_t ACTIVE_USER_ID = 100;
SimStateTracker::SimStateTracker(std::weak_ptr<SimFileManager> simFileManager,
    std::shared_ptr<OperatorConfigCache> operatorConfigCache, int32_t slotId)
    : TelEventHandler("SimStateTracker"), simFileManager_(simFileManager), operatorConfigCache_(operatorConfigCache),
      slotId_(slotId)
{
    if (simFileManager.lock() == nullptr) {
        TELEPHONY_LOGE("can not make OperatorConfigLoader");
    }
    operatorConfigLoader_ = std::make_shared<OperatorConfigLoader>(simFileManager, operatorConfigCache);
    InitListener();
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

void SimStateTracker::InitListener()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(slotId_, operatorConfigLoader_);
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("samgrProxy or statusChangeListener_ is nullptr");
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, statusChangeListener_);
    TELEPHONY_LOGI("SubscribeSystemAbility SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN result:%{public}d", ret);
    ret = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
    TELEPHONY_LOGI("SubscribeSystemAbility COMMON_EVENT_SERVICE_ID result:%{public}d", ret);
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
        TelFFRTUtils::Submit([&]() { operatorConfigLoader_->LoadOperatorConfig(slotId_); });
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

SimStateTracker::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    int32_t slotId, std::shared_ptr<OperatorConfigLoader> configLoader)
    : slotId_(slotId), configLoader_(configLoader)
{}

void SimStateTracker::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    if (configLoader_ == nullptr) {
        TELEPHONY_LOGE("configLoader_ is nullptr.");
        return;
    }
    switch (systemAbilityId) {
        case SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN: {
            TELEPHONY_LOGI("SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN running");
            std::vector<int32_t> activeList = { 0 };
            DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->QueryActiveOsAccountIds(activeList);
            TELEPHONY_LOGI("current active user id is :%{public}d", activeList[0]);
            if (activeList[0] == ACTIVE_USER_ID) {
                configLoader_->LoadOperatorConfig(slotId_);
            }
            break;
        }
        case COMMON_EVENT_SERVICE_ID: {
            TELEPHONY_LOGI("COMMON_EVENT_SERVICE_ID running");
            MatchingSkills matchingSkills;
            matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
            CommonEventSubscribeInfo subscriberInfo(matchingSkills);
            subscriberInfo.SetThreadMode(CommonEventSubscribeInfo::COMMON);
            userSwitchSubscriber_ = std::make_shared<UserSwitchEventSubscriber>(subscriberInfo, slotId_, configLoader_);
            bool subRet = CommonEventManager::SubscribeCommonEvent(userSwitchSubscriber_);
            TELEPHONY_LOGI("Subscribe user switched subRet is :%{public}d", subRet);
            break;
        }
        default:
            TELEPHONY_LOGE("systemAbilityId is invalid");
            break;
    }
}

void SimStateTracker::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    switch (systemAbilityId) {
        case SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN: {
            TELEPHONY_LOGE("SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN stopped");
            break;
        }
        case COMMON_EVENT_SERVICE_ID: {
            TELEPHONY_LOGE("COMMON_EVENT_SERVICE_ID stopped");
            if (userSwitchSubscriber_ != nullptr) {
                bool subRet = CommonEventManager::UnSubscribeCommonEvent(userSwitchSubscriber_);
                TELEPHONY_LOGI("Unsubscribe user switched subRet is :%{public}d", subRet);
                userSwitchSubscriber_ = nullptr;
            }
            break;
        }
        default:
            TELEPHONY_LOGE("systemAbilityId is invalid");
            break;
    }
}

void SimStateTracker::UserSwitchEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    OHOS::EventFwk::Want want = data.GetWant();
    std::string action = data.GetWant().GetAction();
    TELEPHONY_LOGI("action = %{public}s", action.c_str());
    if (action == CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t userId = data.GetCode();
        TELEPHONY_LOGI("current user id is :%{public}d", userId);
        if (userId == ACTIVE_USER_ID) {
            configLoader_->LoadOperatorConfig(slotId_);
        }
    }
}
} // namespace Telephony
} // namespace OHOS
