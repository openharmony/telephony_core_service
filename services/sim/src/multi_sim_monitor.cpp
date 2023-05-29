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

#include "multi_sim_monitor.h"

#include "common_event_manager.h"
#include "common_event_support.h"
#include "os_account_manager_wrapper.h"
#include "radio_event.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
const int32_t ACTIVE_USER_ID = 100;
MultiSimMonitor::MultiSimMonitor(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::shared_ptr<MultiSimController> &controller,
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager)
    : AppExecFwk::EventHandler(runner), controller_(controller), simStateManager_(simStateManager),
      simFileManager_(simFileManager)
{
    if (observerHandler_ == nullptr) {
        observerHandler_ = std::make_unique<ObserverHandler>();
    }
}

MultiSimMonitor::~MultiSimMonitor()
{
    if (statusChangeListener_ != nullptr) {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy != nullptr) {
            samgrProxy->UnSubscribeSystemAbility(OHOS::SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, statusChangeListener_);
            statusChangeListener_ = nullptr;
        }
    }
}

void MultiSimMonitor::Init()
{
    InitListener();
}

void MultiSimMonitor::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    auto eventCode = event->GetInnerEventId();
    switch (eventCode) {
        case RadioEvent::RADIO_SIM_RECORDS_LOADED: {
            auto slotId = event->GetParam();
            InitData(slotId);
            break;
        }
        case RadioEvent::RADIO_SIM_STATE_CHANGE: {
            auto slotId = event->GetParam();
            RefreshData(slotId);
            break;
        }
        case MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT: {
            RegisterSimNotify();
            break;
        }
        case MultiSimMonitor::UNREGISTER_SIM_NOTIFY_EVENT: {
            UnRegisterSimNotify();
            break;
        }
        default:
            break;
    }
}

void MultiSimMonitor::InitData(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimMonitor::InitData slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData slotId is invalid");
        return;
    }
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData controller_ is nullptr");
        return;
    }
    if (!controller_->InitData(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData failed");
        return;
    }
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData observerHandler_ is nullptr");
        return;
    }
    NotifySimAccountChanged();
    observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_ACCOUNT_LOADED, slotId);
}

void MultiSimMonitor::RefreshData(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::RefreshData slotId is invalid");
        return;
    }
    if (controller_ == nullptr || simStateManager_[slotId] == nullptr || simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::RefreshData controller_ or simStateManager_ is nullptr");
        return;
    }
    if (simStateManager_[slotId]->GetSimState() == SimState::SIM_STATE_NOT_PRESENT) {
        TELEPHONY_LOGI("MultiSimMonitor::RefreshData clear data when sim is absent");
        controller_->ForgetAllData(slotId);
        controller_->GetListFromDataBase();
        simFileManager_[slotId]->ClearData();
    }
    NotifySimAccountChanged();
}

void MultiSimMonitor::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::RegisterCoreNotify observerHandler_ is nullptr");
        return;
    }
    observerHandler_->RegObserver(what, handler);
}

bool MultiSimMonitor::IsValidSlotId(int32_t slotId)
{
    return (slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT);
}

int32_t MultiSimMonitor::RegisterSimAccountCallback(
    const std::string &bundleName, const sptr<SimAccountCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE(" callback is nullptr");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    bool isExisted = false;
    std::lock_guard<std::mutex> lock(mutexInner_);
    for (auto iter : listSimAccountCallbackRecord_) {
        if ((iter.bundleName == bundleName)) {
            iter.simAccountCallback = callback;
            isExisted = true;
            break;
        }
    }
    if (isExisted) {
        TELEPHONY_LOGI("Ignore register action, since callback is existent");
        return TELEPHONY_SUCCESS;
    }

    SimAccountCallbackRecord simAccountRecord;
    simAccountRecord.bundleName = bundleName;
    simAccountRecord.simAccountCallback = callback;
    listSimAccountCallbackRecord_.push_back(simAccountRecord);
    TELEPHONY_LOGI("Register successfully, callback list size is %{public}zu", listSimAccountCallbackRecord_.size());
    return TELEPHONY_SUCCESS;
}

int32_t MultiSimMonitor::UnregisterSimAccountCallback(const std::string &bundleName)
{
    bool isSuccess = false;
    std::lock_guard<std::mutex> lock(mutexInner_);
    auto iter = listSimAccountCallbackRecord_.begin();
    for (; iter != listSimAccountCallbackRecord_.end();) {
        if ((iter->bundleName == bundleName)) {
            iter = listSimAccountCallbackRecord_.erase(iter);
            isSuccess = true;
            break;
        }
        iter++;
    }
    if (!isSuccess) {
        TELEPHONY_LOGE("Ignore unregister action, since callback is nonexistent");
        return TELEPHONY_ERROR;
    }
    TELEPHONY_LOGI("Unregister successfully, callback list size is %{public}zu", listSimAccountCallbackRecord_.size());
    return TELEPHONY_SUCCESS;
}

void MultiSimMonitor::NotifySimAccountChanged()
{
    TELEPHONY_LOGD("NotifySimAccountChanged");
    bool isExisted = false;
    std::lock_guard<std::mutex> lock(mutexInner_);
    for (auto iter : listSimAccountCallbackRecord_) {
        if (iter.simAccountCallback != nullptr) {
            isExisted = true;
            iter.simAccountCallback->OnSimAccountChanged();
        }
    }
    if (!isExisted) {
        TELEPHONY_LOGI("SimAccountCallback has not been registered");
    }
}

void MultiSimMonitor::RegisterSimNotify()
{
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController is null");
        return;
    }
    controller_->ForgetAllData();
    for (unsigned slotId = 0; slotId < simFileManager_.size(); slotId++) {
        if (simFileManager_[slotId] == nullptr) {
            TELEPHONY_LOGE("simFileManager_ is null slotId :  %{public}d", slotId);
            continue;
        }
        simFileManager_[slotId]->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
        simFileManager_[slotId]->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    }
}

void MultiSimMonitor::UnRegisterSimNotify()
{
    for (unsigned slotId = 0; slotId < simFileManager_.size(); slotId++) {
        if (simFileManager_[slotId] == nullptr) {
            TELEPHONY_LOGE("simFileManager_ is null slotId :  %{public}d", slotId);
            continue;
        }
        simFileManager_[slotId]->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
        simFileManager_[slotId]->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    }
}

void MultiSimMonitor::InitListener()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(shared_from_this());
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("samgrProxy or statusChangeListener_ is nullptr");
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, statusChangeListener_);
    TELEPHONY_LOGI("SubscribeSystemAbility SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN result:%{public}d", ret);
}

MultiSimMonitor::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    std::shared_ptr<AppExecFwk::EventHandler> multiSimMonitorHandler)
    : multiSimMonitorHandler_(multiSimMonitorHandler)
{}

void MultiSimMonitor::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
        return;
    }

    TELEPHONY_LOGD("SystemAbilityStatusChangeListener::OnAddSystemAbility SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN");
    std::vector<int32_t> activeList = { 0 };
    DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->QueryActiveOsAccountIds(activeList);
    TELEPHONY_LOGI("current active user id is :%{public}d", activeList[0]);
    auto multiSimMonitorHandler = multiSimMonitorHandler_.lock();
    if (activeList[0] == ACTIVE_USER_ID) {
        if (multiSimMonitorHandler == nullptr) {
            TELEPHONY_LOGE("MultiSimMonitor is null");
            return;
        }
        multiSimMonitorHandler->SendEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT);
    } else {
        MatchingSkills matchingSkills;
        matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
        CommonEventSubscribeInfo subscriberInfo(matchingSkills);
        subscriberInfo.SetThreadMode(CommonEventSubscribeInfo::COMMON);
        userSwitchSubscriber_ = std::make_shared<UserSwitchEventSubscriber>(subscriberInfo, multiSimMonitorHandler);
        bool subRet = CommonEventManager::SubscribeCommonEvent(userSwitchSubscriber_);
        if (!subRet) {
            TELEPHONY_LOGE("Subscribe user switched event failed!");
        }
    }
}

void MultiSimMonitor::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
        return;
    }
    TELEPHONY_LOGD("SystemAbilityStatusChangeListener::OnRemoveSystemAbility SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN");
    auto multiSimMonitorHandler = multiSimMonitorHandler_.lock();
    if (multiSimMonitorHandler == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor is null");
        return;
    }
    multiSimMonitorHandler->SendEvent(MultiSimMonitor::UNREGISTER_SIM_NOTIFY_EVENT);
    if (userSwitchSubscriber_ != nullptr) {
        bool subRet = CommonEventManager::UnSubscribeCommonEvent(userSwitchSubscriber_);
        if (!subRet) {
            TELEPHONY_LOGE("UnSubscribe user switched event failed!");
        }
        userSwitchSubscriber_ = nullptr;
    }
}

void MultiSimMonitor::UserSwitchEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    if (multiSimMonitorHandler_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor is null");
        return;
    }
    OHOS::EventFwk::Want want = data.GetWant();
    std::string action = data.GetWant().GetAction();
    TELEPHONY_LOGI("action = %{public}s", action.c_str());
    if (action == CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t userId = data.GetCode();
        TELEPHONY_LOGI("current user id is :%{public}d", userId);
        if (userId == ACTIVE_USER_ID) {
            multiSimMonitorHandler_->SendEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT);
        }
    }
}
} // namespace Telephony
} // namespace OHOS
