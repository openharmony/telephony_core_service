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

#include "string_ex.h"

#include "radio_event.h"

namespace OHOS {
namespace Telephony {
static const int32_t RETRY_COUNT = 30;

MultiSimMonitor::MultiSimMonitor(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::shared_ptr<MultiSimController> &controller,
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager)
    : AppExecFwk::EventHandler(runner), controller_(controller),
      simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    if (runner != nullptr) {
        runner->Run();
    }
    if (observerHandler_ == nullptr) {
        observerHandler_ = std::make_unique<ObserverHandler>();
    }
}

void MultiSimMonitor::Init()
{
    SendEvent(MSG_SIM_FORGET_ALLDATA);
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
        case MSG_SIM_FORGET_ALLDATA:
            TELEPHONY_LOGI("MultiSimMonitor::forget all data");
            ready_ = controller_->ForgetAllData();
            break;
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
    for (int i = 0; i < RETRY_COUNT; i++) {
        if (ready_) {
            TELEPHONY_LOGI("MultiSimMonitor::InitData dataAbility is ready");
            break;
        }
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
        controller_->GetListFromDataBase();
        simFileManager_[slotId]->ClearData();
    }
    NotifySimAccountChanged();
}

bool MultiSimMonitor::RegisterForIccLoaded(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimMonitor::RegisterForIccLoaded");
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::RegisterForIccLoaded simFileManager_ is nullptr");
        return false;
    }
    simFileManager_[slotId]->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool MultiSimMonitor::UnRegisterForIccLoaded(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimMonitor::UnRegisterForIccLoaded");
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::UnRegisterForIccLoaded simFileManager_ is nullptr");
        return false;
    }
    simFileManager_[slotId]->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool MultiSimMonitor::RegisterForSimStateChanged(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimMonitor::RegisterForSimStateChanged");
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::RegisterForSimStateChanged simFileManager_ is nullptr");
        return false;
    }
    simFileManager_[slotId]->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    return true;
}

bool MultiSimMonitor::UnRegisterForSimStateChanged(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimMonitor::UnRegisterForSimStateChanged");
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::UnRegisterForSimStateChanged simFileManager_ is nullptr");
        return false;
    }
    simFileManager_[slotId]->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    return true;
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
    TELEPHONY_LOGI("NotifySimAccountChanged");
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
} // namespace Telephony
} // namespace OHOS
