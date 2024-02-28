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

#include <atomic>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "os_account_manager_wrapper.h"
#include "radio_event.h"
#include "string_ex.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
const int64_t DELAY_TIME = 1000;
MultiSimMonitor::MultiSimMonitor(const std::shared_ptr<MultiSimController> &controller,
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
    std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManager)
    : TelEventHandler("MultiSimMonitor"), controller_(controller), simStateManager_(simStateManager),
      simFileManager_(simFileManager)
{
    if (observerHandler_ == nullptr) {
        observerHandler_ = std::make_unique<ObserverHandler>();
    }
}

MultiSimMonitor::~MultiSimMonitor()
{
    TELEPHONY_LOGD("destory");
}

void MultiSimMonitor::Init()
{
    TELEPHONY_LOGD("init");
    SendEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT);
}

void MultiSimMonitor::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    auto eventCode = event->GetInnerEventId();
    TELEPHONY_LOGI("eventCode is %{public}d", eventCode);
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
    auto simFileManager = simFileManager_[slotId].lock();
    if (controller_ == nullptr || simStateManager_[slotId] == nullptr || simFileManager == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::RefreshData controller_ or simStateManager_ is nullptr");
        return;
    }
    if (simStateManager_[slotId]->GetSimState() == SimState::SIM_STATE_NOT_PRESENT) {
        TELEPHONY_LOGI("MultiSimMonitor::RefreshData clear data when sim is absent");
        controller_->ForgetAllData(slotId);
        controller_->GetListFromDataBase();
        simFileManager->ClearData();
    }
    if (controller_->unInitModemSlotId_ == slotId) {
        TELEPHONY_LOGI("need to recheck primary");
        controller_->ReCheckPrimary();
    }
    NotifySimAccountChanged();
}

void MultiSimMonitor::RegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    if (observerHandler_ == nullptr || handler == nullptr) {
        TELEPHONY_LOGE("observerHandler_ or handler is nullptr");
        return;
    }
    observerHandler_->RegObserver(what, handler);
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("controller_ is nullptr");
        return;
    }
    if (controller_->IsSimActive(slotId) || IsVSimSlotId(slotId)) {
        TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_SIM_ACCOUNT_LOADED, slotId, 0);
    }
}

bool MultiSimMonitor::IsValidSlotId(int32_t slotId)
{
    return (slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT);
}

bool MultiSimMonitor::IsVSimSlotId(int32_t slotId)
{
    if (TELEPHONY_EXT_WRAPPER.getVSimSlotId_) {
        int vSimSlotId = DEFAULT_SIM_SLOT_ID_REMOVE;
        TELEPHONY_EXT_WRAPPER.getVSimSlotId_(vSimSlotId);
        return vSimSlotId == slotId;
    }
    return false;
}

int32_t MultiSimMonitor::RegisterSimAccountCallback(
    const std::string &bundleName, const sptr<SimAccountCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE(" callback is nullptr");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    std::lock_guard<std::mutex> lock(mutexInner_);
    bool isExisted = false;
    for (auto &iter : listSimAccountCallbackRecord_) {
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
    std::lock_guard<std::mutex> lock(mutexInner_);
    bool isSuccess = false;
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

std::list<MultiSimMonitor::SimAccountCallbackRecord> MultiSimMonitor::GetSimAccountCallbackRecords()
{
    std::lock_guard<std::mutex> lock(mutexInner_);
    return listSimAccountCallbackRecord_;
}

void MultiSimMonitor::NotifySimAccountChanged()
{
    std::list<SimAccountCallbackRecord> CallbackRecord = GetSimAccountCallbackRecords();
    TELEPHONY_LOGD("CallbackRecord size is %{public}zu", CallbackRecord.size());
    for (auto iter : CallbackRecord) {
        if (iter.simAccountCallback != nullptr) {
            iter.simAccountCallback->OnSimAccountChanged();
        }
    }
    DelayedRefSingleton<TelephonyStateRegistryClient>::GetInstance().UpdateIccAccount();
}

void MultiSimMonitor::RegisterSimNotify()
{
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController is null");
        return;
    }
    if (!controller_->ForgetAllData()) {
        if (remainCount_ > 0) {
            SendEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT, 0, DELAY_TIME);
            TELEPHONY_LOGI("retry remain %{public}d", static_cast<int32_t>(remainCount_));
            remainCount_--;
        }
        return;
    }
    TELEPHONY_LOGI("Register with time left %{public}d", static_cast<int32_t>(remainCount_));
    for (size_t slotId = 0; slotId < simFileManager_.size(); slotId++) {
        auto simFileManager = simFileManager_[slotId].lock();
        if (simFileManager == nullptr) {
            TELEPHONY_LOGE("simFileManager is null slotId : %{public}zu", slotId);
            continue;
        }
        simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
        simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    }
}

void MultiSimMonitor::UnRegisterSimNotify()
{
    for (size_t slotId = 0; slotId < simFileManager_.size(); slotId++) {
        auto simFileManager = simFileManager_[slotId].lock();
        if (simFileManager == nullptr) {
            TELEPHONY_LOGE("simFileManager is null slotId : %{public}zu", slotId);
            continue;
        }
        simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
        simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    }
}
} // namespace Telephony
} // namespace OHOS
