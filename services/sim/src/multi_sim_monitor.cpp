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
bool MultiSimMonitor::ready_ = false;
std::unique_ptr<ObserverHandler> MultiSimMonitor::observerHandler_ = nullptr;

MultiSimMonitor::MultiSimMonitor(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
                                 const std::shared_ptr<MultiSimController> &controller,
                                 std::shared_ptr<SimStateManager> simStateManager,
                                 std::shared_ptr<SimFileManager> simFileManager,
                                 int32_t slotId)
    : AppExecFwk::EventHandler(runner), controller_(controller),
      simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    slotId_ = slotId;
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
            if (slotId != slotId_) {
                TELEPHONY_LOGI(
                    "MultiSimMonitor::getEvent not right slotId_ = %{public}d, %{public}d", slotId_, (int32_t)slotId);
                return;
            }
            InitData();
            break;
        }
        case RadioEvent::RADIO_SIM_STATE_CHANGE: {
            auto slotId = event->GetParam();
            if (slotId != slotId_) {
                TELEPHONY_LOGI(
                    "MultiSimMonitor::getEvent not right slotId_ = %{public}d, %{public}d", slotId_, (int32_t)slotId);
                return;
            }
            RefreshData();
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

void MultiSimMonitor::InitData()
{
    TELEPHONY_LOGI("MultiSimMonitor::INIT_DATA sim icc data slotId_ = %{public}d", slotId_);
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::INIT_DATA failed by nullptr");
        return;
    }
    for (int i = 0; i < RETRY_COUNT; i++) {
        if (ready_) {
            TELEPHONY_LOGI("MultiSimMonitor::dataAbility ready");
            break;
        }
    }
    if (!controller_->InitData(slotId_)) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData failed");
        return;
    }
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::can not notify RADIO_SIM_ACCOUNT_LOADED by nullptr");
        return;
    }
    observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_ACCOUNT_LOADED, slotId_);
}

void MultiSimMonitor::RefreshData()
{
    TELEPHONY_LOGI("MultiSimMonitor::RefreshData slotId_ = %{public}d", slotId_);
    if (controller_ == nullptr || simStateManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::INIT_DATA failed by nullptr");
        return;
    }
    if (simStateManager_->GetSimState() == SimState::SIM_STATE_NOT_PRESENT) {
        TELEPHONY_LOGI("MultiSimMonitor::clear data when sim is absent");
        controller_->ForgetAllData();
        controller_->GetListFromDataBase();
    }
}

bool MultiSimMonitor::RegisterForIccLoaded()
{
    TELEPHONY_LOGI("MultiSimMonitor::RegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::can not get SimFileManager");
        return false;
    }
    simFileManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool MultiSimMonitor::UnRegisterForIccLoaded()
{
    TELEPHONY_LOGI("MultiSimMonitor::UnRegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::can not get SimFileManager");
        return false;
    }
    simFileManager_->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool MultiSimMonitor::RegisterForSimStateChanged()
{
    TELEPHONY_LOGI("MultiSimMonitor::RegisterForSimStateChanged");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::can not get SimFileManager");
        return false;
    }
    simFileManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    return true;
}

bool MultiSimMonitor::UnRegisterForSimStateChanged()
{
    TELEPHONY_LOGI("MultiSimMonitor::UnRegisterForSimStateChanged");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::can not get SimFileManager");
        return false;
    }
    simFileManager_->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    return true;
}

void MultiSimMonitor::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::can not RegisterCoreNotify by nullptr");
        return;
    }
    observerHandler_->RegObserver(what, handler);
}
} // namespace Telephony
} // namespace OHOS
