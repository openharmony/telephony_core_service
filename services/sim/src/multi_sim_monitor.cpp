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

namespace OHOS {
namespace Telephony {
MultiSimMonitor::MultiSimMonitor(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
                                 const std::shared_ptr<MultiSimController> &controller,
                                 std::shared_ptr<ISimStateManager> simStateManager,
                                 std::shared_ptr<ISimFileManager> simFileManager)
    : AppExecFwk::EventHandler(runner), controller_(controller),
      simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    if (runner != nullptr) {
        runner->Run();
    }
}

MultiSimMonitor::~MultiSimMonitor()
{
    UnRegisterForIccLoaded();
}

void MultiSimMonitor::Init(int32_t slotId)
{
    slotId_ = slotId;
}

void MultiSimMonitor::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    auto eventCode = event->GetInnerEventId();
    switch (eventCode) {
        case ObserverHandler::RADIO_SIM_RECORDS_LOADED:
            TELEPHONY_LOGI("MultiSimMonitor::INIT_DATA sim icc data slotId_ = %{public}d", slotId_);
            if (controller_ == nullptr) {
                TELEPHONY_LOGE("MultiSimMonitor::INIT_DATA failed by nullptr");
                return;
            }
            controller_->Init();
            controller_->InitData();
            break;
        default:
            break;
    }
}

bool MultiSimMonitor::RegisterForIccLoaded()
{
    TELEPHONY_LOGI("MultiSimMonitor::RegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGI("MultiSimMonitor::can not get SimFileManager");
        return false;
    }
    simFileManager_->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool MultiSimMonitor::UnRegisterForIccLoaded()
{
    TELEPHONY_LOGI("MultiSimMonitor::UnRegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGI("MultiSimMonitor::can not get SimFileManager");
        return false;
    }
    simFileManager_->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_RECORDS_LOADED);
    return true;
}
} // namespace Telephony
} // namespace OHOS

