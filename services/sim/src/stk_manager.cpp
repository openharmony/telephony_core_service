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

#include "stk_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
StkManager::StkManager(std::shared_ptr<ITelRilManager> telRilManager,
    std::shared_ptr<Telephony::ISimStateManager> simStateManager)
    : telRilManager_(telRilManager), simStateManager_(simStateManager)
{
    TELEPHONY_LOGI("StkManager::StkManager()");
}

void StkManager::Init(int slotId)
{
    TELEPHONY_LOGI("StkManager::Init() started");
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("StkManager::StkManager get ril_Manager fail");
        return;
    }

    if (stateStkMgr_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("StkManager::Init stateStkCtrl_ started.");
        return;
    }

    eventLoopStkController_ = AppExecFwk::EventRunner::Create("StkHandler");
    if (eventLoopStkController_.get() == nullptr) {
        TELEPHONY_LOGE("StkHandler failed to create EventRunner");
        return;
    }
    stkController_ = std::make_shared<StkController>(eventLoopStkController_);
    if (stkController_ == nullptr) {
        TELEPHONY_LOGE("StkManager::Init stkController_ create nullptr.");
        return;
    }
    stkController_->SetRilAndSimStateManager(telRilManager_, simStateManager_);
    stkController_->Init(slotId);
    eventLoopStkController_->Run();
    stateStkMgr_ = HandleRunningState::STATE_RUNNING;
    TELEPHONY_LOGI("StkManager::Init() end");
}

bool StkManager::SendEnvelopeCmd(const std::string &cmd)
{
    TELEPHONY_LOGI("StkManager::SendEnvelopeCmd()");
    if (stkController_ == nullptr) {
        TELEPHONY_LOGE("StkManager::stkController_ is nullptr");
        return false;
    }
    bool result = stkController_->SendEnvelopeCmd(cmd);
    TELEPHONY_LOGI("StkManager::SendEnvelopeCmd result:%{public}s ",
        (result ? "true" : "false"));
    return result;
}

bool StkManager::SendTerminalResponseCmd(const std::string &cmd)
{
    TELEPHONY_LOGI("StkManager::SendTerminalResponseCmd()");
    if (stkController_ == nullptr) {
        TELEPHONY_LOGE("StkManager::stkController_ is nullptr");
        return false;
    }
    bool result = stkController_->SendTerminalResponseCmd(cmd);
    TELEPHONY_LOGI("StkManager::SendTerminalResponseCmd result:%{public}s ",
        (result ? "true" : "false"));
    return result;
}
} // namespace Telephony
} // namespace OHOS
