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

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"


namespace OHOS {
namespace Telephony {
StkManager::StkManager(std::shared_ptr<ITelRilManager> telRilManager, std::shared_ptr<SimStateManager> simStateManager)
    : telRilManager_(telRilManager), simStateManager_(simStateManager)
{
    TELEPHONY_LOGI("StkManager::StkManager()");
}

StkManager::~StkManager()
{
    if (stkController_ != nullptr) {
        stkController_->UnRegisterEvents();
    }
}

void StkManager::Init(int slotId)
{
    if (telRilManager_ == nullptr || simStateManager_ == nullptr) {
        TELEPHONY_LOGE("StkManager[%{public}d]::Init() telRilManager or simStateManager_ is nullptr", slotId);
        return;
    }
    std::string name = "StkController_";
    name.append(std::to_string(slotId));
    stkEventLoop_ = AppExecFwk::EventRunner::Create(name.c_str());
    if (stkEventLoop_.get() == nullptr) {
        TELEPHONY_LOGE("StkManager[%{public}d]::Init() failed to create EventRunner", slotId);
        return;
    }
    stkController_ = std::make_shared<StkController>(stkEventLoop_, telRilManager_, simStateManager_, slotId);
    if (stkController_ == nullptr) {
        TELEPHONY_LOGE("StkManager[%{public}d]::Init() failed to create StkController", slotId);
        return;
    }
    stkController_->Init();
    stkEventLoop_->Run();
    TELEPHONY_LOGI("StkManager[%{public}d]::Init() success", slotId);
}

int32_t StkManager::SendEnvelopeCmd(int32_t slotId, const std::string &cmd) const
{
    if (stkController_ == nullptr) {
        TELEPHONY_LOGE("StkManager[%{public}d]::SendEnvelopeCmd() stkController_ is nullptr", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = stkController_->SendEnvelopeCmd(cmd);
    TELEPHONY_LOGI("StkManager[%{public}d]::SendEnvelopeCmd() result:%{public}s", slotId, (result ? "true" : "false"));
    return result;
}

int32_t StkManager::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) const
{
    if (stkController_ == nullptr) {
        TELEPHONY_LOGE("StkManager[%{public}d]::SendTerminalResponseCmd() stkController_ is nullptr", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = stkController_->SendTerminalResponseCmd(cmd);
    TELEPHONY_LOGI("StkManager[%{public}d]::SendTerminalResponseCmd() result:%{public}s",
        slotId, (result ? "true" : "false"));
    return result;
}

int32_t StkManager::SendCallSetupRequestResult(int32_t slotId, bool accept) const
{
    if (stkController_ == nullptr) {
        TELEPHONY_LOGE("StkManager[%{public}d]::SendCallSetupRequestResult() stkController_ is nullptr", slotId);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = stkController_->SendCallSetupRequestResult(accept);
    TELEPHONY_LOGI("StkManager[%{public}d]::SendCallSetupRequestResult() result:%{public}d", slotId, result);
    return result;
}
} // namespace Telephony
} // namespace OHOS
