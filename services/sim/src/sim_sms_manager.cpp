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

#include "sim_sms_manager.h"

#include "telephony_errors.h"


namespace OHOS {
namespace Telephony {
SimSmsManager::SimSmsManager(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
    std::shared_ptr<SimFileManager> simFileManager, std::shared_ptr<SimStateManager> simStateManager)
    : telRilManager_(telRilManager), simFileManager_(simFileManager), stateManager_(simStateManager)
{
    TELEPHONY_LOGI("SimSmsManager::SimSmsManager started");
}

SimSmsManager::~SimSmsManager() {}

void SimSmsManager::Init(int slotId)
{
    TELEPHONY_LOGI("SimSmsManager::Init() started ");
    slotId_ = slotId;
    if (stateSms_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("SimSmsManager::Init stateSms_ started.");
        return;
    }

    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager get NULL ITelRilManager.");
        return;
    }

    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::Init SimFileManager null pointer");
        return;
    }
    std::shared_ptr<SimFileManager> fileManager = std::static_pointer_cast<SimFileManager>(simFileManager_);

    smsController_ = std::make_shared<SimSmsController>(stateManager_);
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::Init simFile create nullptr.");
        return;
    }
    smsController_->SetRilAndFileManager(telRilManager_, fileManager);

    stateSms_ = HandleRunningState::STATE_RUNNING;

    smsController_->Init(slotId_);
    TELEPHONY_LOGI("SimSmsManager::Init() end");
}

int32_t SimSmsManager::AddSmsToIcc(int status, std::string &pdu, std::string &smsc)
{
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::AddSmsToIcc smsController_ nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t result = smsController_->AddSmsToIcc(status, pdu, smsc);
    TELEPHONY_LOGI("SimSmsManager::AddSmsToIcc result:%{public}d", result);
    return result;
}

int32_t SimSmsManager::UpdateSmsIcc(int index, int status, std::string &pduData, std::string &smsc)
{
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::UpdateSmsIcc smsController_ nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t result = smsController_->UpdateSmsIcc(index, status, pduData, smsc);
    TELEPHONY_LOGI("SimSmsManager::UpdateSmsIcc result:%{public}d", result);
    return result;
}

int32_t SimSmsManager::DelSmsIcc(int index)
{
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::DelSmsIcc smsController_ nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    int32_t result = smsController_->DelSmsIcc(index);
    TELEPHONY_LOGI("SimSmsManager::DelSmsIcc result:%{public}d", result);
    return result;
}

std::vector<std::string> SimSmsManager::ObtainAllSmsOfIcc()
{
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::ObtainAllSmsOfIcc smsController_ nullptr");
        return std::vector<std::string>();
    }

    std::vector<std::string> result = smsController_->ObtainAllSmsOfIcc();
    TELEPHONY_LOGI("SimSmsManager::ObtainAllSmsOfIcc result:%{public}s ", (result.empty() ? "false" : "true"));
    return result;
}
} // namespace Telephony
} // namespace OHOS
