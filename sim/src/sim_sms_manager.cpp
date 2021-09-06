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

namespace OHOS {
namespace Telephony {
SimSmsManager::SimSmsManager()
{
    TELEPHONY_LOGI("SimSmsManager::SimSmsManager started");
}

SimSmsManager::~SimSmsManager() {}

void SimSmsManager::Init()
{
    TELEPHONY_LOGI("SimSmsManager::Init() started ");
    if (stateSms_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("SimSmsManager::Init stateSms_ started.");
        return;
    }

    std::shared_ptr<Telephony::IRilManager> rilManager =
        CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetRilManager();
    if (rilManager == nullptr) {
        TELEPHONY_LOGE("SimSmsManager get NULL IRilManager.");
        return;
    }

    eventLoopSms_ = AppExecFwk::EventRunner::Create("simSmsController");
    if (eventLoopSms_.get() == nullptr) {
        TELEPHONY_LOGE("simSmsController  failed to create EventRunner");
        return;
    }

    std::shared_ptr<ISimFileManager> ifileMannager =
        CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetSimFileManager();
    if (ifileMannager == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::Init ISimFileManager null pointer");
        return;
    }
    std::shared_ptr<SimFileManager> fileMannager = std::static_pointer_cast<SimFileManager>(ifileMannager);

    smsController_ = std::make_shared<SimSmsController>(eventLoopSms_);
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::Init simFile create nullptr.");
        return;
    }
    smsController_->SetRilAndFileController(rilManager, fileMannager->GetIccFileController());

    eventLoopSms_->Run();
    stateSms_ = HandleRunningState::STATE_RUNNING;

    smsController_->Init();
    TELEPHONY_LOGI("SimSmsManager::Init() end");
}

bool SimSmsManager::AddSmsToIcc(int status, std::string &pdu, std::string &smsc)
{
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::AddSmsToIcc smsController_ nullptr");
        return false;
    }

    bool result = smsController_->AddSmsToIcc(status, pdu, smsc);
    TELEPHONY_LOGI("SimSmsManager::AddSmsToIcc result:%{public}s ", (result ? "true" : "false"));
    return result;
}

bool SimSmsManager::RenewSmsIcc(int index, int status, std::string &pduData, std::string &smsc)
{
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::RenewSmsIcc smsController_ nullptr");
        return false;
    }

    bool result = smsController_->RenewSmsIcc(index, status, pduData, smsc);
    TELEPHONY_LOGI("SimSmsManager::RenewSmsIcc result:%{public}s ", (result ? "true" : "false"));
    return result;
}

bool SimSmsManager::DelSmsIcc(int index)
{
    if (smsController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsManager::DelSmsIcc smsController_ nullptr");
        return false;
    }

    bool result = smsController_->DelSmsIcc(index);
    TELEPHONY_LOGI("SimSmsManager::DelSmsIcc result:%{public}s ", (result ? "true" : "false"));
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
