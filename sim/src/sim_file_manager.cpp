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
#include "sim_file_manager.h"
#include <cstring>
#include <string>

namespace OHOS {
namespace SIM {
SimFileManager::SimFileManager(std::shared_ptr<SIM::ISimStateManager> state)
{
    simStateManager_ = state;
    TELEPHONY_INFO_LOG("SIM manager SimFileManager::SimFileManager started ");
}

SimFileManager::~SimFileManager() {}

void SimFileManager::Init()
{
    TELEPHONY_INFO_LOG("SIM manager SimFileManager::Init() started ");
    if (stateRecord_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_INFO_LOG("SimFileManager::Init stateRecord_ started.");
        return;
    }

    if (stateHandler_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_INFO_LOG("SimFileManager::Init stateHandler_ started.");
        return;
    }

    IRilManager *rilManager = PhoneManager ::GetInstance().phone_[1]->rilManager_;
    eventLoopRecord_ = AppExecFwk::EventRunner::Create("IccFile");
    if (eventLoopRecord_.get() == nullptr) {
        TELEPHONY_INFO_LOG("IccFile  failed to create EventRunner");
        return;
    }

    eventLoopFileController_ = AppExecFwk::EventRunner::Create("SIMHandler");
    if (eventLoopFileController_.get() == nullptr) {
        TELEPHONY_INFO_LOG("SIMHandler  failed to create EventRunner");
        return;
    }

    fileController_ = std::make_shared<SimFileController>(eventLoopFileController_);
    if (fileController_ == nullptr) {
        TELEPHONY_ERR_LOG("SimFileManager::Init fileController create nullptr.");
        return;
    }
    fileController_->SetRilManager(rilManager);

    simFile_ = std::make_shared<SimFile>(eventLoopRecord_, simStateManager_);
    if (simFile_ == nullptr) {
        TELEPHONY_ERR_LOG("SimFileManager::Init simFile create nullptr.");
        return;
    }
    simFile_->SetRilAndFileController(rilManager, fileController_);

    eventLoopRecord_->Run();
    eventLoopFileController_->Run();
    stateRecord_ = HandleRunningState::STATE_RUNNING;
    stateHandler_ = HandleRunningState::STATE_RUNNING;

    simFile_->Init();
    TELEPHONY_INFO_LOG("SIM manager SimFileManager::Init() end");
}

std::u16string SimFileManager::GetSimOperator(int32_t slotId)
{
    std::string result = simFile_->ObtainSimOperator();
    if (!result.empty()) {
        TELEPHONY_INFO_LOG("SimFileManager::GetOperator result:%{public}s ", result.c_str());
    }
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetIsoCountryCode(int32_t slotId)
{
    std::string result = simFile_->ObtainIsoCountryCode();
    if (!result.empty()) {
        TELEPHONY_INFO_LOG("SimFileManager::GetIsoCountryCode result:%{public}s ", result.c_str());
    }
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSpn(int32_t slotId)
{
    std::string result = simFile_->ObtainSPN();
    if (!result.empty()) {
        TELEPHONY_INFO_LOG("SimFileManager::GetSpn result:%{public}s ", result.c_str());
    }
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetIccId(int32_t slotId)
{
    std::string result = simFile_->ObtainIccId();
    if (!result.empty()) {
        TELEPHONY_INFO_LOG("SimFileManager::GetIccId result:%{public}s ", result.c_str());
    }
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetIMSI(int32_t slotId)
{
    std::string result = simFile_->ObtainIMSI();
    if (!result.empty()) {
        TELEPHONY_INFO_LOG("SimFileManager::GetIMSI result:%{public}s ", result.c_str());
    }
    return Str8ToStr16(result);
}

std::shared_ptr<IccFile> SimFileManager::GetIccFile()
{
    return simFile_;
}
std::shared_ptr<IccFileController> SimFileManager::GetIccFileController()
{
    return fileController_;
}
void SimFileManager::RegisterImsiLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    simFile_->RegisterImsiLoaded(eventHandler);
}

void SimFileManager::UnregisterImsiLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    simFile_->UnregisterImsiLoaded(handler);
}

void SimFileManager::RegisterAllFilesLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    simFile_->RegisterAllFilesLoaded(eventHandler);
}

void SimFileManager::UnregisterAllFilesLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    simFile_->UnregisterAllFilesLoaded(handler);
}

void SimFileManager::SetImsi(std::string imsi)
{
    simFile_->UpdateImsi(imsi);
}
} // namespace SIM
} // namespace OHOS
