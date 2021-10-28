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
namespace Telephony {
SimFileManager::SimFileManager(std::shared_ptr<IRilManager> rilManager,
    std::shared_ptr<Telephony::ISimStateManager> state) : rilManager_(rilManager), simStateManager_(state)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager set NULL simStateManager.");
        return;
    }
    TELEPHONY_LOGI("SIM manager SimFileManager::SimFileManager started ");
}

SimFileManager::~SimFileManager() {}

void SimFileManager::Init()
{
    TELEPHONY_LOGI("SimFileManager::Init() started ");
    if (stateRecord_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("SimFileManager::Init stateRecord_ started.");
        return;
    }
    if (stateHandler_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("SimFileManager::Init stateHandler_ started.");
        return;
    }
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager get NULL IRilManager.");
        return;
    }
    eventLoopRecord_ = AppExecFwk::EventRunner::Create("IccFile");
    if (eventLoopRecord_.get() == nullptr) {
        TELEPHONY_LOGE("IccFile  failed to create EventRunner");
        return;
    }
    eventLoopFileController_ = AppExecFwk::EventRunner::Create("SIMHandler");
    if (eventLoopFileController_.get() == nullptr) {
        TELEPHONY_LOGE("SIMHandler  failed to create EventRunner");
        return;
    }
    fileController_ = std::make_shared<UsimFileController>(eventLoopFileController_);
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::Init fileController create nullptr.");
        return;
    }
    fileController_->SetRilManager(rilManager_);
    eventLoopFileController_->Run();
    if (!InitDiallingNumberHandler()) {
        TELEPHONY_LOGE("SimFileManager::InitDiallingNumberHandler fail");
        return;
    }
    simFile_ = std::make_shared<SimFile>(eventLoopRecord_, simStateManager_);
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::Init simFile create nullptr.");
        return;
    }
    simFile_->SetRilAndFileController(rilManager_, fileController_, diallingNumberHandler_);
    eventLoopRecord_->Run();

    stateRecord_ = HandleRunningState::STATE_RUNNING;
    stateHandler_ = HandleRunningState::STATE_RUNNING;

    simFile_->Init();
    TELEPHONY_LOGI("SimFileManager::Init() end");
}

std::u16string SimFileManager::GetSimOperatorNumeric(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimOperatorNumeric simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainSimOperator();
    TELEPHONY_LOGI("SimFileManager::GetOperator result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetIsoCountryCodeForSim(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetIsoCountryCodeForSim simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIsoCountryCode();
    TELEPHONY_LOGI("SimFileManager::ObtainIsoCountryCode result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimSpn(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimSpn simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainSPN();
    TELEPHONY_LOGI("SimFileManager::GetSimSpn result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimIccId(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimIccId simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIccId();
    TELEPHONY_LOGI("SimFileManager::GetSimIccId result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetIMSI(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetIMSI simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIMSI();
    TELEPHONY_LOGI("SimFileManager::ObtainIMSI result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetLocaleFromDefaultSim()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetLocaleFromDefaultSim simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIccLanguage();
    TELEPHONY_LOGI(
        "SimFileManager::GetLocaleFromDefaultSim result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimGid1(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimGid1 simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainGid1();
    TELEPHONY_LOGI("SimFileManager::GetSimGid1 result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimTelephoneNumber(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimTelephoneNumber simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainMsisdnNumber();
    TELEPHONY_LOGI("SimFileManager::GetSimTelephoneNumber result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetVoiceMailIdentifier(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetVoiceMailIdentifier simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainVoiceMailInfo();
    TELEPHONY_LOGI(
        "SimFileManager::GetVoiceMailIdentifier result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetVoiceMailNumber(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetVoiceMailNumber simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainVoiceMailNumber();
    TELEPHONY_LOGI("SimFileManager::GetVoiceMailNumber result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

int SimFileManager::ObtainSpnCondition(bool roaming, std::string operatorNum)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::ObtainSpnCondition simFile nullptr");
        return 0;
    }

    int result = simFile_->ObtainSpnCondition(roaming, operatorNum);
    TELEPHONY_LOGI("SimFileManager::ObtainSpnCondition:%{public}d", result);
    return result;
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

void SimFileManager::RegisterPhoneNotify(
    const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    simFile_->RegisterPhoneNotify(handler, what);
}

void SimFileManager::UnRegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    simFile_->UnRegisterPhoneNotify(handler, what);
}

void SimFileManager::SetImsi(std::string imsi)
{
    simFile_->UpdateImsi(imsi);
}

bool SimFileManager::SetVoiceMail(const std::u16string &mailName, const std::u16string &mailNumber, int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::SetVoiceMail simFile nullptr");
        return false;
    }
    std::string name = Str16ToStr8(mailName);
    std::string number = Str16ToStr8(mailNumber);
    bool result = simFile_->UpdateVoiceMail(name, number);
    TELEPHONY_LOGI("SimFileManager::SetVoiceMail result:%{public}s ", (!result ? "false" : "true"));
    return result;
}

bool SimFileManager::InitDiallingNumberHandler()
{
    if (diallingNumberHandler_ != nullptr) {
        return true;
    }
    if (fileController_ == nullptr) {
        return false;
    }
    std::shared_ptr<AppExecFwk::EventRunner> loaderLoop = AppExecFwk::EventRunner::Create("msisdnLoader");
    if (loaderLoop.get() == nullptr) {
        TELEPHONY_LOGE("SimFileManager failed to create diallingNumberloader loop");
        return false;
    }
    diallingNumberHandler_ = std::make_shared<SimDiallingNumbersHandler>(loaderLoop, fileController_);
    if (diallingNumberHandler_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager failed to create SimDiallingNumbersHandler.");
        return false;
    }
    loaderLoop->Run();
    return true;
}

std::shared_ptr<SimDiallingNumbersHandler> SimFileManager::ObtainDiallingNumberHandler()
{
    return diallingNumberHandler_;
}
} // namespace Telephony
} // namespace OHOS
