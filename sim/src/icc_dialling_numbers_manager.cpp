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

#include "icc_dialling_numbers_manager.h"

namespace OHOS {
namespace Telephony {
IccDiallingNumbersManager::IccDiallingNumbersManager(const std::shared_ptr<ISimFileManager> &simFileManager)
    : simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("IccDiallingNumbersManager::IccDiallingNumbersManager started");
}

IccDiallingNumbersManager::~IccDiallingNumbersManager() {}

void IccDiallingNumbersManager::Init()
{
    TELEPHONY_LOGI("IccDiallingNumbersManager::Init() started ");
    if (statePhoneBookCtrl__ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("IccDiallingNumbersManager::Init statePhoneBookCtrl__ started.");
        return;
    }

    eventLoopPhoneBookCtrl_ = AppExecFwk::EventRunner::Create("pbCtrlLoop");
    if (eventLoopPhoneBookCtrl_.get() == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager  failed to create EventRunner");
        return;
    }
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::Init ISimFileManager null pointer");
        return;
    }
    phoneBookCtrl_ = std::make_shared<IccDiallingNumbersController>(eventLoopPhoneBookCtrl_, simFileManager_);
    if (phoneBookCtrl_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::Init phoneBookCtrl_ create nullptr.");
        return;
    }

    eventLoopPhoneBookCtrl_->Run();
    statePhoneBookCtrl__ = HandleRunningState::STATE_RUNNING;

    phoneBookCtrl_->Init();
    TELEPHONY_LOGI("IccDiallingNumbersManager::Init() end");
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> IccDiallingNumbersManager::QueryIccDiallingNumbers(
    int slotId, int type)
{
    if (phoneBookCtrl_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::QueryIccDiallingNumbers phoneBookCtrl_ nullptr");
        return std::vector<std::shared_ptr<DiallingNumbersInfo>>();
    }
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result =
        phoneBookCtrl_->QueryIccDiallingNumbers(slotId, type);
    TELEPHONY_LOGI("IccDiallingNumbersManager::QueryIccDiallingNumbers:%{public}zu", result.size());
    return result;
}

bool IccDiallingNumbersManager::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (phoneBookCtrl_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::AddIccDiallingNumbers phoneBookCtrl_ nullptr");
        return false;
    }
    bool result = phoneBookCtrl_->AddIccDiallingNumbers(slotId, type, diallingNumber);
    TELEPHONY_LOGI("IccDiallingNumbersManager::AddIccDiallingNumbers:%{public}d", result);
    return result;
}

bool IccDiallingNumbersManager::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (phoneBookCtrl_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::DelIccDiallingNumbers phoneBookCtrl_ nullptr");
        return false;
    }
    bool result = phoneBookCtrl_->DelIccDiallingNumbers(slotId, type, diallingNumber);
    TELEPHONY_LOGI("IccDiallingNumbersManager::DelIccDiallingNumbers:%{public}d", result);
    return result;
}

bool IccDiallingNumbersManager::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (phoneBookCtrl_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::UpdateIccDiallingNumbers phoneBookCtrl_ nullptr");
        return false;
    }
    bool result = phoneBookCtrl_->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
    TELEPHONY_LOGI("IccDiallingNumbersManager::UpdateIccDiallingNumbers:%{public}d", result);
    return result;
}
} // namespace Telephony
} // namespace OHOS
