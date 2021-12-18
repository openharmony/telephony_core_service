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

#include "core_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
std::unique_ptr<CoreManager> CoreManager::coreManager_;
std::mutex CoreManager::mutex_;
const int32_t DEFAULT_SLOT_NUM = SIM_SLOT_NUM;

CoreManager &CoreManager::GetInstance()
{
    if (coreManager_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (coreManager_ == nullptr) {
            coreManager_.reset(new CoreManager);
            coreManager_->Init();
        }
    }
    return *coreManager_;
}

int32_t CoreManager::Init()
{
    int32_t slotCount = DEFAULT_SLOT_NUM;
    int32_t slotId = DEFAULT_SLOT_ID;

    ReleaseCore();
    while (slotId < slotCount) {
        /* Prevent multiple instantiations of objects. */
        if (core_.find(slotId) == core_.end()) {
            auto newCore = std::make_shared<Core>(slotId);
            core_[slotId] = newCore; // Other modules call directly using pointers.
            if (!newCore->OnInit()) {
                TELEPHONY_LOGE("Core initialization failed, erase core map slotId:%{public}d!", slotId);
                core_.erase(slotId);
                slotId++;
                continue;
            }
        } else {
            TELEPHONY_LOGI("The object has already been instantiated! slotId:%{public}d", slotId);
        }
        slotId++;
    }
    return TELEPHONY_SUCCESS;
}

void CoreManager::ReleaseCore()
{
    if (core_.size() != 0) {
        core_.clear();
    }
}

std::shared_ptr<Core> CoreManager::getCore(int slotId)
{
    if (core_.find(slotId) == core_.end()) {
        TELEPHONY_LOGE("The slotId:%{public}d core object is null.", slotId);
        return nullptr;
    }
    return core_[slotId];
}
} // namespace Telephony
} // namespace OHOS