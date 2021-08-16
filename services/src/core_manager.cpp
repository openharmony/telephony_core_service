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
CoreManager *CoreManager::coreManager_ = nullptr;
std::mutex CoreManager::mutex_;

CoreManager &CoreManager::GetInstance()
{
    if (coreManager_ == nullptr) {
        TELEPHONY_LOGD("Instance is null, new a object.");
        std::lock_guard<std::mutex> lock(mutex_);
        if (coreManager_ == nullptr) {
            coreManager_ = new CoreManager();
        }
    }
    return *coreManager_;
}

int32_t CoreManager::Init()
{
    TELEPHONY_LOGD("CoreManager OnInit");
    int32_t slotCount = DEFAULT_SLOT_NUM;
    int32_t slotId = DEFAULT_SLOT_ID;

    ReleaseCore();
    while (slotId < slotCount) {
        /* Prevent multiple instantiations of objects. */
        if (core_.find(slotId) == core_.end()) {
            auto newCore = std::make_shared<Core>(slotId);
            core_[slotId] = newCore;
            core_[slotId]->OnInit();
        } else {
            TELEPHONY_LOGD("The object has already been instantiated! slotId:%{public}d", slotId);
        }
        slotId++;
    }
    return TELEPHONY_SUCCESS;
}

void CoreManager::ReleaseCore()
{
    TELEPHONY_LOGD("CoreManager ReleaseCore size:%{public}zu", core_.size());
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