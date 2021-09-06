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

#include "sim_manager.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
SimManager::SimManager() {}

SimManager::~SimManager() {}

void SimManager::Init()
{
    multiSimController_ = std::make_unique<MultiSimController>();
}

bool SimManager::GetSimAccountInfo(int32_t subId, IccAccountInfo &info)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimManager::GetSimAccountInfo failed subId = %{public}d", subId);
        return false;
    }
    if (multiSimController_->RefreshIccAccountInfoList()) {
        std::list<IccAccountInfo>::iterator it = multiSimController_->iccAccountInfoList_.begin();
        while (it != multiSimController_->iccAccountInfoList_.end()) {
            if (subId == it->slotIndex) {
                info = *it;
                return true;
            }
            it++;
        }
        TELEPHONY_LOGD("SimManager::GetSimAccountInfo can't find the item");
    }
    TELEPHONY_LOGD("SimManager::GetSimAccountInfo refresh database failed");
    return false;
}

bool SimManager::SetDefaultVoiceSlotId(int32_t subId)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimManager::SetDefaultVoiceSlotId failed = %d", subId);
        return false;
    }
    multiSimController_->SetDefaultVoiceSlotId(subId);
    return true;
}

bool SimManager::SetDefaultSmsSlotId(int32_t subId)
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimManager::SetDefaultSmsSlotId failed = %d", subId);
        return false;
    }
    if (!IsValidSimId(subId)) {
        TELEPHONY_LOGE("SimManager::SetDefaultSmsSlotId invalid subId = %d", subId);
        return false;
    }
    multiSimController_->SetDefaultSmsSlotId(subId);
    return true;
}

int32_t SimManager::GetDefaultVoiceSlotId()
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimManager::GetDefaultVoiceSlotId failed");
        return INVALID_VALUE;
    }
    return multiSimController_->GetDefaultVoiceSlotId();
}

int32_t SimManager::GetDefaultSmsSlotId()
{
    if (multiSimController_ == nullptr) {
        TELEPHONY_LOGE("SimManager::GetDefaultSmsSlotId failed");
        return INVALID_VALUE;
    }
    return multiSimController_->GetDefaultSmsSlotId();
}

bool SimManager::IsValidSimId(int32_t subId)
{
    if (subId >= CoreManager::DEFAULT_SLOT_ID && subId <= MAX_SLOT_INDEX) {
        return true;
    }
    TELEPHONY_LOGE("SimManager SimId is InValid = %d", subId);
    return false;
}
} // namespace Telephony
} // namespace OHOS