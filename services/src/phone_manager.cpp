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
#include "phone_manager.h"
#include <cstdlib>
#include "network_search_manager.h"
#include "telephony_log.h"

namespace OHOS {
PhoneManager *PhoneManager ::phoneManager_ = nullptr;
std::mutex PhoneManager ::mutex_;

PhoneManager &PhoneManager ::GetInstance()
{
    if (phoneManager_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (phoneManager_ == nullptr) {
            TELEPHONY_INFO_LOG("SingletonTest instance is null");
            phoneManager_ = new PhoneManager();
        }
    }
    return *phoneManager_;
}

int32_t PhoneManager ::Init()
{
    TELEPHONY_INFO_LOG("PhoneManager  OnInit");
    int32_t phoneCount = 1;
    ReleasePhone();
    for (int32_t phoneId = 1; phoneId <= phoneCount; phoneId++) {
        phone_[phoneId] = new Phone(phoneId);
        phone_[phoneId]->OnInit();
    }
    return 0;
}

void PhoneManager ::ReleasePhone()
{
    TELEPHONY_INFO_LOG("PhoneManager  ReleasePhone phone_.size():%{public}zu", phone_.size());
    if (phone_.size() != 0) {
        phone_.clear();
    }
}
} // namespace OHOS
