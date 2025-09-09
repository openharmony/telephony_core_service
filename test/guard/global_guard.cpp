/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "global_guard.h"

#include <iostream>
#include "mock_i_system_ability_manager.h"

namespace OHOS {
namespace Telephony {

SubscribeSystemAbilityStub::SubscribeSystemAbilityStub()
{
    std::cout << "SubscribeSystemAbilityStub init" << std::endl;
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = MockISystemAbilityManager::GetInstance();
}

SubscribeSystemAbilityStub::~SubscribeSystemAbilityStub()
{
    std::cout << "SubscribeSystemAbilityStub deinit" << std::endl;
}

void GlobalGuard::Init()
{
    if (instance_ == nullptr) {
        instance_ = std::make_shared<GlobalGuard>();
    }
}
}
}