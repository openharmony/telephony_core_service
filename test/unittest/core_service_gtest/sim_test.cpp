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

#include <unistd.h>
#include <gtest/gtest.h>
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "core_service_proxy.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
const int32_t slotId = 0;

class SimTest : public testing::Test {
public:
    // execute before first testcase
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    static void TearDownTestCase();

    static sptr<ICoreService> GetProxy();
    static sptr<ICoreService> telephonyService_;
};

sptr<ICoreService> SimTest::telephonyService_ = nullptr;
void SimTest::SetUpTestCase()
{
    std::cout << "----------Sim gtest start ------------" << std::endl;
    if (telephonyService_ == nullptr) {
        telephonyService_ = GetProxy();
    }
    std::cout << "Sim connect coreservice  server success!!!" << std::endl;
}

void SimTest::TearDownTestCase()
{
    std::cout << "----------Sim gtest end ------------" << std::endl;
}

void SimTest::SetUp() {}

void SimTest::TearDown() {}

sptr<ICoreService> SimTest::GetProxy()
{
    TELEPHONY_LOGI("TelephonyTestService GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        std::cout << "TelephonyTestService Get ISystemAbilityManager failed!!!" << std::endl;
        return nullptr;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote) {
        sptr<ICoreService> telephonyService = iface_cast<ICoreService>(remote);
        return telephonyService;
    } else {
        std::cout << "TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail ..." << std::endl;
        return nullptr;
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimState_0100
 * @tc.name     Get sim State
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimState_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetSimState(slotId);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimState_0100
 * @tc.name     Get sim State
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_HasSimCard_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->HasSimCard(slotId);
        EXPECT_GT(result, -1);
    }
}
} // namespace Telephony
} // namespace OHOS