/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define private public
#define protected public

#include <string>
#include <unistd.h>
#include "sim_manager.h"
#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"
#include "gtest/gtest.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class SimManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SimManagerTest::TearDownTestCase() {}

void SimManagerTest::SetUp() {}

void SimManagerTest::TearDown() {}

void SimManagerTest::SetUpTestCase() {}

/**
 * @tc.number   Telephony_Sim_SimManager_0100
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->InitTelExtraModule(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERROR);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0200
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_002, Function | MediumTest | Level1)
{
    int32_t slotId = 2;
    int32_t slotCount = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    simManager->OnInit(slotCount);
    int32_t ret = simManager->InitTelExtraModule(slotId);
    EXPECT_EQ(ret, TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0300
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_003, Function | MediumTest | Level1)
{
    int32_t simId = 0;
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(nullptr);
    int32_t ret = simManager->GetDefaultSmsSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0400
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_004, Function | MediumTest | Level1)
{
    int32_t simId = 0;
    int32_t slotCount = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    simManager->OnInit(slotCount);
    int32_t ret = simManager->GetDefaultSmsSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0500
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_005, Function | MediumTest | Level1)
{
    int32_t simId = 0;
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(nullptr);
    int32_t ret = simManager->GetDefaultCellularDataSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0600
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_006, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->UpdateOperatorConfigs(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0700
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_007, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "ABCDEFG";
    std::string path = "";
    SimAuthenticationResponse mResponse;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetSimIO(slotId, command, fileId, data, path, mResponse);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

}
}