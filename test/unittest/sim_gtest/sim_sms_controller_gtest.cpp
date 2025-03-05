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
#define private public
#define protected public

#include "gtest/gtest.h"
#include "sim_state_manager.h"
#include "sim_state_manager.h"
#include "sim_sms_controller.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class SimSmsControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SimSmsControllerTest::TearDownTestCase() {}

void SimSmsControllerTest::SetUp() {}

void SimSmsControllerTest::TearDown() {}

void SimSmsControllerTest::SetUpTestCase() {}

HWTEST_F(SimSmsControllerTest, Telephony_Sim_ProcessEvent_001, Function | MediumTest | Level1)
{
    auto telRilManager_ = std::make_shared<TelRilManager>();
    auto stateManager_ = std::make_shared<SimStateManager>(telRilManager_);
    auto simSmsController = std::make_shared<SimSmsController>(stateManager_);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(SIM_SMS_GET_COMPLETED, 1);
    simSmsController->ProcessEvent(event);
    EXPECT_EQ(simSmsController->loadDone_, true);
}

HWTEST_F(SimSmsControllerTest, Telephony_Sim_ProcessEvent_002, Function | MediumTest | Level1)
{
    auto telRilManager_ = std::make_shared<TelRilManager>();
    auto stateManager_ = std::make_shared<SimStateManager>(telRilManager_);
    auto simSmsController = std::make_shared<SimSmsController>(stateManager_);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(SIM_SMS_UPDATE_COMPLETED, 1);
    simSmsController->ProcessEvent(event);
    EXPECT_EQ(simSmsController->responseReady_, true);
}

HWTEST_F(SimSmsControllerTest, Telephony_Sim_ProcessEvent_003, Function | MediumTest | Level1)
{
    auto telRilManager_ = std::make_shared<TelRilManager>();
    auto stateManager_ = std::make_shared<SimStateManager>(telRilManager_);
    auto simSmsController = std::make_shared<SimSmsController>(stateManager_);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(SIM_SMS_WRITE_COMPLETED, 1);
    simSmsController->ProcessEvent(event);
    EXPECT_EQ(simSmsController->responseReady_, true);
}

HWTEST_F(SimSmsControllerTest, Telephony_Sim_ProcessEvent_004, Function | MediumTest | Level1)
{
    auto telRilManager_ = std::make_shared<TelRilManager>();
    auto stateManager_ = std::make_shared<SimStateManager>(telRilManager_);
    auto simSmsController = std::make_shared<SimSmsController>(stateManager_);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(SIM_SMS_DELETE_COMPLETED, 1);
    simSmsController->ProcessEvent(event);
    EXPECT_EQ(simSmsController->responseReady_, true);
}

HWTEST_F(SimSmsControllerTest, Telephony_Sim_SetRilAndFileManager_001, Function | MediumTest | Level1)
{
    auto telRilManager_ = std::make_shared<TelRilManager>();
    auto stateManager_ = std::make_shared<SimStateManager>(telRilManager_);
    auto simSmsController = std::make_shared<SimSmsController>(stateManager_);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(SIM_SMS_DELETE_COMPLETED, 1);
    simSmsController->SetRilAndFileManager(nullptr, nullptr);
    EXPECT_EQ(simSmsController->fileManager_, nullptr);
}

}
}