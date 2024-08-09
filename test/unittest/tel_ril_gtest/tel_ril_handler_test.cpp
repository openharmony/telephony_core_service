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

#include "gtest/gtest.h"
#include "tel_ril_handler.h"
#include "tel_ril_manager.h"
#include "tel_event_handler.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class TelRilHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void TelRilHandlerTest::SetUpTestCase() {}

void TelRilHandlerTest::TearDownTestCase() {}

void TelRilHandlerTest::SetUp() {}

void TelRilHandlerTest::TearDown() {}

/**
 * @tc.number   Telephony_tel_ril_manager_001
 * @tc.name     test function branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilHandlerTest, Telephony_tel_ril_handler_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    telRilManager->handler_->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(-1);
    ASSERT_NE(telRilManager->handler_->reqRunningLockCount_, 0);
}

/**
 * @tc.number   Telephony_tel_ril_handler_002
 * @tc.name     test function branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilHandlerTest, Telephony_tel_ril_handler_002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    #ifdef ABILITY_POWER_SUPPORT
    telRilManager->handler_->ackRunningLock_ = nullptr;
    telRilManager->handler_->reqRunningLock_  = nullptr;
    #endif
    int32_t lockType = 100;
    telRilManager->handler_->ApplyRunningLock(lockType);
    ASSERT_NE(telRilManager->handler_->ackLockSerialNum_, 0);
}

/**
 * @tc.number   Telephony_tel_ril_handler_003
 * @tc.name     test function branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilHandlerTest, Telephony_tel_ril_handler_003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    int32_t lockType = TelRilHandler::NORMAL_RUNNING_LOCK;
    telRilManager->handler_->ReduceRunningLock(lockType);
    ASSERT_NE(telRilManager->handler_->reqRunningLockCount_, 0);
    lockType = TelRilHandler::ACK_RUNNING_LOCK;
    telRilManager->handler_->ReduceRunningLock(lockType);
    ASSERT_NE(telRilManager->handler_->reqRunningLockCount_, 0);
    #ifdef ABILITY_POWER_SUPPORT
    telRilManager->handler_->reqRunningLock_ = nullptr;
    #endif
    lockType = TelRilHandler::NORMAL_RUNNING_LOCK;
    telRilManager->handler_->ReduceRunningLock(lockType);
    ASSERT_NE(telRilManager->handler_->reqRunningLockCount_, 0);
    lockType = TelRilHandler::ACK_RUNNING_LOCK;
    telRilManager->handler_->ReduceRunningLock(lockType);
    ASSERT_NE(telRilManager->handler_->reqRunningLockCount_, 0);
}

/**
 * @tc.number   Telephony_tel_ril_handler_004
 * @tc.name     test function branch
 * @tc.desc     Function test
 */
HWTEST_F(TelRilHandlerTest, Telephony_tel_ril_handler_004, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    int32_t lockType = TelRilHandler::NORMAL_RUNNING_LOCK;
    telRilManager->handler_->ReleaseRunningLock(lockType);
    #ifdef ABILITY_POWER_SUPPORT
    telRilManager->handler_->ackRunningLock_ = nullptr;
    #endif
    telRilManager->handler_->ReleaseRunningLock(lockType);
    ASSERT_NE(telRilManager->handler_->reqRunningLockCount_, 0);
    #ifdef ABILITY_POWER_SUPPORT
    telRilManager->handler_->reqRunningLock_ = nullptr;
    #endif
    telRilManager->handler_->ReleaseRunningLock(lockType);
    ASSERT_NE(telRilManager->handler_->reqRunningLockCount_, 0);
}
} // namespace Telephony
} // namespace OHOS