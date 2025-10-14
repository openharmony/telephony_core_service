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
#define BATCH_INSERT_APN_RETRY_DEALY 1
#include "operator_config_cache.h"
#include "mock_datashare_helper.h"
#include "tel_ril_manager.h"
#include "common_event_support.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <thread>
#include <chrono>

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class OperatorConfigCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
 
void OperatorConfigCacheTest::SetUpTestCase() {}
 
void OperatorConfigCacheTest::TearDownTestCase() {}
 
void OperatorConfigCacheTest::SetUp() {}
 
void OperatorConfigCacheTest::TearDown() {}

/**
 * @tc.number   Telephony_NotifyInitApnConfigs_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(OperatorConfigCacheTest, NotifyInitApnConfigsTest001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    auto dataShareHelper = std::make_shared<MockDataShareHelper>();
    EXPECT_CALL(*dataShareHelper, Creator(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::DoAll(testing::Return(nullptr)));
    operatorConfigCache->notifyInitApnConfigs(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_NE(operatorConfigCache->retryBatchInsertApnTimes_, 0);
}

HWTEST_F(OperatorConfigCacheTest, NotifyInitApnConfigsTest002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    auto dataShareHelper = std::make_shared<MockDataShareHelper>();
    EXPECT_CALL(*dataShareHelper, Creator(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::DoAll(testing::Return(nullptr)));
    operatorConfigCache->notifyInitApnConfigs(0);
    operatorConfigCache->batchInsertApnRetryHandler_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_NE(operatorConfigCache->retryBatchInsertApnTimes_, 0);
}

HWTEST_F(OperatorConfigCacheTest, NotifyInitApnConfigsTest003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    auto dataShareHelper = std::make_shared<MockDataShareHelper>();
    EXPECT_CALL(*dataShareHelper, Creator(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::DoAll(testing::Return(nullptr)));
    operatorConfigCache->retryBatchInsertApnTimes_ = 5;
    operatorConfigCache->notifyInitApnConfigs(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_NE(operatorConfigCache->retryBatchInsertApnTimes_, 0);
}
}
}
