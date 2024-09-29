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

#include "common_event_manager.h"
#include "common_event_support.h"
#include "gtest/gtest.h"
#include "sim_file_manager.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class EsimFileManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimFileManagerTest::TearDownTestCase() {}

void EsimFileManagerTest::SetUp() {}

void EsimFileManagerTest::TearDown() {}

void EsimFileManagerTest::SetUpTestCase() {}

HWTEST_F(EsimFileManagerTest, ResetMemory_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    ResultState res = simFileManager.ResetMemory(resetOption);
    EXPECT_NE(res, ResultState::RESULT_UNDEFINED_ERROR);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.ResetMemory(resetOption);
    EXPECT_EQ(res, ResultState::RESULT_UNDEFINED_ERROR);
}

HWTEST_F(EsimFileManagerTest, SetDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    std::u16string defaultSmdpAddress = u"";
    ResultState res = simFileManager.SetDefaultSmdpAddress(defaultSmdpAddress);
    EXPECT_NE(res, ResultState::RESULT_UNDEFINED_ERROR);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.SetDefaultSmdpAddress(defaultSmdpAddress);
    EXPECT_EQ(res, ResultState::RESULT_UNDEFINED_ERROR);
}

HWTEST_F(EsimFileManagerTest, IsEsimSupported_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    bool res = simFileManager.IsEsimSupported();
    EXPECT_EQ(res, false);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.IsEsimSupported();
    EXPECT_EQ(res, false);
}

HWTEST_F(EsimFileManagerTest, SendApduData_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    std::u16string aid = u"";
    std::u16string apduData = u"";
    ResponseEsimResult res = simFileManager.SendApduData(aid, apduData);
    EXPECT_EQ(res.resultCode, ResultState::RESULT_OK);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.SendApduData(aid, apduData);
    EXPECT_EQ(res.resultCode, ResultState::RESULT_OK);
}
} // namespace Telephony
} // namespace OHOS