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

HWTEST_F(EsimFileManagerTest, RequestDefaultSmdpAddress_001, Function | MediumTest | Level2)
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
    std::u16string resStr = simFileManager.GetDefaultSmdpAddress();
    EXPECT_EQ(resStr, u"");
    simFileManager.eSimFile_ = nullptr;
    resStr = simFileManager.GetDefaultSmdpAddress();
    EXPECT_EQ(resStr, u"");
}

HWTEST_F(EsimFileManagerTest, CancelSession_001, Function | MediumTest | Level2)
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
    std::u16string transactionId = u"";
    CancelReason cancelReason = CancelReason::CANCEL_REASON_END_USER_REJECTED;
    ResponseEsimResult res = simFileManager.CancelSession(transactionId, cancelReason);
    EXPECT_EQ(res.resultCode, ResultState::RESULT_OK);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.CancelSession(transactionId, cancelReason);
    EXPECT_EQ(res.resultCode, ResultState::RESULT_OK);
}

HWTEST_F(EsimFileManagerTest, GetProfile_001, Function | MediumTest | Level2)
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
    int32_t portIndex = 0;
    std::u16string iccId = u"";
    EuiccProfile res = simFileManager.GetProfile(portIndex, iccId);
    EXPECT_EQ(res.state, ProfileState::PROFILE_STATE_DISABLED);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.GetProfile(portIndex, iccId);
    EXPECT_EQ(res.state, ProfileState::PROFILE_STATE_DISABLED);
}
} // namespace Telephony
} // namespace OHOS