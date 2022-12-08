/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "gtest/gtest.h"
#include "sim_file_manager.h"
#include "sim_state_manager.h"
#include "stk_manager.h"
#include "tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_hisysevent.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {} // namespace

class DemoHandler : public AppExecFwk::EventHandler {
public:
    explicit DemoHandler(std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner) {}
    virtual ~DemoHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}
};

class BranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void BranchTest::SetUpTestCase() {}

void BranchTest::TearDownTestCase() {}

void BranchTest::SetUp() {}

void BranchTest::TearDown() {}

/**
 * @tc.number   Telephony_SimFileManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFileManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    SimFileManager simFileManager { runner, telRilManager, simStateManager };
    const std::u16string emptyStr = Str8ToStr16("");
    const std::u16string mailName = Str8ToStr16("张三");
    const std::u16string mailnumber = Str8ToStr16("13123456789");
    simFileManager.ClearData();
    EXPECT_EQ(simFileManager.GetSimOperatorNumeric(), u"");
    simFileManager.GetISOCountryCodeForSim();
    EXPECT_EQ(simFileManager.GetSimSpn(), u"");
    EXPECT_EQ(simFileManager.GetSimEons("46001", 1, true), u"");
    EXPECT_EQ(simFileManager.GetSimIccId(), u"");
    EXPECT_EQ(simFileManager.GetLocaleFromDefaultSim(), u"");
    EXPECT_EQ(simFileManager.GetSimGid1(), u"");
    EXPECT_EQ(simFileManager.GetSimGid2(), u"");
    EXPECT_EQ(simFileManager.GetSimTelephoneNumber(), u"");
    EXPECT_EQ(simFileManager.GetSimTeleNumberIdentifier(), u"");
    EXPECT_EQ(simFileManager.GetSimIst(), u"");
    EXPECT_EQ(simFileManager.GetVoiceMailIdentifier(), u"");
    EXPECT_EQ(simFileManager.GetVoiceMailNumber(), u"");
    EXPECT_EQ(simFileManager.GetIccFile(), nullptr);
    EXPECT_EQ(simFileManager.GetIccFileController(), nullptr);
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    simFileManager.ProcessEvent(event);
    simFileManager.SetImsi("46001");
    simFileManager.SetOpName("46001");
    simFileManager.SetOpKey("CMCC");
    simFileManager.SetOpKeyExt("opkeyext");
    EXPECT_EQ(simFileManager.ObtainSpnCondition(true, "46001"), 0);
    EXPECT_FALSE(simFileManager.SetVoiceMailInfo(mailName, mailnumber));
    EXPECT_FALSE(simFileManager.HasSimCard());
    EXPECT_NE(simFileManager.GetIMSI(), u"46001");
    EXPECT_EQ(simFileManager.GetOpKey(), u"CMCC");
    EXPECT_EQ(simFileManager.GetOpName(), u"46001");
    EXPECT_EQ(simFileManager.GetOpKeyExt(), u"opkeyext");
}
} // namespace Telephony
} // namespace OHOS