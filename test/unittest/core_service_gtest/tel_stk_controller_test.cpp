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
#include <gtest/gtest.h>
#include <string_ex.h>
 
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "telephony_log_wrapper.h"
#include "telephony_ext_wrapper.h"
#include "stk_controller.h"
 
namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int32_t INVALID_SLOTID = -1;
class TelStkControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void TelStkControllerTest::SetUpTestCase() {}
 
void TelStkControllerTest::TearDownTestCase() {}
 
void TelStkControllerTest::SetUp() {}
 
void TelStkControllerTest::TearDown() {}
 
/**
 * @tc.number   Telephony_StkController_StkBundleName_001
 * @tc.name     test stk bundle name
 * @tc.desc     Function test
 */
HWTEST_F(TelStkControllerTest, Telephony_StkController_StkBundleName_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto stkController = std::make_shared<StkController>(telRilManager, simStateManager, INVALID_SLOTID);
    auto tempFunc = TELEPHONY_EXT_WRAPPER.getStkBundleNameFunc_;
    TELEPHONY_EXT_WRAPPER.getStkBundleNameFunc_ = nullptr;
    stkController->InitStkBundleName();
    EXPECT_TRUE(stkController->stkBundleName_.empty());
    TELEPHONY_EXT_WRAPPER.getStkBundleNameFunc_ = [](std::string &bundleName) { bundleName = "123"; };
    stkController->InitStkBundleName();
    EXPECT_TRUE(!stkController->stkBundleName_.empty());
    TELEPHONY_EXT_WRAPPER.getStkBundleNameFunc_ = tempFunc;
}
 
/**
 * @tc.number   Telephony_StkController_StkBundleName_002
 * @tc.name     test stk bundle name ext
 * @tc.desc     Function test
 */
HWTEST_F(TelStkControllerTest, Telephony_StkController_StkBundleName_002, Function | MediumTest | Level1)
{
    TelephonyExtWrapper telephonyExtWrapper;
    std::string bundleName;
    EXPECT_FALSE(telephonyExtWrapper.GetStkBundleName(bundleName));
    telephonyExtWrapper.getStkBundleNameFunc_ = [](std::string &bundleName) { bundleName = "123"; };
    EXPECT_TRUE(telephonyExtWrapper.GetStkBundleName(bundleName));
}

/**
 * @tc.number   Telephony_Sim_ReportEventToChr
 * @tc.name     test ReportEventToChr
 * @tc.desc     Function test
 */
HWTEST_F(TelStkControllerTest, Telephony_Sim_ReportEventToChr, Function | MediumTest | Level1)
{
    TelephonyExtWrapper telephonyExtWrapper;
    EXPECT_FALSE(telephonyExtWrapper.ReportEventToChr(0, "SIM_ACCOUNT_LOADED", 1));
    telephonyExtWrapper.reportEventToChr_ = [](int32_t slotId, const char* scenario, int32_t cause) {};
    EXPECT_TRUE(telephonyExtWrapper.ReportEventToChr(0, "SIM_ACCOUNT_LOADED", 1));
    EXPECT_TRUE(telephonyExtWrapper.ReportEventToChr(0, "SIM_ACCOUNT_LOADED", 0));
}
} // namespace Telephony
} // namespace OHOS