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
#include "tel_ril_manager.h"
#include "sim_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
const int32_t SLOT_ID_0 = 0;
const int32_t INVALID_SLOTID = -1;
} // namespace

class SimManagerBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SimManagerBranchTest::TearDownTestCase() {}

void SimManagerBranchTest::SetUp() {}

void SimManagerBranchTest::TearDown() {}

void SimManagerBranchTest::SetUpTestCase() {}

HWTEST_F(SimManagerBranchTest, Telephony_SimManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    simManager->OnInit(MAX_SLOT_COUNT);
    std::u16string testStr = u"";
    std::u16string result;
    EXPECT_EQ(simManager->GetSimOperatorNumeric(INVALID_SLOTID, result), TELEPHONY_ERR_NO_SIM_CARD);
    EXPECT_EQ(simManager->GetOpName(INVALID_SLOTID, result), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(simManager->GetSimOperatorNumeric(1, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simManager->GetOpName(1, testStr), TELEPHONY_ERR_SUCCESS);
    simManager->simFileManager_[0] = nullptr;
    EXPECT_EQ(simManager->GetSimOperatorNumeric(0, testStr), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(simManager->GetOpName(0, testStr), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

} // namespace Telephony
} // namespace OHOS
