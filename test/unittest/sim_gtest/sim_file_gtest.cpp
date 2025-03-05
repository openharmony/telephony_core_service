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

#include <string>
#include <unistd.h>
#include "telephony_ext_wrapper.h"
#include "tel_ril_manager.h"
#include "gtest/gtest.h"
#include "sim_file.h"
#include "sim_file_init.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class SimFileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SimFileTest::TearDownTestCase() {}

void SimFileTest::SetUp() {}

void SimFileTest::TearDown() {}

void SimFileTest::SetUpTestCase() {}

/**
 * @tc.number   Telephony_sim_file_001
 * @tc.name     SimFile
 * @tc.desc     Function test
 */
HWTEST_F(SimFileTest, Telephony_sim_file_001, Function | MediumTest | Level1)
{
    std::weak_ptr<Telephony::SimStateManager> simStateManager_;
    auto simFile_ = std::make_shared<SimFile>(simStateManager_.lock());
    simFile_->ObtainMCC();

    simFile_->imsi_ = "46001";
    simFile_->lengthOfMnc_ = -1;
    simFile_->ObtainMCC();

    simFile_->lengthOfMnc_ = 5;
    simFile_->ObtainMCC();

    simFile_->lengthOfMnc_ = 0;
    auto ret = simFile_->ObtainMCC();
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number   Telephony_sim_file_002
 * @tc.name     SimFile
 * @tc.desc     Function test
 */
HWTEST_F(SimFileTest, Telephony_sim_file_002, Function | MediumTest | Level1)
{
    std::weak_ptr<Telephony::SimStateManager> simStateManager_;
    auto simFile_ = std::make_shared<SimFile>(simStateManager_.lock());
    simFile_->ObtainMCC();

    simFile_->imsi_ = "46001";
    simFile_->lengthOfMnc_ = -1;
    simFile_->ObtainMNC();

    simFile_->lengthOfMnc_ = 5;
    simFile_->ObtainMNC();

    simFile_->mnc_ = "123";
    simFile_->ObtainMNC();

    simFile_->mnc_ = "";

    simFile_->imsi_ = "";
    simFile_->ObtainMNC();

    simFile_->imsi_ = "46001";
    simFile_->lengthOfMnc_ = 0;
    auto ret = simFile_->ObtainMNC();
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number   Telephony_sim_file_003
 * @tc.name     SimFile
 * @tc.desc     Function test
 */
HWTEST_F(SimFileTest, Telephony_sim_file_003, Function | MediumTest | Level1)
{
    std::weak_ptr<Telephony::SimStateManager> simStateManager_;
    auto simFile_ = std::make_shared<SimFile>(simStateManager_.lock());
    simFile_->ObtainMCC();

    simFile_->imsi_ = "46001";
    simFile_->lengthOfMnc_ = -1;
    simFile_->ObtainMNC();

    simFile_->lengthOfMnc_ = 5;
    simFile_->ObtainMNC();

    simFile_->lengthOfMnc_ = 0;
    auto ret = simFile_->ObtainMNC();
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number   Telephony_sim_file_004
 * @tc.name     SimFile
 * @tc.desc     Function test
 */
HWTEST_F(SimFileTest, Telephony_sim_file_004, Function | MediumTest | Level1)
{
    std::weak_ptr<Telephony::SimStateManager> simStateManager_;
    auto simFile_ = std::make_shared<SimFile>(simStateManager_.lock());
    simFile_->ObtainMCC();

    simFile_->imsi_ = "46001";
    simFile_->lengthOfMnc_ = -1;
    simFile_->ObtainSimOperator();

    simFile_->lengthOfMnc_ = 5;
    simFile_->ObtainSimOperator();

    simFile_->ObtainCallForwardStatus();

    simFile_->fileToGet_ = 0;
    simFile_->lockQueried_ = true;
    simFile_->fileQueried_ = false;
    simFile_->ProcessFileLoaded(true);

    simFile_->fileQueried_ = true;
    simFile_->ProcessFileLoaded(true);

    simFile_->lengthOfMnc_ = 0;
    auto ret = simFile_->ObtainSimOperator();
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number   Telephony_sim_file_005
 * @tc.name     SimFile
 * @tc.desc     Function test
 */
HWTEST_F(SimFileTest, Telephony_sim_file_005, Function | MediumTest | Level1)
{
    std::weak_ptr<Telephony::SimStateManager> simStateManager_;
    auto simFile_ = std::make_shared<SimFile>(simStateManager_.lock());
    simFile_->ObtainIsoCountryCode();

    simFile_->operatorNumeric_ = "12";
    simFile_->ObtainIsoCountryCode();

    simFile_->operatorNumeric_ = "12345678901234568";
    simFile_->ObtainIsoCountryCode();

    simFile_->operatorNumeric_ = "1234";
    auto ret = simFile_->ObtainIsoCountryCode();
    EXPECT_EQ(ret, "");
}

}
}