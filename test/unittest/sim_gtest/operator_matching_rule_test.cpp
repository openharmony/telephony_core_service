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

#include "operator_matching_rule.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class SimOperatorMatchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
 
void SimOperatorMatchTest::SetUpTestCase() {}
 
void SimOperatorMatchTest::TearDownTestCase() {}
 
void SimOperatorMatchTest::SetUp() {}
 
void SimOperatorMatchTest::TearDown() {}

HWTEST_F(SimOperatorMatchTest, SimOperatorMatchTest001, Function | MediumTest | Level1)
{
    OperatorMatchingRule simOperatorMatch;
    std::string iccidFromSim = "";
    std::string iccidRegex = "";
    simOperatorMatch.ImsiRegexMatch(iccidFromSim, iccidRegex);
    simOperatorMatch.IccidRegexMatch(iccidFromSim, iccidRegex);
    iccidFromSim = "89804003462611111111111111";
    simOperatorMatch.IccidRegexMatch(iccidFromSim, iccidRegex);
    iccidRegex = "^8980[0-9]{11,20}$";
    EXPECT_FALSE(simOperatorMatch.IccidRegexMatch(iccidFromSim, iccidRegex));
}

HWTEST_F(SimOperatorMatchTest, SimOperatorMatchTest002, Function | MediumTest | Level1)
{
    OperatorMatchingRule simOperatorMatch;
    std::string imsiFromSim = "";
    std::string imsiRegex = "";
    simOperatorMatch.IccidRegexMatch(imsiFromSim, imsiRegex);
    imsiFromSim = "2340110770010000000000000";
    simOperatorMatch.IccidRegexMatch(imsiFromSim, imsiRegex);
    imsiRegex = "^2\\d{11}$";
    EXPECT_FALSE(simOperatorMatch.IccidRegexMatch(imsiFromSim, imsiRegex));
}

HWTEST_F(SimOperatorMatchTest, SimOperatorMatchTest003, Function | MediumTest | Level1)
{
    OperatorMatchingRule simOperatorMatch;
    std::string spnFromSim = "";
    std::string spnRegex = "null";
    simOperatorMatch.SpnRegexMatch(spnFromSim, spnRegex);
    spnRegex = "";
    simOperatorMatch.SpnRegexMatch(spnFromSim, spnRegex);
    spnFromSim = "Com1";
    spnRegex = "Com\\d";
    simOperatorMatch.IccidRegexMatch(spnFromSim, spnRegex);
    spnRegex = "Com2\\d";
    EXPECT_FALSE(simOperatorMatch.IccidRegexMatch(spnFromSim, spnRegex));
}

HWTEST_F(SimOperatorMatchTest, SimOperatorMatchTest004, Function | MediumTest | Level1)
{
    OperatorMatchingRule simOperatorMatch;
    std::string valueFromSim = "";
    std::string valuePrefix = "";
    simOperatorMatch.PrefixMatch(valueFromSim, valuePrefix);
    valueFromSim = "Com1";
    valuePrefix = "Com";
    EXPECT_TRUE(simOperatorMatch.PrefixMatch(valueFromSim, valuePrefix));
}

}
}