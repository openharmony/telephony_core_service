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

#include <iostream>
#include <gtest/gtest.h>
#include "reset_response.h"
#include "asn1_node.h"
#include "telephony_log_wrapper.h"

using namespace testing::ext;
namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT

class ResetResponseTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ResetResponseTest::SetUpTestCase() {}

void ResetResponseTest::TearDownTestCase() {}

void ResetResponseTest::SetUp() {}

void ResetResponseTest::TearDown() {}

HWTEST_F(ResetResponseTest, ParseAtrData_ValidInput, Function | MediumTest | Level1)
{
    ResetResponse response;
    const std::string atr1 = "";
    EXPECT_FALSE(response.AnalysisAtrData(atr1));
    const std::string atr2 = "123";
    EXPECT_FALSE(response.AnalysisAtrData(atr2));
    const std::string atr3 = "12";
    EXPECT_FALSE(response.AnalysisAtrData(atr3));
    const std::string atr = "3B9F96803F47A28031E073FE211B6759868828681011C4";
    EXPECT_TRUE(response.AnalysisAtrData(atr));
    EXPECT_TRUE(response.IsEuiccAvailable());
}

HWTEST_F(ResetResponseTest, CheckAtrDataParam_ValidInput, Function | MediumTest | Level1)
{
    ResetResponse response;
    const std::string atr1 = "";
    EXPECT_FALSE(response.CheckAtrDataParam(atr1));
    const std::string atr2 = "123";
    EXPECT_FALSE(response.CheckAtrDataParam(atr2));
    const std::string atr3 = "12";
    EXPECT_FALSE(response.CheckAtrDataParam(atr3));
    const std::string atr4 = "1234";
    EXPECT_TRUE(response.CheckAtrDataParam(atr4));
}

HWTEST_F(ResetResponseTest, CheckIsEuiccAvailable_ValidInput, Function | MediumTest | Level1)
{
    ResetResponse response;
    uint8_t charB = '\0';
    uint8_t charD = 'A';
    EXPECT_FALSE(response.CheckIsEuiccAvailable(charB, charD));

    charB = 'A';
    charD = '\0';
    EXPECT_FALSE(response.CheckIsEuiccAvailable(charB, charD));

    charB = 0xA2;
    charD = 0x3F;
    EXPECT_TRUE(response.CheckIsEuiccAvailable(charB, charD));
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
