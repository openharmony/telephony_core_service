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
#define private public
#define protected public
using namespace testing::ext;
namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
const uint32_t MAX_BPP_LENGTH = 245760;
const uint32_t BYTE_TO_HEX_LEN = 2;
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
    const std::string atr2 = "12";
    EXPECT_FALSE(response.AnalysisAtrData(atr2));
    const std::string atr3 = "123";
    EXPECT_FALSE(response.AnalysisAtrData(atr3));
        const std::string atr4 = "1234";
    EXPECT_FALSE(response.AnalysisAtrData(atr4));
    const std::string atr5 = "3B9F96803F47A28031E073FE211B6759868828681011C4";
    EXPECT_TRUE(response.AnalysisAtrData(atr5));
    EXPECT_TRUE(response.IsEuiccAvailable());
    const std::string atr6 = "4B4F96803F47A28031E073FE211B6759868828681011C4";
    EXPECT_FALSE(response.AnalysisAtrData(atr6));
    std::string atr7 = "";
    for (int i = 0; i < MAX_BPP_LENGTH * BYTE_TO_HEX_LEN + 2; i++) {
        atr7 += "0";
    }
    EXPECT_FALSE(response.AnalysisAtrData(atr7));
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

HWTEST_F(ResetResponseTest, AnalysisInterfaceData_ValidInput, Function | MediumTest | Level1)
{
    ResetResponse response;
    std::vector<uint8_t> atrData;
    uint32_t atrDataLen = 0;
    uint32_t index = 0;
    EXPECT_TRUE(response.AnalysisInterfaceData(atrData, atrDataLen, index));
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
