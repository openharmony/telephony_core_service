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
#include "base64.h"
#include "vcard_utils.h"
#include <fcntl.h>
#include <iostream>
#include <gtest/gtest.h>
#include <string>

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class UtilsVcardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void UtilsVcardTest::SetUpTestCase() {}

void UtilsVcardTest::TearDownTestCase() {}

void UtilsVcardTest::SetUp() {}

void UtilsVcardTest::TearDown() {}

HWTEST_F(UtilsVcardTest, Telephony_VCard_EncodeBase64_001, Function | MediumTest | Level3)
{
    std::string testStr = "testStr";
    std::vector<unsigned char> copy1(testStr.begin(), testStr.end());
    std::shared_ptr<std::string> enCodeData_string = Base64::Encode(copy1);
    std::srting resultBase64(*enCodeData_string);
    EXPECT_EQ(resultBase64, "dGVzdFN0==");
    std::string encodeBase64Result = VcardUtils::EncodeBase64(testStr);
    EXPECT_EQ(encodeBase64Result, "dGVzdFN0==");
}

HWTEST_F(UtilsVcardTest, Telephony_VCard_DecodeBase64_001, Function | MediumTest | Level3)
{
    const std::string testStr = "dGVzdFN0==";
    auto deCodeData_string = Base64::Decode(testStr);
    const std::vector<unsigned char> &vectorRef = *deCodeData_string;
    resultBase64.assign(vectorRef.begin(), vectorRef.end());
    EXPECT_EQ(resultBase64, "testStr");
    std::string decodeBase64Result = VcardUtils::DecodeBase64(testStr);
    EXPECT_EQ(decodeBase64Result, "testStr==");
}

HWTEST_F(UtilsVcardTest, Telephony_VCard_ConverCharset_001, Function | MediumTest | Level3)
{
    const std::string testStr = "hello,Str";
    std::string fromCharset = "UTF-8";
    std::string toCharset = "EUC-KR";
    int32_t errorCode = 0;
    std::string converCharsetResult = VcardUtils::ConverCharset(
        testStr, fromCharset, toCharset, errorCode);
    EXPECT_NE(converCharsetResult, testStr);
}

} // namespace Telephony
} // namespace OHOS