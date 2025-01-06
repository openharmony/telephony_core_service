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

#include "vcard_utils.h"
#include "base64.h"

#include <iconv.h>
#include <fcntl.h>
#include <iostream>
#include <gtest/gtest.h>

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

HWTEST_F(UtilsVcardTest, Telephony_Common_EncodeBase64_001, Function | MediumTest | Level3)
{
    std::string testStr = "testStr";
    std::string answerStr = "dGVzdFN0cg==";
    std::vector<unsigned char> tempInput(testStr.begin(), testStr.end());
    std::shared_ptr<std::string> encodedDataString = OHOS::Telephony::Base64::Encode(tempInput);
    EXPECT_EQ(*encodedDataString, answerStr);
    std::string encodeBase64Resuilt = VCardUtils::EncodeBase64(testStr);
    EXPECT_EQ(encodeBase64Resuilt, answerStr);

    testStr = "!@#$%^&*(){}[]:;<>?,./\"'\\n\\t\\r\\b -_=+[]{}|;:\'\",.<>/?@ABCDqrstuvwxyz12890你\
                好🌟🚀";
    answerStr = "IUAjJCVeJiooKXt9W106Ozw+PywuLyInXG5cdFxyXGIgLV89K1tde318OzonIiwuPD4vP0BBQkNEcXJ\
                zdHV2d3h5ejEyODkw5L2g5aW98J+Mn/CfmoA=";
    tempInput.clear();
    tempInput.assign(testStr.begin(), testStr.end());
    encodedDataString = OHOS::Telephony::Base64::Encode(tempInput);
    EXPECT_EQ(*encodedDataString, answerStr);
    encodeBase64Resuilt = VCardUtils::EncodeBase64(testStr);
    EXPECT_EQ(encodeBase64Resuilt, answerStr);

    testStr = "你好，世界";   //非ASCII码
    answerStr = "5L2g5aW977yM5LiW55WM";
    tempInput.clear();
    tempInput.assign(testStr.begin(), testStr.end());
    encodedDataString = OHOS::Telephony::Base64::Encode(tempInput);
    EXPECT_EQ(encodedDataString, answerStr);
    encodeBase64Resuilt = VCardUtils::EncodeBase64(testStr);
    EXPECT_EQ(encodeBase64Resuilt, answerStr);
}

HWTEST_F(UtilsVcardTest, Telephony_Common_DecodeBase64_001, Function | MediumTest | Level3)
{
    std::string resultBase64;
    std::string testStr = "dGVzdFN0cg==";
    std::string answerStr = "testStr";
    auto decodedData_string = Base64::Decode(testStr);
    std::vector <unsigned char> &vectorRef = *decodedData_string;
    resultBase64.assign(vectorRef.begin(), vectorRef.end());
    EXPECT_EQ(resultBase64, answerStr);
    std::string decodeBase64testStr = VCardUtils::DecodeBase64(testStr);
    EXPECT_EQ(decodeBase64testStr, decodeBase64testStr_new);

    answerStr =  "!@#$%^&*(){}[]:;<>?,./\"'\\n\\t\\r\\b -_=+[]{}|;:\'\",.<>/?@ABCDqrstuvwxyz12\
                890你好🌟🚀";
    testStr = "IUAjJCVeJiooKXt9W106Ozw+PywuLyInXG5cdFxyXGIgLV89K1tde318OzonIiwuPD4vP0BBQkNEcXJ\
                zdHV2d3h5ejEyODkw5L2g5aW98J+Mn/CfmoA=";
    decodedData_string = Base64::Decode(testStr);
    resultBase64.assign(vectorRef.begin(), vectorRef.end());
    EXPECT_EQ(resultBase64, answerStr);
    decodeBase64testStr = VCardUtils::DecodeBase64(testStr);
    EXPECT_EQ(decodeBase64testStr, answerStr);

    testStr = "dGV==dFN0c=";
    answerStr = "";
    decodedData_string = Base64::Decode(testStr);
    resultBase64.assign(vectorRef.begin(), vectorRef.end());
    EXPECT_EQ(decodedData_string, nullptr);
    decodeBase64testStr = VCardUtils::DecodeBase64(testStr);
    EXPECT_EQ(decodeBase64testStr, answerStr);
}

HWTEST_F(UtilsVcardTest, Telephony_Common_ConvertCharset_001, Function | MediumTest | Level3)
{
    std::string convertCharseInput = "Hello, world! 你好，世界！";
    std::string convertCharseOutput = "Hello, world! ******";
    std::cout<< "std::string ConvertCharseInput:" << ConvertCharseInput;
    std::string fromCharset = "UTF-8";
    std::string toCharset = "ISO-8859-1";
    int32_t errorCode = 0;
    std::string resultConvert = VCardUtils::ConvertCharset(ConvertCharseInput, fromCharset, toCharset, errorCode);
    EXPECT_NE(resultConvert, convertCharseOutput);
    EXPECT_EQ(DecodeBase64testStr, convertCharseOutput);

    ConvertCharseInput = "Hello, world! こんにちは、世界!";
    std::string convertCharseOutput = "Hello, world! ±ñÉ¿ÍAE!";
    fromCharset = "UTF-8";
    toCharset = "SHIFT_JIS";
    resultConvert = VCardUtils::ConvertCharset(ConvertCharseInput, fromCharset, toCharset, errorCode);
    EXPECT_NE(resultConvert, convertCharseOutput);
    EXPECT_EQ(DecodeBase64testStr, convertCharseOutput);
}
 
}
}
