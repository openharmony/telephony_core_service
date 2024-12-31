#define private public
#define protected public
#incldue "base64.h"
#incldue "vcard_utils.h"
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
    std::sting resultBase64(*enCodeData_string);
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