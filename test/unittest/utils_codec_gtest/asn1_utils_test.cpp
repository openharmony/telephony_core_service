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

#include <cstdbool>
#include <gtest/gtest.h>
#include <iostream>
#include "asn1_constants.h"
#include "asn1_utils.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

using namespace testing::ext;
namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
class Asn1UtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Asn1UtilsTest::SetUpTestCase() {}

void Asn1UtilsTest::TearDownTestCase() {}

void Asn1UtilsTest::SetUp() {}

void Asn1UtilsTest::TearDown() {}

HWTEST_F(Asn1UtilsTest, IsConstructedTag_001, Function | MediumTest | Level3)
{
    uint32_t tag = 1;
    bool ret = Asn1Utils::IsConstructedTag(tag);
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, CalculateEncodedBytesNumForLength_001, Function | MediumTest | Level3)
{
    bool ret = false;
    uint32_t tag = 1;
    uint32_t result = Asn1Utils::CalculateEncodedBytesNumForLength(tag);
    ret = result == 1 ? true : false;
    EXPECT_EQ(ret, true);

    tag = 0xFF;
    result = Asn1Utils::CalculateEncodedBytesNumForLength(tag);
    ret = result == 2 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1UtilsTest, ByteCountForUint_001, Function | MediumTest | Level3)
{
    bool ret = false;
    uint32_t tag = 1;
    uint32_t result = Asn1Utils::ByteCountForUint(tag);
    ret = result == 1 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1UtilsTest, BchToString_001, Function | MediumTest | Level3)
{
    bool ret = false;
    std::vector<uint8_t> responseByte;
    std::string destStr;
    Asn1Utils::BchToString(responseByte, destStr);
    int32_t res = destStr.size();
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1UtilsTest, BcdToBytes_001, Function | MediumTest | Level3)
{
    bool ret = false;
    std::vector<uint8_t> iccidBytes;
    const std::string str = "ABCDEFG";
    Asn1Utils::BcdToBytes(str.c_str(), iccidBytes);
    uint32_t iccidBytesLen = iccidBytes.size();
    ret = iccidBytesLen == 4 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1UtilsTest, BytesToHexStr_001, Function | MediumTest | Level3)
{
    int32_t res = -1;
    bool ret = false;
    const std::string resultData = "BF3C148008534D44502E434F408108736D64732E636F6D9000";
    std::vector<uint8_t> responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    std::string strResult;
    strResult = Asn1Utils::BytesToHexStr(responseByte);
    res = strResult.length();
    ret = res > 0 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1UtilsTest, ByteCountForInt_001, Function | MediumTest | Level3)
{
    uint32_t res = -1;
    uint32_t value = 0;
    uint32_t resOne = 1;
    uint32_t resTwo = 2;
    uint32_t resThree = 3;
    uint32_t resFour = 4;

    res = Asn1Utils::ByteCountForInt(value, false);
    EXPECT_EQ(res, resOne);

    value = 0x7F;
    res = Asn1Utils::ByteCountForInt(value, true);
    EXPECT_EQ(res, resOne);

    value = 0x7FFF;
    res = Asn1Utils::ByteCountForInt(value, true);
    EXPECT_EQ(res, resTwo);

    value = 0x7FFFFF;
    res = Asn1Utils::ByteCountForInt(value, true);
    EXPECT_EQ(res, resThree);

    value = 0xFF;
    res = Asn1Utils::ByteCountForInt(value, false);
    EXPECT_EQ(res, resOne);

    value = 0xFFFF;
    res = Asn1Utils::ByteCountForInt(value, false);
    EXPECT_EQ(res, resTwo);

    value = 0xFFFFFF;
    res = Asn1Utils::ByteCountForInt(value, false);
    EXPECT_EQ(res, resThree);

    value = 0xFFFFFF0;
    res = Asn1Utils::ByteCountForInt(value, false);
    EXPECT_EQ(res, resFour);

    value = 0xFFFFFF0;
    res = Asn1Utils::ByteCountForInt(value, true);
    EXPECT_EQ(res, resFour);
}

HWTEST_F(Asn1UtilsTest, HexStrToBytes_001, Function | MediumTest | Level3)
{
    const std::string resultData = "BF3C148008534D44502E434F408108736D64732E636F6D9000";
    std::vector<uint8_t> responseByte;
    bool ret = false;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    ret = byteLen == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, UintToBytes_001, Function | MediumTest | Level3)
{
    bool ret = false;
    uint32_t res = 0;
    uint32_t value = 0xFF;
    std::vector<uint8_t> versionBytes;
    res = Asn1Utils::UintToBytes(value, versionBytes);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, BytesToString_001, Function | MediumTest | Level3)
{
    int32_t res = -1;
    bool ret = false;
    const std::string resultData = "BF3C148008534D44502E434F408108736D64732E636F6D9000";
    std::vector<uint8_t> responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    std::string strResult;
    strResult = Asn1Utils::BytesToString(responseByte);
    res = strResult.length();
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, BytesToInt_001, Function | MediumTest | Level3)
{
    bool ret = false;
    const std::string resultData = "010000";
    std::vector<uint8_t> responseByte;
    int32_t offset = 0;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = Asn1Utils::BytesToInt(responseByte, offset, responseByte.size());
    ret = byteLen == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, StrToHexStr_001, Function | MediumTest | Level3)
{
    bool ret = false;
    int32_t res = 0;
    std::string bufOut = Asn1Utils::StrToHexStr(std::string("BF370ABF2707A205A103810103"));
    res = bufOut.length();
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, StringToBytes_001, Function | MediumTest | Level3)
{
    bool ret = false;
    uint32_t res = 0;
    const std::string src = "BF2102A0009000";
    std::vector<uint8_t> dest;
    dest = Asn1Utils::StringToBytes(src);
    res = dest.size();
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, HexStrToString_001, Function | MediumTest | Level3)
{
    bool ret = false;
    const std::string src = "BF2102A0009000";
    std::string dest;
    dest = Asn1Utils::HexStrToString(src);
    size_t length = dest.length();
    ret = length == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, CountTrailingZeros_001, Function | MediumTest | Level3)
{
    bool ret = false;
    uint8_t res = 0;
    uint8_t b = 0;
    res = Asn1Utils::CountTrailingZeros(b);
    ret = res == 8 ? true : false;
    EXPECT_EQ(ret, true);

    b = 1;
    res = Asn1Utils::CountTrailingZeros(b);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);

    b = 8;
    res = Asn1Utils::CountTrailingZeros(b);
    ret = res == 3 ? true : false;
    EXPECT_EQ(ret, true);

    b = 32;
    res = Asn1Utils::CountTrailingZeros(b);
    ret = res == 5 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1UtilsTest, ReverseInt_001, Function | MediumTest | Level3)
{
    bool ret = false;
    uint32_t res = 0;
    uint32_t i = 1;
    res = Asn1Utils::ReverseInt(i);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1UtilsTest, ByteToHexStr_001, Function | MediumTest | Level3)
{
    bool ret = false;
    uint32_t res = 0;
    uint8_t src = 1;
    std::string dest;
    res = Asn1Utils::ByteToHexStr(src, dest);
    ret = res == BYTE_TO_HEX_LEN ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1UtilsTest, IntToBytes_001, Function | MediumTest | Level3)
{
    bool ret = false;
    uint32_t res = 0;
    int32_t value = 1;
    std::vector<uint8_t> dest;
    res = Asn1Utils::IntToBytes(value, dest);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS