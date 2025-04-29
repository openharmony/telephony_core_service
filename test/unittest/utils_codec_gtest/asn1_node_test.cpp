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
#include <securec.h>
#include "asn1_decoder.h"
#include "asn1_node.h"
#include "asn1_utils.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_tag_def.h"

using namespace testing::ext;
namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
#define private public
#define protected public
class Asn1NodeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    std::shared_ptr<Asn1Node> Asn1ParseResponse(std::vector<uint8_t> response, int32_t respLength);
};

void Asn1NodeTest::SetUpTestCase() {}

void Asn1NodeTest::TearDownTestCase() {}

void Asn1NodeTest::SetUp() {}

void Asn1NodeTest::TearDown() {}

std::shared_ptr<Asn1Node> Asn1NodeTest::Asn1ParseResponse(std::vector<uint8_t> response, int32_t respLength)
{
    TELEPHONY_LOGD("enter Asn1ParseResponse");
    if (response.empty() || respLength == 0) {
        TELEPHONY_LOGE("response null, respLen = %d", respLength);
        return nullptr;
    }
    Asn1Decoder decoder(response, 0, respLength);
    if (!decoder.Asn1HasNextNode()) {
        TELEPHONY_LOGE("Empty response.");
        return nullptr;
    }

    std::shared_ptr<Asn1Node> node = decoder.Asn1NextNode();
    return node;
}

HWTEST_F(Asn1NodeTest, Asn1NodeToHexStr_001, Function | MediumTest | Level3)
{
    int32_t tag = 0x81;
    std::vector<uint8_t> src;
    std::string destStr;
    uint32_t res = -1;
    bool ret = false;

    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, 0, 0);
    res = asn1Node->Asn1NodeToHexStr(destStr);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1NodeTest, Asn1NodeToBytes_001, Function | MediumTest | Level3)
{
    int32_t tag = 0x81;
    std::vector<uint8_t> src;
    std::vector<uint8_t> destStr;
    uint32_t res = -1;
    bool ret = false;

    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, 0, 0);
    res = asn1Node->Asn1NodeToBytes(destStr);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);

    asn1Node->encodedLength_ = 0;
    res = asn1Node->Asn1NodeToBytes(destStr);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1NodeTest, Asn1GetChild_001, Function | MediumTest | Level3)
{
    int32_t tag = 0;
    std::vector<uint8_t> src;
    bool ret = false;
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, 0, 0);
    std::shared_ptr<Asn1Node> pAsn1GetChild = asn1Node->Asn1GetChild(tag);
    ret = pAsn1GetChild == nullptr ? true : false;
    EXPECT_EQ(ret, true);

    asn1Node->constructed_ = false;
    pAsn1GetChild = asn1Node->Asn1GetChild(tag);
    ret = pAsn1GetChild == nullptr ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1NodeTest, Asn1HasChild_001, Function | MediumTest | Level3)
{
    bool ret = false;
    int32_t tag = 0;
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, 0, 0);
    asn1Node->constructed_ = false;
    ret = asn1Node->Asn1HasChild(TAG_ESIM_CTX_1);
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1NodeTest, Asn1GetGrandson_001, Function | MediumTest | Level3)
{
    int32_t tag = 0;
    bool ret = false;
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, 0, 0);
    std::shared_ptr<Asn1Node> pAsn1GetChild = asn1Node->Asn1GetGrandson(tag, tag);
    ret = pAsn1GetChild == nullptr ? true : false;
    EXPECT_EQ(ret, true);

    const std::string resultData = "BF208184A08181E37F"
                                   "5A0A89670000000000452301"
                                   "90046E69636B"
                                   "9103746D6F6D"
                                   "92027031"
                                   "B70F800312F34581030102038203040506"
                                   "9F700101"
                                   "950101"
                                   "990206C0"
                                   "BF7645E243E135C114ABCD92CBB156B280FA4E1429A6ECEEB6E5C1BFE4"
                                   "CA1D636F6D2E676F6F676C652E616E64726F69642E617070732E6D79617070"
                                   "E30ADA080000000000000000"
                                   "9000";
    std::vector<uint8_t> responseByte;
    int32_t byteLen = 0;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    if (root == nullptr) {
        ret = root == nullptr ? true : false;
        EXPECT_EQ(ret, true);
    } else {
        pAsn1GetChild = root->Asn1GetGrandson(TAG_ESIM_CTX_COMP_0, TAG_ESIM_PROFILE_INFO);
        ret = pAsn1GetChild == nullptr ? true : false;
        EXPECT_EQ(ret, false);
    }
}

HWTEST_F(Asn1NodeTest, Asn1GetChildren_001, Function | MediumTest | Level3)
{
    int32_t ret = 0;
    const std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020410BF2F128001020C09736D6470322E636F60810204209000";
    std::vector<uint8_t> responseByte;
    int32_t byteLen = 0;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    std::list<std::shared_ptr<Asn1Node>> ls;
    ret = root->Asn1GetChildren(TAG_ESIM_NOTIFICATION_METADATA, ls);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);

    root->constructed_ = false;
    ret = root->Asn1GetChildren(TAG_ESIM_NOTIFICATION_METADATA, ls);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(Asn1NodeTest, Asn1GetHeadAsHexStr_001, Function | MediumTest | Level3)
{
    int32_t tag = 0;
    std::vector<uint8_t> src;
    std::string headHex;
    int32_t offset = 0;
    int32_t length = 1;
    int32_t res = -1;
    bool ret = false;

    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, offset, length);
    res = asn1Node->Asn1GetHeadAsHexStr(headHex);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(Asn1NodeTest, Asn1AsBytes_001, Function | MediumTest | Level3)
{
    uint32_t res = -1;
    bool ret = false;
    const std::string resultData = "BF3C148008534D44502E434F408108736D64732E636F6D9000";
    std::vector<uint8_t> responseByte;
    int32_t byteLen = 0;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    std::shared_ptr<Asn1Node> asn1Node = root->Asn1GetChild(TAG_ESIM_CTX_0);
    res = asn1Node->Asn1AsBytes(responseByte);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);

    asn1Node->constructed_ = true;
    res = asn1Node->Asn1AsBytes(responseByte);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);

    asn1Node->constructed_ = false;
    asn1Node->dataBytes_.clear();
    res = asn1Node->Asn1AsBytes(responseByte);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);

    asn1Node->constructed_ = false;
    res = asn1Node->Asn1BuildChildren();
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1NodeTest, Asn1AsInteger_001, Function | MediumTest | Level3)
{
    int32_t res = -1;
    bool ret = false;

    const std::string resultData = "BF370ABF2707A205A1038101039000";
    std::vector<uint8_t> responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    std::shared_ptr<Asn1Node> errCodeNode = nullptr;
    if (root->Asn1HasChild(TAG_ESIM_PROFILE_INSTALLATION_RESULT_DATA)) {
        std::shared_ptr<Asn1Node> resultNode = root->Asn1GetChild(TAG_ESIM_PROFILE_INSTALLATION_RESULT_DATA);
        errCodeNode = resultNode->Asn1GetGreatGrandson(TAG_ESIM_CTX_COMP_2, TAG_ESIM_CTX_COMP_1, TAG_ESIM_CTX_1);
        res = errCodeNode->Asn1AsInteger();
        ret = res == -1 ? true : false;
        EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    }
    root->constructed_ = true;
    res = root->Asn1AsInteger();
    ret = res == -1 ? true : false;
    EXPECT_EQ(ret, true);

    root->constructed_ = false;
    root->dataBytes_.clear();
    res = root->Asn1AsInteger();
    ret = res == -1 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1NodeTest, Asn1AsInteger_002, Function | MediumTest | Level3)
{
    uint32_t tag = 0;
    std::vector<uint8_t> src = {0, 1, 2};
    uint32_t offset = 0;
    uint32_t length = 5;
    std::shared_ptr<Asn1Node> root = std::make_shared<Asn1Node>(tag, src, offset, length);
    EXPECT_EQ(root->Asn1AsInteger(), -1);
}

HWTEST_F(Asn1NodeTest, Asn1AsString_001, Function | MediumTest | Level3)
{
    uint32_t res = -1;
    bool ret = false;
    std::string output;

    const std::string resultData = "BF370581030000009000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    std::shared_ptr<Asn1Node> childNode = root->Asn1GetChild(TAG_ESIM_CTX_1);
    res = childNode->Asn1AsString(output);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);

    childNode->constructed_ = true;
    res = childNode->Asn1AsString(output);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);

    childNode->constructed_ = false;
    childNode->dataBytes_.clear();
    res = childNode->Asn1AsString(output);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1NodeTest, Asn1AsBits_001, Function | MediumTest | Level3)
{
    int32_t res = -1;
    bool ret = false;

    const std::string resultData = "BF370581030102039000";
    std::vector<uint8_t> responseByte;
    responseByte = Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = Asn1ParseResponse(responseByte, byteLen);
    std::shared_ptr<Asn1Node> childNode = root->Asn1GetChild(TAG_ESIM_CTX_1);
    res = childNode->Asn1AsBits();
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);

    childNode->constructed_ = true;
    res = childNode->Asn1AsBits();
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);

    childNode->constructed_ = false;
    childNode->dataBytes_.clear();
    res = childNode->Asn1AsBits();
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, true);
}

HWTEST_F(Asn1NodeTest, Asn1AsBits_002, Function | MediumTest | Level3)
{
    uint32_t tag = 0;
    std::vector<uint8_t> src = {0, 1, 2};
    uint32_t offset = 0;
    uint32_t length = 5;
    std::shared_ptr<Asn1Node> root = std::make_shared<Asn1Node>(tag, src, offset, length);
    EXPECT_EQ(root->Asn1AsBits(), 0);
}

HWTEST_F(Asn1NodeTest, Asn1AsBits_003, Function | MediumTest | Level3)
{
    uint32_t tag = 0;
    std::vector<uint8_t> src = {0, 1, 2};
    uint32_t offset = 0;
    uint32_t length = 0;
    std::shared_ptr<Asn1Node> root = std::make_shared<Asn1Node>(tag, src, offset, length);
    EXPECT_EQ(root->Asn1AsBits(), 0);
}

HWTEST_F(Asn1NodeTest, Asn1AsBits_004, Function | MediumTest | Level3)
{
    uint32_t tag = 0;
    std::vector<uint8_t> src = {0, 1, 2};
    uint32_t offset = 6;
    uint32_t length = 1;
    std::shared_ptr<Asn1Node> root = std::make_shared<Asn1Node>(tag, src, offset, length);
    EXPECT_EQ(root->Asn1AsBits(), 0);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS