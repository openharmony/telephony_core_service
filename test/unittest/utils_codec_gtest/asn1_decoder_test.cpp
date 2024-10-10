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
class Asn1DecoderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Asn1DecoderTest::SetUpTestCase() {}

void Asn1DecoderTest::TearDownTestCase() {}

void Asn1DecoderTest::SetUp() {}

void Asn1DecoderTest::TearDown() {}

HWTEST_F(Asn1DecoderTest, BuildAsn1Node_001, Function | MediumTest | Level3)
{
    uint32_t tag = 0x81;
    std::vector<uint8_t> src = Asn1Utils::HexStrToBytes(std::string("A10401020304"));
    uint32_t offset = 1;
    uint32_t tagStart = 0;
    uint32_t decodeLen = 6;
    bool ret = false;

    std::shared_ptr<Asn1Decoder> pAsn1Decoder = std::make_shared<Asn1Decoder>(src, offset, decodeLen);
    std::shared_ptr<Asn1Node> pAsn1Node = pAsn1Decoder->BuildAsn1Node(tag, offset, tagStart);
    ret = pAsn1Node == nullptr ? true : false;
    EXPECT_EQ(ret, true);

    pAsn1Decoder = std::make_shared<Asn1Decoder>(src, 0, src.size());
    offset = 1;
    pAsn1Node = pAsn1Decoder->BuildAsn1Node(tag, offset, tagStart);
    ret = pAsn1Node == nullptr ? true : false;
    EXPECT_EQ(ret, false);
}

HWTEST_F(Asn1DecoderTest, Asn1NextNode_001, Function | MediumTest | Level3)
{
    uint32_t offset = 0;
    uint32_t decodeLen = 6;
    bool ret = false;
    std::vector<uint8_t> tmpSrc = Asn1Utils::HexStrToBytes(std::string(""));
    std::shared_ptr<Asn1Decoder> pAsn1Decoder = std::make_shared<Asn1Decoder>(tmpSrc, offset, decodeLen);
    std::shared_ptr<Asn1Node> pAsn1Node = pAsn1Decoder->Asn1NextNode();
    ret = pAsn1Node == nullptr ? true : false;
    EXPECT_EQ(ret, true);

    std::vector<uint8_t> src = Asn1Utils::HexStrToBytes(std::string("A10401020304"));
    std::shared_ptr<Asn1Decoder> pAsn1Decoder1 = std::make_shared<Asn1Decoder>(src, offset, decodeLen);
    std::shared_ptr<Asn1Node> pAsn1Node1 = pAsn1Decoder1->Asn1NextNode();
    ret = pAsn1Node1 == nullptr ? true : false;
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS