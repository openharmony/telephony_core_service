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
#include "asn1_builder.h"
#include "asn1_node.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_tag_def.h"

using namespace testing::ext;
namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT

class Asn1BuilderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Asn1BuilderTest::SetUpTestCase() {}

void Asn1BuilderTest::TearDownTestCase() {}

void Asn1BuilderTest::SetUp() {}

void Asn1BuilderTest::TearDown() {}

HWTEST_F(Asn1BuilderTest, Asn1AddChildAsString_001, Function | MediumTest | Level3)
{
    uint32_t tag = 0;
    int32_t ret = -1;
    std::string childStr = "";
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(tag);
    ret = builder->Asn1AddChildAsString(tag, childStr);
    EXPECT_EQ(ret, TELEPHONY_ERR_ARGUMENT_NULL);
    childStr = "abc";
    ret = builder->Asn1AddChildAsString(tag, childStr);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(Asn1BuilderTest, Asn1AddChildAsBytes_001, Function | MediumTest | Level3)
{
    uint32_t tag = 0;
    int32_t ret = -1;
    int32_t byteLen = 0;
    std::vector<uint8_t> childByte = {};
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(tag);
    ret = builder->Asn1AddChildAsBytes(tag, childByte, byteLen);
    EXPECT_EQ(ret, TELEPHONY_ERR_ARGUMENT_NULL);

    tag = 0x81;
    childByte.clear();
    childByte.push_back(0x61);
    childByte.push_back(0x62);
    childByte.push_back(0x63);
    ret = builder->Asn1AddChildAsBytes(tag, childByte, byteLen);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);

    tag = 0xA0;
    ret = builder->Asn1AddChildAsBytes(tag, childByte, byteLen);
    EXPECT_EQ(ret, TELEPHONY_ERR_FAIL);
}

HWTEST_F(Asn1BuilderTest, Asn1AddChildAsInteger_001, Function | MediumTest | Level3)
{
    uint32_t tag = 0xBF2B;
    int32_t ret = -1;
    uint32_t childInt = 0;
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(tag);
    ret = builder->Asn1AddChildAsInteger(tag, childInt);
    EXPECT_EQ(ret, TELEPHONY_ERR_FAIL);

    tag = 0x81;
    ret = builder->Asn1AddChildAsInteger(tag, childInt);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(Asn1BuilderTest, Asn1AddChildAsSignedInteger_001, Function | MediumTest | Level3)
{
    uint32_t tag = 0;
    int32_t ret = -1;
    int32_t childInt = 0;
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(tag);
    tag = 0xBF2B;
    ret = builder->Asn1AddChildAsSignedInteger(tag, childInt);
    EXPECT_EQ(ret, TELEPHONY_ERR_FAIL);

    tag = 0x81;
    ret = builder->Asn1AddChildAsSignedInteger(tag, childInt);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(Asn1BuilderTest, Asn1AddChildAsBits_001, Function | MediumTest | Level3)
{
    uint32_t tag = 0;
    int32_t ret = -1;
    int32_t childInt = 0;
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(tag);
    tag = 0xBF2B;
    ret = builder->Asn1AddChildAsBits(tag, childInt);
    EXPECT_EQ(ret, TELEPHONY_ERR_FAIL);

    tag = 0x81;
    ret = builder->Asn1AddChildAsBits(tag, childInt);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(Asn1BuilderTest, Asn1AddChildAsBoolean_001, Function | MediumTest | Level3)
{
    int32_t tag = 0x81;
    int32_t ret = -1;
    int32_t flag = 0;

    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(tag);
    ret = builder->Asn1AddChildAsBoolean(tag, flag);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(Asn1BuilderTest, Asn1Build_001, Function | MediumTest | Level3)
{
    int32_t tag = 0x81;
    int32_t ret = -1;

    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(tag);
    std::shared_ptr<Asn1Node> pAsn1Node = builder->Asn1Build();
    ret = pAsn1Node == nullptr ? true : false;
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(Asn1BuilderTest, Asn1BuilderToHexStr_001, Function | MediumTest | Level3)
{
    int32_t tag = 0x81;
    std::string destStr;
    uint32_t res = -1;
    bool ret = false;

    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(tag);
    res = builder->Asn1BuilderToHexStr(destStr);
    ret = res == 0 ? true : false;
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS