/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <string>
#include <unistd.h>

#include "esim_file.h"

// #include "asn1_node.h"
// #include "common_event_manager.h"
// #include "common_event_support.h"
// #include "esim_file.h"
// #include "icc_file.h"
// #include "sim_file_manager.h"
// #include "sim_constant.h"
// #include "sim_file_manager.h"
#include "event_handler.h"
#include "mock_tel_ril_manager.h"
#include "telephony_log_wrapper.h"
#include "tel_ril_manager.h"
#include "telephony_tag_def.h"
// #include "esim_state_type.h"
#include "gtest/gtest.h"
#include "str_convert.h"

namespace OHOS {
namespace Telephony {
using namespace testing;
using namespace testing::ext;
class EsimfileBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
public:
    static MockTelRilManager *telRilManager_;
    static std::shared_ptr<Telephony::EsimFile> esimFile;
    static MockAsn1Node *mockAsn1Node;
};

    MockTelRilManager *EsimfileBranchTest::telRilManager_ = nullptr;
    std::shared_ptr<Telephony::EsimFile> EsimfileBranchTest::esimFile = nullptr;
    MockAsn1Node *EsimfileBranchTest::mockAsn1Node = nullptr;

void EsimfileBranchTest::TearDownTestCase() {}

void EsimfileBranchTest::SetUp()
{
    telRilManager_ = new MockTelRilManager();
    std::shared_ptr<MockTelRilManager> telRilManager(telRilManager_);
    esimFile = std::make_shared<EsimFile>(telRilManager);
}

void EsimfileBranchTest::TearDown() {}

void EsimfileBranchTest::SetUpTestCase() {}

HWTEST_F(EsimfileBranchTest, CarrierIdentifiers_001, Function | MediumTest | Level2)
{
    std::vector<uint8_t> mccMncData = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    int mccMncLen = 6;
    std::u16string gid1 = u"gid1";
    std::u16string gid2 = u"gid2";

    CarrierIdentifier result = esimFile->CarrierIdentifiers(mccMncData, mccMncLen, gid1, gid2);

    std::string expectedMcc = "001";
    std::string expectedMnc = "200";
    std::u16string expectedGid1 = u"gid1";
    std::u16string expectedGid2 = u"gid2";

    EXPECT_EQ(result.mcc_, OHOS::Telephony::ToUtf16(expectedMcc));
    EXPECT_EQ(result.mnc_, OHOS::Telephony::ToUtf16(expectedMnc));
    EXPECT_EQ(result.gid1_, expectedGid1);
    EXPECT_EQ(result.gid2_, expectedGid2);
}

HWTEST_F(EsimfileBranchTest, CarrierIdentifiers_002, Function | MediumTest | Level2)
{
    std::vector<uint8_t> mccMncData = {0x00, 0x01, 0xFF, 0x03, 0x04, 0x05};
    int mccMncLen = 6;
    std::u16string gid1 = u"gid1";
    std::u16string gid2 = u"gid2";

    CarrierIdentifier result = esimFile->CarrierIdentifiers(mccMncData, mccMncLen, gid1, gid2);

    std::string expectedMcc = "001";
    std::string expectedMnc = "FF0"; // mnc[2] = 'F'

    EXPECT_EQ(result.mcc_, OHOS::Telephony::ToUtf16(expectedMcc));
    EXPECT_EQ(result.mnc_, OHOS::Telephony::ToUtf16(expectedMnc));
}

HWTEST_F(EsimfileBranchTest, buildCarrierIdentifiers_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(3)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_))
        .Times(3)
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(0));

    CarrierIdentifier result = esimFile->buildCarrierIdentifiers(mockAsn1Node);

    std::u16string expectedGid1 = u"";
    std::u16string expectedGid2 = u"";

    EXPECT_EQ(result.gid1_, expectedGid1);
    EXPECT_EQ(result.gid2_, expectedGid2);
}

HWTEST_F(EsimfileBranchTest, buildCarrierIdentifiers_002, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(3)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_))
        .Times(2)
        .WillOnce(Return(0))
        .WillOnce(Return(0));

    CarrierIdentifier result = esimFile->buildCarrierIdentifiers(mockAsn1Node);

    std::u16string expectedGid1 = u"";
    std::u16string expectedGid2 = u"";

    EXPECT_EQ(result.gid1_, expectedGid1);
    EXPECT_EQ(result.gid2_, expectedGid2);
}

HWTEST_F(EsimfileBranchTest, buildCarrierIdentifiers_003, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(2)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_))
        .Times(1)
        .WillOnce(Return(0));

    CarrierIdentifier result = esimFile->buildCarrierIdentifiers(mockAsn1Node);

    std::u16string expectedGid1 = u"";
    std::u16string expectedGid2 = u"";

    EXPECT_EQ(result.gid1_, expectedGid1);
    EXPECT_EQ(result.gid2_, expectedGid2);
}

HWTEST_F(EsimfileBranchTest, buildCarrierIdentifiers_004, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(1)
        .WillOnce(Return(nullptr));

    CarrierIdentifier result = esimFile->buildCarrierIdentifiers(mockAsn1Node);

    std::u16string expectedGid1 = u"";
    std::u16string expectedGid2 = u"";

    EXPECT_EQ(result.gid1_, expectedGid1);
    EXPECT_EQ(result.gid2_, expectedGid2);
}

HWTEST_F(EsimfileBranchTest, ObtainEid_001, Function | MediumTest | Level2)
{
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    esimFile->BuildCallerInfo(-1);
    esimFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EID_DONE);
    bool ret = esimFile->ProcessEsimCloseSpareChannelDone(event);
    EXPECT_TRUE(ret);

    esimFile->currentChannelId_ = 1;
    std::string res = esimFile->ObtainEid();
    EXPECT_TRUE(res.empty());
}

HWTEST_F(EsimfileBranchTest, Asn1ParseResponse_001, Function | MediumTest | Level2)
{
    std::vector<uint8_t> src {1, 2, 3, 4, 5};
    uint32_t offset = 0;
    uint32_t decodeLen = 0;
    MockAsn1Decoder mockAsn1Decoder(src, offset, decodeLen);
    std::shared_ptr<Asn1Node> ret = esimFile->Asn1ParseResponse(src, decodeLen);
    EXPECT_EQ(ret, nullptr);

    std::vector<uint8_t> src1 {};
    decodeLen = 5;
    ret = esimFile->Asn1ParseResponse(src1, decodeLen);
    EXPECT_EQ(ret, nullptr);

    EXPECT_CALL(mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(false));
    ret = esimFile->Asn1ParseResponse(src, decodeLen);
    EXPECT_EQ(ret, nullptr);

    EXPECT_CALL(mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(nullptr));
    ret = esimFile->Asn1ParseResponse(src, decodeLen);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(EsimfileBranchTest, ObtainEuiccInfo1ParseTagCtx2_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    bool ret = esimFile->ObtainEuiccInfo1ParseTagCtx2(asn1Node);
    EXPECT_FALSE(ret);

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(asn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_)).WillOnce(Return(0));
    ret = esimFile->ObtainEuiccInfo1ParseTagCtx2(asn1Node);
    EXPECT_FALSE(ret);

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(asn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_)).WillOnce(Return(4));
    ret = esimFile->ObtainEuiccInfo1ParseTagCtx2(asn1Node);
    EXPECT_TRUE(ret);
}

HWTEST_F(EsimfileBranchTest, BuildBasicProfileInfo_000, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EuiccProfileInfo *eProfileInfo1 = nullptr;
    std::shared_ptr<Asn1Node> asn1Node1 = std::make_shared<Asn1Node>();
    esimFile->BuildBasicProfileInfo(eProfileInfo1, asn1Node1);

    std::shared_ptr<Asn1Node> asn1Node2 = nullptr;
    EuiccProfileInfo *eProfileInfo2 = new (std::nothrow)EuiccProfileInfo();
    esimFile->BuildBasicProfileInfo(eProfileInfo2, asn1Node2);
}

HWTEST_F(EsimfileBranchTest, BuildBasicProfileInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(11)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(12)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_))
        .Times(4)
        .WillOnce(Return(5))
        .WillOnce(Return(5))
        .WillOnce(Return(5))
        .WillOnce(Return(5));
    esimFile->BuildBasicProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildBasicProfileInfo_002, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();

    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(3)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(4)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_))
        .Times(3)
        .WillOnce(Return(5))
        .WillOnce(Return(5))
        .WillOnce(Return(5));
    esimFile->BuildBasicProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildBasicProfileInfo_003, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();

    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(3)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_))
        .Times(2)
        .WillOnce(Return(5))
        .WillOnce(Return(5));
    esimFile->BuildBasicProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildBasicProfileInfo_004, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();

    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(1)
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(2)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_))
        .Times(1)
        .WillOnce(Return(5));
    esimFile->BuildBasicProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildBasicProfileInfo_005, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(1)
        .WillOnce(Return(nullptr));
    esimFile->BuildBasicProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildAdvancedProfileInfo_000, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EuiccProfileInfo *eProfileInfo1 = nullptr;
    std::shared_ptr<Asn1Node> asn1Node1 = std::make_shared<Asn1Node>();
    esimFile->BuildAdvancedProfileInfo(eProfileInfo1, asn1Node1);

    std::shared_ptr<Asn1Node> asn1Node2 = nullptr;
    EuiccProfileInfo *eProfileInfo2 = new (std::nothrow)EuiccProfileInfo();
    esimFile->BuildAdvancedProfileInfo(eProfileInfo2, asn1Node2);
}

HWTEST_F(EsimfileBranchTest, BuildAdvancedProfileInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(4)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(4)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node));

    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger())
        .Times(2)
        .WillOnce(Return(5))
        .WillOnce(Return(5));
    
    EXPECT_CALL(*mockAsn1Node, Asn1AsBits())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _))
        .Times(1)
        .WillOnce(Return(0));
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildAdvancedProfileInfo_002, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(4)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(4)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger())
        .Times(2)
        .WillOnce(Return(5))
        .WillOnce(Return(5));
    
    EXPECT_CALL(*mockAsn1Node, Asn1AsBits())
        .Times(1)
        .WillOnce(Return(0));
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildAdvancedProfileInfo_003, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(3)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(3)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger())
        .Times(2)
        .WillOnce(Return(5))
        .WillOnce(Return(5));
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildAdvancedProfileInfo_004, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(2)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger())
        .Times(1)
        .WillOnce(Return(5));
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildAdvancedProfileInfo_005, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(1)
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(1)
        .WillOnce(Return(nullptr));
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildOperatorId_000, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EuiccProfileInfo *eProfileInfo1 = nullptr;
    std::shared_ptr<Asn1Node> asn1Node1 = std::make_shared<Asn1Node>();
    esimFile->BuildOperatorId(eProfileInfo1, asn1Node1);

    std::shared_ptr<Asn1Node> asn1Node2 = nullptr;
    EuiccProfileInfo *eProfileInfo2 = new (std::nothrow)EuiccProfileInfo();
    esimFile->BuildOperatorId(eProfileInfo2, asn1Node2);
}

HWTEST_F(EsimfileBranchTest, BuildOperatorId_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(3)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(3)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node));

    EXPECT_CALL(*mockAsn1Node, Asn1AsString(_))
        .Times(3)
        .WillOnce(Return(5))
        .WillOnce(Return(5))
        .WillOnce(Return(5));
    esimFile->BuildOperatorId(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildOperatorId_002, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(3)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(3)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockAsn1Node, Asn1AsString(_))
        .Times(2)
        .WillOnce(Return(5))
        .WillOnce(Return(5));
    esimFile->BuildOperatorId(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildOperatorId_003, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(2)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockAsn1Node, Asn1AsString(_))
        .Times(1)
        .WillOnce(Return(5));
    esimFile->BuildOperatorId(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildOperatorId_004, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(1)
        .WillOnce(Return(true));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(1)
        .WillOnce(Return(nullptr));
    esimFile->BuildOperatorId(eProfileInfo, asn1Node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, ProcessDisableProfile_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventGetProfile = esimFile->BuildCallerInfo(MSG_ESIM_DISABLE_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));

    esimFile->currentChannelId_ = 2;
    // std::string iccIdStr = "ABCDEFG";
    // esimFile->esimProfile_.iccId = Str8ToStr16(iccIdStr);
    std::shared_ptr<MockAsn1Builder> mockAsn1Builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_DISABLE_PROFILE);
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBoolean(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));

    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBoolean(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(-1));
    EXPECT_TRUE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));

    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBoolean(_, _)).WillOnce(Return(0));
    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));

    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(-1));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(nullptr));
    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));
}

HWTEST_F(EsimfileBranchTest, ProcessObtainSmdsAddress_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventGetProfile = esimFile->BuildCallerInfo(MSG_ESIM_OBTAIN_SMDS_ADDRESS);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventGetProfile));

    esimFile->currentChannelId_ = 2;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessObtainSmdsAddress(slotId, eventGetProfile));

    // EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(-1));
    // EXPECT_FALSE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventGetProfile));
}

HWTEST_F(EsimfileBranchTest, ProcessRequestRulesAuthTable_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventGetProfile = esimFile->BuildCallerInfo(MSG_ESIM_REQUEST_RULES_AUTH_TABLE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRequestRulesAuthTable(slotId, eventGetProfile));

    esimFile->currentChannelId_ = 2;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessRequestRulesAuthTable(slotId, eventGetProfile));

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(-1));
    EXPECT_TRUE(esimFile->ProcessRequestRulesAuthTable(slotId, eventGetProfile));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessRequestRulesAuthTable(slotId, eventGetProfile));
}

HWTEST_F(EsimfileBranchTest, ProcessObtainEuiccChallenge_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventGetProfile = esimFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_CHALLENGE_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessObtainEuiccChallenge(slotId, eventGetProfile));

    esimFile->currentChannelId_ = 2;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessObtainEuiccChallenge(slotId, eventGetProfile));

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(-1));
    EXPECT_TRUE(esimFile->ProcessObtainEuiccChallenge(slotId, eventGetProfile));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessObtainEuiccChallenge(slotId, eventGetProfile));
}

HWTEST_F(EsimfileBranchTest, ProcessDisableProfileDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF32038001009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    EXPECT_FALSE(esimFile->ProcessDisableProfileDone(event));

    auto eventDisableProfile = AppExecFwk::InnerEvent::Get(0);
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->ProcessDisableProfileDone(eventDisableProfile));
    
    eventDisableProfile = nullptr;
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->ProcessDisableProfileDone(eventDisableProfile));
}

HWTEST_F(EsimfileBranchTest, ProcessObtainSmdsAddressDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3C148008534D44502E434F4D8108736D64732E636F6D9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddressDone(event));

    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddressDone(event1));
    
    event1 = nullptr;
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddressDone(event1));
}

HWTEST_F(EsimfileBranchTest, GetProfileDoneParseProfileInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>();

    EXPECT_CALL(*mockAsn1Node, Asn1GetGrandson(_, _)).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).Times(2)
        .WillOnce(Return(mockAsn1Node))
        .WillOnce(Return(nullptr));
    EXPECT_TRUE(esimFile->GetProfileDoneParseProfileInfo(asn1Node));

    EXPECT_CALL(*mockAsn1Node, Asn1GetGrandson(_, _)).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->GetProfileDoneParseProfileInfo(asn1Node));

    EXPECT_CALL(*mockAsn1Node, Asn1GetGrandson(_, _)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->GetProfileDoneParseProfileInfo(asn1Node));
}

HWTEST_F(EsimfileBranchTest, Asn1AddChildAsBase64_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Builder> mockAsn1Builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_DISABLE_PROFILE);
    std::shared_ptr<Asn1Builder> asn1Builder = std::make_shared<Asn1Builder>(TAG_ESIM_DISABLE_PROFILE);
    std::vector<uint8_t> dest {1, 2, 3};
    std::shared_ptr<MockAsn1Decoder> mockAsn1Decoder = std::make_shared<MockAsn1Decoder>(dest, 0, dest.size());
    std::shared_ptr<Asn1Decoder> asn1Decoder = std::make_shared<Asn1Decoder>(dest, 0, dest.size());
    std::string base64Src = "test123";
    std::shared_ptr<Asn1Node> node = std::make_shared<Asn1Node> ();
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChild(_)).WillOnce(Return());
    esimFile->Asn1AddChildAsBase64(asn1Builder, base64Src);
    EXPECT_TRUE(esimFile != nullptr);

    asn1Builder = nullptr;
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    esimFile->Asn1AddChildAsBase64(asn1Builder, base64Src);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, ProcessIfNeedMoreResponse_001, Function | MediumTest | Level2)
{
    IccFileData fileData;
    fileData.sw1 = 0x61;
    int32_t eventId = 0;
    esimFile->currentChannelId_ = 1;
    esimFile->telRilManager_ = nullptr;
    esimFile->ProcessIfNeedMoreResponse(fileData, eventId);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildApduForSequenceOf88_001, Function | MediumTest | Level2)
{
    RequestApduBuild codec(1);
    std::shared_ptr<Asn1Node> sequenceOf88 = std::make_shared<Asn1Node>();
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _)).WillOnce(Return(-1));
    esimFile->BuildApduForSequenceOf88(codec, sequenceOf88);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildApduForSequenceOf86_001, Function | MediumTest | Level2)
{
    RequestApduBuild codec(1);
    std::shared_ptr<Asn1Node> bppNode = std::make_shared<Asn1Node>();
    std::shared_ptr<Asn1Node> sequenceOf86 = std::make_shared<Asn1Node>();
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _)).WillOnce(Return(-1));
    esimFile->BuildApduForSequenceOf86(codec, bppNode, sequenceOf86);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_)).WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->BuildApduForSequenceOf86(codec, bppNode, sequenceOf86);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, ProcessListNotifications_001, Function | MediumTest | Level2)
{
    esimFile->currentChannelId_ = 0;
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventListNotif = esimFile->BuildCallerInfo(MSG_ESIM_LIST_NOTIFICATION);
    EXPECT_FALSE(esimFile->ProcessListNotifications(slotId, EsimEvent::EVENT_ENABLE, eventListNotif));

    esimFile->currentChannelId_ = 1;
    std::shared_ptr<MockAsn1Builder> builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_LIST_NOTIFICATION);
    EXPECT_CALL(*builder, Asn1AddChildAsBits(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessListNotifications(slotId, EsimEvent::EVENT_ENABLE, eventListNotif));

    EXPECT_CALL(*builder, Asn1AddChildAsBits(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessListNotifications(slotId, EsimEvent::EVENT_ENABLE, eventListNotif));

    EXPECT_CALL(*builder, Asn1AddChildAsBits(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessListNotifications(slotId, EsimEvent::EVENT_ENABLE, eventListNotif));
}

HWTEST_F(EsimfileBranchTest, createNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<Asn1Node> node = nullptr;
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EuiccNotification euicc;
    esimFile->createNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);
    
    node = std::make_shared<Asn1Node>();
    EXPECT_CALL(*mockAsn1Node, GetNodeTag()).WillOnce(Return(TAG_ESIM_NOTIFICATION_METADATA));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->createNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag())
        .Times(2)
        .WillOnce(Return(TAG_ESIM_SEQ))
        .WillOnce(Return(TAG_ESIM_PROFILE_INSTALLATION_RESULT));
    EXPECT_CALL(*mockAsn1Node, Asn1GetGrandson(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));
    esimFile->createNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag())
        .Times(2)
        .WillOnce(Return(TAG_ESIM_SEQ))
        .WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(1)
        .WillOnce(Return(nullptr));
    esimFile->createNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag())
        .Times(2)
        .WillOnce(Return(TAG_ESIM_SEQ))
        .WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(2)
        .WillOnce(Return(node))
        .WillOnce(Return(nullptr));
    esimFile->createNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag())
        .Times(2)
        .WillOnce(Return(TAG_ESIM_SEQ))
        .WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(3)
        .WillOnce(Return(node))
        .WillOnce(Return(node))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    esimFile->createNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag())
        .Times(2)
        .WillOnce(Return(TAG_ESIM_SEQ))
        .WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(4)
        .WillOnce(Return(node))
        .WillOnce(Return(node))
        .WillOnce(Return(node))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_)).WillOnce(Return(0));
    esimFile->createNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag())
        .Times(2)
        .WillOnce(Return(TAG_ESIM_SEQ))
        .WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(4)
        .WillOnce(Return(node))
        .WillOnce(Return(node))
        .WillOnce(Return(node))
        .WillOnce(Return(node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBits()).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1NodeToHexStr(_)).WillOnce(Return(0));
    esimFile->createNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);
}
} // Telephony
} // OHOS
