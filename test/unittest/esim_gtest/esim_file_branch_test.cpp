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

#include "event_handler.h"
#include "icc_dialling_numbers_handler.h"
#include "icc_file_controller.h"
#include "mock_tel_ril_manager.h"
#include "sim_file_controller.h"
#include "telephony_log_wrapper.h"
#include "tel_ril_manager.h"
#include "telephony_tag_def.h"
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
};

    MockTelRilManager *EsimfileBranchTest::telRilManager_ = nullptr;
    std::shared_ptr<Telephony::EsimFile> EsimfileBranchTest::esimFile = nullptr;

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

HWTEST_F(EsimfileBranchTest, BuildCarrierIdentifiers_001, Function | MediumTest | Level2)
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

    CarrierIdentifier result = esimFile->BuildCarrierIdentifiers(mockAsn1Node);

    std::u16string expectedGid1 = u"";
    std::u16string expectedGid2 = u"";

    EXPECT_EQ(result.gid1_, expectedGid1);
    EXPECT_EQ(result.gid2_, expectedGid2);
}

HWTEST_F(EsimfileBranchTest, BuildCarrierIdentifiers_002, Function | MediumTest | Level2)
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

    CarrierIdentifier result = esimFile->BuildCarrierIdentifiers(mockAsn1Node);

    std::u16string expectedGid1 = u"";
    std::u16string expectedGid2 = u"";

    EXPECT_EQ(result.gid1_, expectedGid1);
    EXPECT_EQ(result.gid2_, expectedGid2);
}

HWTEST_F(EsimfileBranchTest, BuildCarrierIdentifiers_003, Function | MediumTest | Level2)
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

    CarrierIdentifier result = esimFile->BuildCarrierIdentifiers(mockAsn1Node);

    std::u16string expectedGid1 = u"";
    std::u16string expectedGid2 = u"";

    EXPECT_EQ(result.gid1_, expectedGid1);
    EXPECT_EQ(result.gid2_, expectedGid2);
}

HWTEST_F(EsimfileBranchTest, BuildCarrierIdentifiers_004, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_))
        .Times(1)
        .WillOnce(Return(nullptr));

    CarrierIdentifier result = esimFile->BuildCarrierIdentifiers(mockAsn1Node);

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
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, BuildBasicProfileInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = mockAsn1Node;
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_)).Times(11).WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).Times(12).WillOnce(Return(asn1Node)).WillOnce(Return(asn1Node))
        .WillOnce(Return(asn1Node)).WillOnce(Return(asn1Node)).WillOnce(Return(asn1Node)).WillOnce(Return(asn1Node))
        .WillOnce(Return(asn1Node)).WillOnce(Return(asn1Node)).WillOnce(Return(asn1Node)).WillOnce(Return(asn1Node))
        .WillOnce(Return(asn1Node)).WillOnce(Return(asn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_)).Times(4).WillOnce(Return(5)).WillOnce(Return(5))
        .WillOnce(Return(5)).WillOnce(Return(5));
    EXPECT_CALL(*mockAsn1Node, Asn1AsString(_)).Times(3).WillOnce(Return(5)).WillOnce(Return(5)).WillOnce(Return(5));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).Times(2).WillOnce(Return(5)).WillOnce(Return(5));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBits()).Times(1).WillOnce(Return(5));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _)).Times(1).WillOnce(Return(0));
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
    EXPECT_TRUE(esimFile != nullptr);
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
    EXPECT_TRUE(esimFile != nullptr);
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
    std::shared_ptr<MockAsn1Builder> mockAsn1Builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_DISABLE_PROFILE);
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBoolean(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));

    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBoolean(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));

    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockAsn1Builder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
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

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventGetProfile));

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

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessRequestRulesAuthTable(slotId, eventGetProfile));

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

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessObtainEuiccChallenge(slotId, eventGetProfile));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessObtainEuiccChallenge(slotId, eventGetProfile));
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

HWTEST_F(EsimfileBranchTest, CreateNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<Asn1Node> node = nullptr;
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EuiccNotification euicc;
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    node = std::make_shared<Asn1Node>();
    EXPECT_CALL(*mockAsn1Node, GetNodeTag()).WillOnce(Return(TAG_ESIM_NOTIFICATION_METADATA));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag()).Times(2).WillOnce(Return(TAG_ESIM_SEQ))
        .WillOnce(Return(TAG_ESIM_PROFILE_INSTALLATION_RESULT));
    EXPECT_CALL(*mockAsn1Node, Asn1GetGrandson(_, _)).Times(1).WillOnce(Return(nullptr));
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag()).Times(2).WillOnce(Return(TAG_ESIM_SEQ)).WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).Times(1).WillOnce(Return(nullptr));
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag()).Times(2).WillOnce(Return(TAG_ESIM_SEQ)).WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).Times(2).WillOnce(Return(node)).WillOnce(Return(nullptr));
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag()).Times(2).WillOnce(Return(TAG_ESIM_SEQ)).WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).Times(3).WillOnce(Return(node)).WillOnce(Return(node))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, CreateNotification_002, Function | MediumTest | Level2)
{
    std::shared_ptr<Asn1Node> node = nullptr;
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EuiccNotification euicc;
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag()).Times(2).WillOnce(Return(TAG_ESIM_SEQ)).WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).Times(4).WillOnce(Return(node)).WillOnce(Return(node))
        .WillOnce(Return(node)).WillOnce(Return(nullptr));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_)).WillOnce(Return(0));
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockAsn1Node, GetNodeTag()).Times(2).WillOnce(Return(TAG_ESIM_SEQ)).WillOnce(Return(TAG_ESIM_SEQ));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).Times(4).WillOnce(Return(node)).WillOnce(Return(node))
        .WillOnce(Return(node)).WillOnce(Return(node));
    EXPECT_CALL(*mockAsn1Node, Asn1AsInteger()).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBytes(_)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1AsBits()).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Node, Asn1NodeToHexStr(_)).WillOnce(Return(0));
    esimFile->CreateNotification(node, euicc);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, ProcessListNotificationsAsn1Response_001, Function | MediumTest | Level2)
{
    std::shared_ptr<Asn1Node> node = std::make_shared<Asn1Node>();
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_)).WillOnce(Return(true));
    EXPECT_FALSE(esimFile->ProcessListNotificationsAsn1Response(node));

    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->ProcessListNotificationsAsn1Response(node));

    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _)).WillOnce(Return(-1));
    EXPECT_FALSE(esimFile->ProcessListNotificationsAsn1Response(node));

    EXPECT_CALL(*mockAsn1Node, Asn1HasChild(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessListNotificationsAsn1Response(node));
}

HWTEST_F(EsimfileBranchTest, ProcessRetrieveNotificationList_001, Function | MediumTest | Level2)
{
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventRetrieveListNotif =
        esimFile->BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_LIST);
    EsimEvent events = EsimEvent::EVENT_ENABLE;

    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));

    esimFile->currentChannelId_ = 1;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));
}

HWTEST_F(EsimfileBranchTest, RetrieveNotificationParseCompTag_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = mockAsn1Node;

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->RetrieveNotificationParseCompTag(asn1Node));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(asn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _)).WillOnce(Return(1));
    EXPECT_FALSE(esimFile->RetrieveNotificationParseCompTag(asn1Node));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(asn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->RetrieveNotificationParseCompTag(asn1Node));
}

HWTEST_F(EsimfileBranchTest, ProcessRetrieveNotification_001, Function | MediumTest | Level2)
{
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventRetrieveNotification =
        esimFile->BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_DONE);

    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));

    esimFile->currentChannelId_ = 1;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));
}

HWTEST_F(EsimfileBranchTest, RetrieveNotificatioParseTagCtxComp0_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> asn1Node = mockAsn1Node;

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->RetrieveNotificatioParseTagCtxComp0(asn1Node));

    EXPECT_CALL(*mockAsn1Node, Asn1GetChild(_)).WillOnce(Return(asn1Node));
    EXPECT_CALL(*mockAsn1Node, Asn1GetChildren(_, _))
        .Times(2)
        .WillOnce(Return(1))
        .WillOnce(Return(1));
    EXPECT_FALSE(esimFile->RetrieveNotificatioParseTagCtxComp0(asn1Node));
}

HWTEST_F(EsimfileBranchTest, ProcessRemoveNotification_001, Function | MediumTest | Level2)
{
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventRemoveNotif = esimFile->BuildCallerInfo(MSG_ESIM_REMOVE_NOTIFICATION);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));

    esimFile->currentChannelId_ = 2;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));
}

HWTEST_F(EsimfileBranchTest, ProcessDeleteProfile_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventDeleteProfile = esimFile->BuildCallerInfo(MSG_ESIM_DELETE_PROFILE);
    esimFile->currentChannelId_ = 1;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));
}

HWTEST_F(EsimfileBranchTest, ProcessSetNickname_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventSetNickName = esimFile->BuildCallerInfo(MSG_ESIM_SET_NICK_NAME);
    esimFile->currentChannelId_ = 1;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessSetNickname(slotId, eventSetNickName));

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessSetNickname(slotId, eventSetNickName));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessSetNickname(slotId, eventSetNickName));
}

HWTEST_F(EsimfileBranchTest, ProcessSwitchToProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Builder> builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_ENABLE_PROFILE);
    std::shared_ptr<Asn1Node> subNode = std::make_shared<Asn1Node>();
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventSwitchToProfile = esimFile->BuildCallerInfo(MSG_ESIM_SWITCH_PROFILE);
    esimFile->currentChannelId_ = 1;

    EXPECT_CALL(*builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1Build()).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));

    EXPECT_CALL(*builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1Build()).WillOnce(Return(subNode));
    EXPECT_CALL(*builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*builder, Asn1AddChildAsBoolean(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(5));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));

    EXPECT_CALL(*builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1Build()).WillOnce(Return(subNode));
    EXPECT_CALL(*builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*builder, Asn1AddChildAsBoolean(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(5));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));

    esimFile->telRilManager_ = nullptr;
    EXPECT_CALL(*builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1Build()).WillOnce(Return(subNode));
    EXPECT_CALL(*builder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*builder, Asn1AddChildAsBoolean(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(5));
    EXPECT_FALSE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));
}

HWTEST_F(EsimfileBranchTest, ProcessObtainEuiccInfo2_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventEUICCInfo2 = esimFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO2_DONE);
    esimFile->currentChannelId_ = 1;

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo2(slotId, eventEUICCInfo2), false);

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo2(slotId, eventEUICCInfo2), true);

    esimFile->telRilManager_ = nullptr;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo2(slotId, eventEUICCInfo2), false);
}

HWTEST_F(EsimfileBranchTest, ProcessAuthenticateServer_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 1;
    std::shared_ptr<MockAsn1Builder> builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_AUTHENTICATE_SERVER);
    EXPECT_CALL(*builder, Asn1Build()).WillOnce(Return(nullptr));
    EXPECT_CALL(*builder, Asn1AddChildAsString(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChild(_))
        .Times(4)
        .WillOnce(Return())
        .WillOnce(Return())
        .WillOnce(Return())
        .WillOnce(Return());
    EXPECT_FALSE(esimFile->ProcessAuthenticateServer(slotId));
}

HWTEST_F(EsimfileBranchTest, AddCtxParams1_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Builder> mockBuilder = std::make_shared<MockAsn1Builder>(TAG_ESIM_ENABLE_PROFILE);
    std::shared_ptr<Asn1Builder> builder = nullptr;
    Es9PlusInitAuthResp authRespData;
    authRespData.imei = "012345";
    esimFile->AddCtxParams1(builder, authRespData);
    EXPECT_TRUE(esimFile != nullptr);

    builder = mockBuilder;
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsString(_, _)).WillOnce(Return(0));
    esimFile->AddCtxParams1(builder, authRespData);
    EXPECT_TRUE(esimFile != nullptr);

    authRespData.imei = "0123456789ABCDEF";
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsString(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _)).Times(4).WillOnce(Return(0)).WillOnce(Return(0))
        .WillOnce(Return(0)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1Build()).WillOnce(Return(nullptr));
    esimFile->AddCtxParams1(builder, authRespData);
    EXPECT_TRUE(esimFile != nullptr);

    std::shared_ptr<Asn1Node> devCapNode = std::make_shared<Asn1Node>();
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsString(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _)).Times(5).WillOnce(Return(0)).WillOnce(Return(0))
        .WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1Build()).Times(2).WillOnce(Return(devCapNode)).WillOnce(Return(devCapNode));
    EXPECT_CALL(*mockBuilder, Asn1AddChild(_)).Times(2).WillOnce(Return()).WillOnce(Return());
    esimFile->AddCtxParams1(builder, authRespData);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseProfileVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseProfileVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(2));
    esimFile->EuiccInfo2ParseProfileVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(4));
    esimFile->EuiccInfo2ParseProfileVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseSvn_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseSvn(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(2));
    esimFile->EuiccInfo2ParseSvn(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(4));
    esimFile->EuiccInfo2ParseSvn(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseEuiccFirmwareVer_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseEuiccFirmwareVer(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(2));
    esimFile->EuiccInfo2ParseEuiccFirmwareVer(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(4));
    esimFile->EuiccInfo2ParseEuiccFirmwareVer(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseExtCardResource_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseExtCardResource(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsString(_)).WillOnce(Return(0));
    esimFile->EuiccInfo2ParseExtCardResource(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseUiccCapability_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseUiccCapability(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsString(_)).WillOnce(Return(0));
    esimFile->EuiccInfo2ParseUiccCapability(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseTs102241Version_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseTs102241Version(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(2));
    esimFile->EuiccInfo2ParseTs102241Version(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(4));
    esimFile->EuiccInfo2ParseTs102241Version(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseGlobalPlatformVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseGlobalPlatformVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(2));
    esimFile->EuiccInfo2ParseGlobalPlatformVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(4));
    esimFile->EuiccInfo2ParseGlobalPlatformVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseRspCapability_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseRspCapability(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsString(_)).WillOnce(Return(0));
    esimFile->EuiccInfo2ParseRspCapability(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseEuiccCiPKIdListForVerification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseEuiccCiPKIdListForVerification(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1NodeToHexStr(_)).WillOnce(Return(0));
    esimFile->EuiccInfo2ParseEuiccCiPKIdListForVerification(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseEuiccCiPKIdListForSigning_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseEuiccCiPKIdListForSigning(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1NodeToHexStr(_)).WillOnce(Return(0));
    esimFile->EuiccInfo2ParseEuiccCiPKIdListForSigning(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParseEuiccCategory_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParseEuiccCategory(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsInteger()).WillOnce(Return(0));
    esimFile->EuiccInfo2ParseEuiccCategory(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, EuiccInfo2ParsePpVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EuiccInfo2 euiccInfo2;

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    esimFile->EuiccInfo2ParsePpVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(2));
    esimFile->EuiccInfo2ParsePpVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);

    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsBytes(_)).WillOnce(Return(4));
    esimFile->EuiccInfo2ParsePpVersion(euiccInfo2, node);
    EXPECT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimfileBranchTest, RealProcessAuthenticateServerDone_001, Function | MediumTest | Level2)
{
    esimFile->recvCombineStr_ = "BF3706A10480000200009000";
    std::vector<uint8_t> dest {1, 2, 3};
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    std::shared_ptr<MockAsn1Decoder> mockAsn1Decoder = std::make_shared<MockAsn1Decoder>(dest, 0, dest.size());
    
    EXPECT_CALL(*mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(false));
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());

    EXPECT_CALL(*mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1HasChild(_)).WillOnce(Return(true));
    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());

    EXPECT_CALL(*mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1HasChild(_)).WillOnce(Return(false));
    EXPECT_TRUE(esimFile->RealProcessAuthenticateServerDone());
}

HWTEST_F(EsimfileBranchTest, RealProcessAuthenticateServerDone_002, Function | MediumTest | Level2)
{
    esimFile->recvCombineStr_ = "BF3706A10480000200009000";
    std::vector<uint8_t> dest {1, 2, 3};
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    std::shared_ptr<MockAsn1Decoder> mockAsn1Decoder = std::make_shared<MockAsn1Decoder>(dest, 0, dest.size());

    EXPECT_CALL(*mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1HasChild(_)).Times(3).WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockNode, Asn1GetChild(_)).Times(3).WillOnce(Return(node)).WillOnce(Return(nullptr))
        .WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());

    EXPECT_CALL(*mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1HasChild(_)).Times(3).WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockNode, Asn1GetChild(_)).Times(3).WillOnce(Return(node)).WillOnce(Return(node))
        .WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsString(_)).WillOnce(Return(0));
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());

    EXPECT_CALL(*mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1HasChild(_)).Times(3).WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockNode, Asn1GetChild(_)).Times(3).WillOnce(Return(node)).WillOnce(Return(node))
        .WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1AsString(_)).WillOnce(Return(1));
    EXPECT_CALL(*mockNode, Asn1AsInteger()).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->RealProcessAuthenticateServerDone());

    EXPECT_CALL(*mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1HasChild(_)).Times(2).WillOnce(Return(true)).WillOnce(Return(false));
    EXPECT_CALL(*mockNode, Asn1GetChild(_)).Times(1).WillOnce(Return(node));
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());

    EXPECT_CALL(*mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(*mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1HasChild(_)).Times(3).WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(false));
    EXPECT_CALL(*mockNode, Asn1GetChild(_)).Times(1).WillOnce(Return(node));
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());
}

HWTEST_F(EsimfileBranchTest, GetKeyValueSequenceNode_001, Function | MediumTest | Level2)
{
    std::shared_ptr<MockAsn1Builder> mockAsn1Builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_SEQUENCE);
    std::shared_ptr<Asn1Builder> builder = mockAsn1Builder;
    uint32_t kTag = 0;
    const std::string key = "test key";
    uint32_t vTag = TAG_ESIM_OCTET_STRING_TYPE;
    std::string value = "test value";

    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsString(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(nullptr));
    std::shared_ptr<Asn1Node> node = esimFile->GetKeyValueSequenceNode(kTag, key, vTag, value);
    EXPECT_TRUE(node == nullptr);

    vTag = 0;
    EXPECT_CALL(*mockAsn1Builder, Asn1AddChildAsString(_, _))
        .Times(2)
        .WillOnce(Return(0))
        .WillOnce(Return(0));
    EXPECT_CALL(*mockAsn1Builder, Asn1Build()).WillOnce(Return(nullptr));
    node = esimFile->GetKeyValueSequenceNode(kTag, key, vTag, value);
    EXPECT_TRUE(node == nullptr);
}

HWTEST_F(EsimfileBranchTest, ProcessGetContractInfo_001, Function | MediumTest | Level2)
{
    esimFile->currentChannelId_ = 0;
    AppExecFwk::InnerEvent::Pointer eventGetContractInfo = esimFile->BuildCallerInfo(MSG_ESIM_CANCEL_SESSION);
    std::shared_ptr<MockAsn1Builder> builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_AUTHENTICATE_SERVER);

    EXPECT_FALSE(esimFile->ProcessGetContractInfo(eventGetContractInfo));

    esimFile->currentChannelId_ = 1;
    EXPECT_CALL(*builder, Asn1Build()).Times(5).WillOnce(Return(nullptr)).WillOnce(Return(nullptr))
        .WillOnce(Return(nullptr)).WillOnce(Return(nullptr)).WillOnce(Return(nullptr));
    EXPECT_CALL(*builder, Asn1AddChildAsString(_, _)).Times(7).WillOnce(Return(0)).WillOnce(Return(0))
        .WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChildAsBytes(_, _, _)).Times(2).WillOnce(Return(0)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChild(_)).Times(4).WillOnce(Return()).WillOnce(Return())
        .WillOnce(Return()).WillOnce(Return());
    EXPECT_FALSE(esimFile->ProcessGetContractInfo(eventGetContractInfo));

    std::shared_ptr<Asn1Node> node = std::make_shared<Asn1Node>();
    EXPECT_CALL(*builder, Asn1Build()).Times(5).WillOnce(Return(nullptr)).WillOnce(Return(nullptr))
        .WillOnce(Return(nullptr)).WillOnce(Return(nullptr)).WillOnce(Return(node));
    EXPECT_CALL(*builder, Asn1AddChildAsString(_, _)).Times(7).WillOnce(Return(0)).WillOnce(Return(0))
        .WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChildAsBytes(_, _, _)).Times(3).WillOnce(Return(0)).WillOnce(Return(0))
        .WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChild(_)).Times(5).WillOnce(Return()).WillOnce(Return()).WillOnce(Return())
        .WillOnce(Return()).WillOnce(Return());
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(5));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessGetContractInfo(eventGetContractInfo));

    EXPECT_CALL(*builder, Asn1Build()).Times(5).WillOnce(Return(nullptr)).WillOnce(Return(nullptr))
        .WillOnce(Return(nullptr)).WillOnce(Return(nullptr)).WillOnce(Return(node));
    EXPECT_CALL(*builder, Asn1AddChildAsString(_, _)).WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0))
        .WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChildAsBytes(_, _, _)).Times(3).WillOnce(Return(0)).WillOnce(Return(0))
        .WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChild(_)).Times(5).WillOnce(Return()).WillOnce(Return())
        .WillOnce(Return()).WillOnce(Return()).WillOnce(Return());
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(5));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessGetContractInfo(eventGetContractInfo));

    EXPECT_CALL(*builder, Asn1Build()).Times(5).WillOnce(Return(nullptr)).WillOnce(Return(nullptr))
        .WillOnce(Return(nullptr)).WillOnce(Return(nullptr)).WillOnce(Return(node));
    EXPECT_CALL(*builder, Asn1AddChildAsString(_, _)).WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0))
        .WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChildAsBytes(_, _, _)).Times(3).WillOnce(Return(0))
        .WillOnce(Return(0)).WillOnce(Return(0));
    EXPECT_CALL(*builder, Asn1AddChild(_)).Times(5).WillOnce(Return()).WillOnce(Return())
        .WillOnce(Return()).WillOnce(Return()).WillOnce(Return());
    EXPECT_CALL(*builder, Asn1BuilderToHexStr(_)).WillOnce(Return(5));
    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessGetContractInfo(eventGetContractInfo));
}

HWTEST_F(EsimfileBranchTest, ProcessGetContractInfoDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.sw1 = 0x90;
    rcvMsg->fileData.sw2 = 0x00;
    rcvMsg->fileData.resultData = "BF70820686A08206823082067ea0820635048206313c2a12361636c856472212e939eb2fe56715cacf8"
        "6889776fd07f54915fa28207a6c8a8dfd9b01ea0e0d12148ce5372b71bf88b7fc3a437c7008a4ed435420e245e0520ec9f958eb1db871"
        "504eb899da4837501d2e1642434b525d238ca514a320ff8a7c1a157e34287af623aa4587f1e762ce2ca62e90ddb9a15d369687a5d7aae"
        "b3b4ea8b538168d30dfbbe30ebcd3f33a8dcd024f0833bd0592c4534824fcfde3c3541d8a0c459cfcaaa00b071a1e5e40ece34b8c2535"
        "574cbd172d688193054dc60f6ffb39d88c13dd941b763d926080e81ac2d9cd2a60de1498c40a3de28c8e4c1b80679d03d1a0f1cc5a7d8"
        "efad7e67f05ab14e4438d63ec212b3cb277a1671a201fcaebeaf73da7b9e1cdf96110eab869ea290011f675b479903da75d692449b472"
        "148eeb31180d4e3a9dfb4dacd750c14d7f32460895e1a17abf3ee4988a02174a65066038c43b07875dc675c074bf2cf334e68fb562fe6"
        "c3c7f5d7ed619191318b55b435c5aae3f561a8c0686aedcbfb169376926b93c3cecc4c023576c25657c84c0e9f4b48e70a19034324a16"
        "309ecc4e0701e858983ed1401dcc5eb786fa29ba73d623df1752e33448e89a23576a631e69ee1d7cab36bb3abe4ed571ba127570b0906"
        "b15119dbcb7ace372cc1216ae10ef01d9fcd28033df8e3c854d3821c224b2fec0901d8c63f6c90e2650167949ee7c5037a1629e99d779"
        "b1c920b8df54dbe3f44e9df207d527ca582e7968acf185b075ba738fbf866a70d8d9d54077a3dcc058ce8b13e18aa06571133729cadcc"
        "7279ac565e58f5be35fabcdba361ab71699a459132939d5ae948cc10ad5d2bcd22a905e97fb94204433a4ff23789e0e3af86759f34aa0"
        "b413406b3dc1d09da88aacb2b33a1c936c44a7855e83b821cc4e1128603eb0a144c981d4b14d854efc2218e70e3816fcd2cd44a6abd97"
        "4fbfba44f29d2df9fe8ac036deb9decad24ebe48f9a58d1afec81480f390e9a6f0110cb6659c174f6ba3a8c9ed73d699d0ab1272959e7"
        "212b80eb00ac7f99047d4a05210134bf7759fdc4b64ca9b142224af2c87134d5dc5818d3631742704c7c2b6c303b675a5d11ebc25ab44"
        "33091b5be993d444a757ae6a9cc5714199a94a4015d22d01f62e1985b7618545f1f4ebcae6c759b210161115fde604d3ff8cef533efa9"
        "580f5c53ceda9ed607d38bc883f470c12e39b28b31daa4dc3bc534617eb3ec86d4ae25d5b9d4b79e012c69c91e53d4a6e07bb18297c7c"
        "e19ce5b7dd2a5763bf7bffb8a660690c11927e24a544026b58865810c4ca81c861f8ca6af8dccc265a30f516990f366b772f1a51c8d1e"
        "2237b49e3fd710f04a2fd7dd082d2dc87cdecb609443ed470d62f4a9bc3e046f3f2af0f5e0b79a37011fed8112d902b4f3f65b552841c"
        "7dbebe15e5c3ea3896f3ee56d9c98649e86222db82a65671b8fc3a3f518f3c71b525594e6fffb409219fde031253fc85e24ff50198c72"
        "37fb5e7d107511dd79fa3c61bbb5a8498038cfd4b2b7683549855801cad3c743ee215a07b2c136015820682cfaee75538a292958232cd"
        "5dce3a06d0f322ef931e649b6cadfa3fab68507a223c94ad98ed145a559378ab2044178f3fa8547aa82b43c8044e656159da6198dd309"
        "e40640c21d0f567a0000eca1bb85cf5901ec532fb911abeab9b47b194bb5dae188b2ea16a5f820184754ceb5cc572dc80c3fe2efefdbe"
        "0b418ea17cf912298eb8225bdd59494881853ac2b29a32b61c51a67dad51f390ddc4a6fe8cb673cca330cbf03c9a459ca106395163668"
        "25a3c37ae41ea4dfbe16260c23d0e10e2f9af7921f4dedce15ae758c62c35ca69488105c85f37cb9508e16f5a21006e65d405a3a81eba"
        "4bf1044a25bfa5d21d7a58dd862f80897982c4a3f007be09bc05805a1ad3cc16f947fbc7e74c365a1a9ca59fc1e47e06f4e5ae54d3366"
        "e72bc8fec502e991ec25c6a76c9114e3f6d92680515d94cee27537187321205d4e6c4eb82ad4a454d8c5b6daacc975659c04460e3d181"
        "6e30792835ac860fe1bb28a37e5bc2f77666a6c248005da8f3cf3fb30ba7d5440799b431d1cc28a27c73da93a7f7b6798af78c73a950e"
        "2535339cafade736595a3515fcef09c7e15d9a01a60b8104cc82040038da38eb8a9bced35306ad6bc4f1510f8622ca68ccf041f8b4178"
        "61ed500a65caa6fec77ef76d3df30fbd992d286a7de88dec6ac0c731bf216a7dcb1792244e0aa1430441040028a868403bfb6e3c6e3bc"
        "77147c4da01f12626cc7bc1553f30f92c9e835387df2f104fc41e01b8f942a4ef6afda10440be1ac908a77187552f4c3de04f15599000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessGetContractInfoDone(event));

    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessGetContractInfoDone(event1));
}

HWTEST_F(EsimfileBranchTest, BuildCallerInfo_001, Function | MediumTest | Level2)
{
    int32_t channelId = 0;
    ApduData apduData;
    ApduSimIORequestInfo requestInfo;
    ApduCommand *apduCommand = new (std::nothrow)ApduCommand(channelId, apduData);
    esimFile->nextSerialId_ = INT32_MAX - 1;
    esimFile->CopyApdCmdToReqInfo(requestInfo, apduCommand);
    EXPECT_FALSE(esimFile == nullptr);

    std::shared_ptr<MockAsn1Builder> mockAsn1Builder = std::make_shared<MockAsn1Builder>(TAG_ESIM_DISABLE_PROFILE);
    std::shared_ptr<Asn1Builder> builder = nullptr;
    esimFile->CommBuildOneApduReqInfo(requestInfo, builder);
    EXPECT_FALSE(esimFile == nullptr);

    AppExecFwk::InnerEvent::Pointer eventEUICCInfo1 =
        esimFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO_1_DONE);
    esimFile->currentChannelId_ = 2;
    int32_t slotId = 0;
    esimFile->telRilManager_ = nullptr;
    esimFile->ProcessEsimCloseSpareChannel();
    EXPECT_FALSE(esimFile->ProcessObtainEuiccInfo1(slotId, eventEUICCInfo1));
}

HWTEST_F(EsimfileBranchTest, ProcessObtainEuiccInfo1Done_001, Function | MediumTest | Level2)
{
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF20618203020202A92C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30414C0BC70BA369"
        "29D43B467FF57570530E57AB8FCD8AA2C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30414C0BC70BA36929D43B467FF575"
        "70530E57AB8FCD8";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);

    std::vector<uint8_t> src {1, 2, 3, 4, 5};
    uint32_t offset = 0;
    uint32_t decodeLen = 5;
    MockAsn1Decoder mockAsn1Decoder(src, offset, decodeLen);
    std::shared_ptr<MockAsn1Node> mockNode = std::make_shared<MockAsn1Node>();
    std::shared_ptr<Asn1Node> node = mockNode;
    EXPECT_CALL(mockAsn1Decoder, Asn1HasNextNode()).WillOnce(Return(true));
    EXPECT_CALL(mockAsn1Decoder, Asn1NextNode()).WillOnce(Return(node));
    EXPECT_CALL(*mockNode, Asn1GetChild(_)).WillOnce(Return(nullptr));
    EXPECT_FALSE(esimFile->ProcessObtainEuiccInfo1Done(event));
}

HWTEST_F(EsimfileBranchTest, ProcessObtainDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventSmdpAddress =
        esimFile->BuildCallerInfo(MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE);
    esimFile->currentChannelId_ = 2;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));

    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));
}

HWTEST_F(EsimfileBranchTest, ProcessGetProfile_001, Function | MediumTest | Level2)
{
    int32_t slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventGetProfile = esimFile->BuildCallerInfo(MSG_ESIM_GET_PROFILE);
    esimFile->currentChannelId_ = 2;

    std::shared_ptr<MockAsn1Builder> mockBuilder = std::make_shared<MockAsn1Builder>(TAG_ESIM_GET_PROFILES);
    std::shared_ptr<Asn1Builder> builder = mockBuilder;
    std::shared_ptr<MockAsn1Node> mockAsn1Node = std::make_shared<MockAsn1Node>();

    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _))
        .Times(2)
        .WillOnce(Return(0))
        .WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockBuilder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessGetProfile(slotId, eventGetProfile));

    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _))
        .Times(2)
        .WillOnce(Return(0))
        .WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockBuilder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessGetProfile(slotId, eventGetProfile));

    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _))
        .Times(2)
        .WillOnce(Return(0))
        .WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1Build()).WillOnce(Return(mockAsn1Node));
    EXPECT_CALL(*mockBuilder, Asn1AddChild(_)).WillOnce(Return());
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
}

HWTEST_F(EsimfileBranchTest, ProcessCancelSession_001, Function | MediumTest | Level2)
{
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventCancelSession = esimFile->BuildCallerInfo(MSG_ESIM_CANCEL_SESSION);
    esimFile->currentChannelId_ = 2;

    std::shared_ptr<MockAsn1Builder> mockBuilder = std::make_shared<MockAsn1Builder>(TAG_ESIM_GET_PROFILES);
    std::shared_ptr<Asn1Builder> builder = mockBuilder;
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsInteger(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessCancelSession(slotId, eventCancelSession));

    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsInteger(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(0));
    EXPECT_TRUE(esimFile->ProcessCancelSession(slotId, eventCancelSession));

    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsInteger(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessCancelSession(slotId, eventCancelSession));
}

HWTEST_F(EsimfileBranchTest, ProcessEstablishDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer event =
        esimFile->BuildCallerInfo(MSG_ESIM_ESTABLISH_DEFAULT_SMDP_ADDRESS_DONE);
    esimFile->currentChannelId_ = 2;

    std::shared_ptr<MockAsn1Builder> mockBuilder = std::make_shared<MockAsn1Builder>(TAG_ESIM_GET_PROFILES);
    std::shared_ptr<Asn1Builder> builder = mockBuilder;
    EXPECT_CALL(*mockBuilder, Asn1AddChildAsString(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessEstablishDefaultSmdpAddress(slotId, event));
}

HWTEST_F(EsimfileBranchTest, ProcessResetMemory_001, Function | MediumTest | Level2)
{
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventResetMemory = esimFile->BuildCallerInfo(MSG_ESIM_RESET_MEMORY);
    esimFile->currentChannelId_ = 2;

    std::shared_ptr<MockAsn1Builder> mockBuilder = std::make_shared<MockAsn1Builder>(TAG_ESIM_GET_PROFILES);

    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_EQ(esimFile->ProcessResetMemory(slotId, eventResetMemory), false);

    EXPECT_CALL(*mockBuilder, Asn1AddChildAsBytes(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(*mockBuilder, Asn1BuilderToHexStr(_)).WillOnce(Return(0));
    esimFile->telRilManager_ = nullptr;
    EXPECT_EQ(esimFile->ProcessResetMemory(slotId, eventResetMemory), false);
}

HWTEST_F(EsimfileBranchTest, ProcessSendApduData_001, Function | MediumTest | Level2)
{
    int slotId = 0;
    AppExecFwk::InnerEvent::Pointer eventSendApduData = esimFile->BuildCallerInfo(MSG_ESIM_SEND_APUD_DATA);
    esimFile->currentChannelId_ = 1;
    EXPECT_CALL(*telRilManager_, SimTransmitApduLogicalChannel(_, _, _)).WillOnce(Return(TELEPHONY_ERR_FAIL));
    EXPECT_FALSE(esimFile->ProcessSendApduData(slotId, eventSendApduData));

    esimFile->telRilManager_ = nullptr;
    EXPECT_FALSE(esimFile->ProcessSendApduData(slotId, eventSendApduData));
}
} // Telephony
} // OHOS
