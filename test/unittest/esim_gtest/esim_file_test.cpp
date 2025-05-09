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
#include <gtest/gtest.h>
#include <thread>

#include "asn1_node.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "esim_file.h"
#include "icc_file.h"
#include "sim_file_manager.h"
#include "sim_constant.h"
#include "sim_file_manager.h"
#include "tel_ril_manager.h"
#include "telephony_tag_def.h"
#include "gtest/gtest.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace NFC {
namespace TEST {
using namespace testing::ext;
using namespace OHOS::Telephony;
class EsimFileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
public:
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
};

static const std::string BPP_COMBINE_HEX_STR = "BF3781ADBF27678008D14FE1DE62C340D7BF2F3480024C66810207800C1E31302E313"
    "02E31322E3136342F64702D706C75732D696E746572666163655A0A98680010203040506080060388370AA21FA01D4F10A000000559101"
    "0FFFFFFFF890000120004093007A00530038001005F3740B354AE39D08ACD7EDD7D2D01C73378621F623B832DFA3243489C5B42C90F220"
    "14E6C928130D78EE561982EF412AC3D94C04B56F37657DA84FD7BB24DD5634E89";

void EsimFileTest::SetUpTestCase() {}

void EsimFileTest::TearDownTestCase() {}

void EsimFileTest::SetUp() {}

void EsimFileTest::TearDown() {}

/**
 * @tc.name: SyncCloseChannel001
 * @tc.desc: Test EsimFileTest SyncCloseChannel.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SyncCloseChannel001, TestSize.Level1)
{
    esimFile->currentChannelId_ = 1;
    esimFile->SyncCloseChannel();
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ObtainEid001
 * @tc.desc: Test EsimFileTest ObtainEid.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ObtainEid001, TestSize.Level1)
{
    esimFile->eid_ = "test";
    ASSERT_TRUE(esimFile->ObtainEid() == "test");
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: CopyApdCmdToReqInfo001
 * @tc.desc: Test EsimFileTest CopyApdCmdToReqInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, CopyApdCmdToReqInfo001, TestSize.Level1)
{
    ApduSimIORequestInfo requestInfo;
    ApduCommand *apduCommand = nullptr;
    esimFile->CopyApdCmdToReqInfo(requestInfo, apduCommand);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: CopyApdCmdToReqInfo002
 * @tc.desc: Test EsimFileTest CopyApdCmdToReqInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, CopyApdCmdToReqInfo002, TestSize.Level1)
{
    int32_t channelId = 0;
    ApduData apduData;
    ApduSimIORequestInfo requestInfo;
    ApduCommand *apduCommand = new (std::nothrow)ApduCommand(channelId, apduData);
    esimFile->nextSerialId_ = 2147483647;
    esimFile->CopyApdCmdToReqInfo(requestInfo, apduCommand);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ObtainChannelSuccessAlllowSameAidReuse001
 * @tc.desc: Test EsimFileTest ObtainChannelSuccessAlllowSameAidReuse.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ObtainChannelSuccessAlllowSameAidReuse001, TestSize.Level1)
{
    std::u16string aid = u"";
    esimFile->aidStr_ = u"test";
    ResultInnerCode ret = esimFile->ObtainChannelSuccessAlllowSameAidReuse(aid);
    ASSERT_TRUE(ret == ResultInnerCode::RESULT_EUICC_CARD_CHANNEL_OTHER_AID);
}

/**
 * @tc.name: ObtainChannelSuccessAlllowSameAidReuse002
 * @tc.desc: Test EsimFileTest ObtainChannelSuccessAlllowSameAidReuse.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ObtainChannelSuccessAlllowSameAidReuse002, TestSize.Level1)
{
    esimFile->currentChannelId_ = 0;
    std::u16string aid = u"test";
    esimFile->aidStr_ = u"test";
    esimFile->ObtainChannelSuccessAlllowSameAidReuse(aid);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: GetEuiccProfileInfoList001
 * @tc.desc: Test EsimFileTest GetEuiccProfileInfoList.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, GetEuiccProfileInfoList001, TestSize.Level1)
{
    esimFile->currentChannelId_ = 0;
    esimFile->GetEuiccProfileInfoList();
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: GetEuiccInfo001
 * @tc.desc: Test EsimFileTest GetEuiccInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, GetEuiccInfo001, TestSize.Level1)
{
    esimFile->currentChannelId_ = 0;
    esimFile->GetEuiccInfo();
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessEsimOpenChannelDone001
 * @tc.desc: Test EsimFileTest ProcessEsimOpenChannelDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessEsimOpenChannelDone001, TestSize.Level1)
{
    OpenLogicalChannelResponse response;
    response.channelId = 0;
    auto responseInfo = std::make_shared<OpenLogicalChannelResponse>();
    auto event = AppExecFwk::InnerEvent::Get(0, responseInfo);
    esimFile->ProcessEsimOpenChannelDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessEsimCloseSpareChannel001
 * @tc.desc: Test EsimFileTest ProcessEsimCloseSpareChannel.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessEsimCloseSpareChannel001, TestSize.Level1)
{
    esimFile->ProcessEsimCloseSpareChannel();
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: MakeVersionString001
 * @tc.desc: Test EsimFileTest MakeVersionString.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, MakeVersionString001, TestSize.Level1)
{
    std::vector<uint8_t> versionRaw(1, 1);
    esimFile->MakeVersionString(versionRaw);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessObtainEidDone001
 * @tc.desc: Test EsimFileTest ProcessObtainEidDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessObtainEidDone001, TestSize.Level1)
{
    std::vector<uint8_t> src;
    auto rootInfo = std::make_shared<Asn1Node>(0, src, 0, 0);
    auto event = AppExecFwk::InnerEvent::Get(0, rootInfo);
    esimFile->ProcessObtainEidDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessObtainEuiccInfo1Done001
 * @tc.desc: Test EsimFileTest ProcessObtainEuiccInfo1Done.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessObtainEuiccInfo1Done001, TestSize.Level1)
{
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessObtainEuiccInfo1Done(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SplitMccAndMnc001
 * @tc.desc: Test EsimFileTest SplitMccAndMnc.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SplitMccAndMnc001, TestSize.Level1)
{
    std::string mccMnc = "FFFF";
    std::string mcc = "";
    std::string mnc = "";
    esimFile->SplitMccAndMnc(mccMnc, mcc, mnc);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SplitMccAndMnc002
 * @tc.desc: Test EsimFileTest SplitMccAndMnc.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SplitMccAndMnc002, TestSize.Level1)
{
    std::string mccMnc = "EEEE";
    std::string mcc = "";
    std::string mnc = "";
    esimFile->SplitMccAndMnc(mccMnc, mcc, mnc);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildBasicProfileInfo001
 * @tc.desc: Test EsimFileTest BuildBasicProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildBasicProfileInfo001, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = nullptr;
    std::shared_ptr<Asn1Node> profileNode = nullptr;
    esimFile->BuildBasicProfileInfo(eProfileInfo, profileNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildBasicProfileInfo002
 * @tc.desc: Test EsimFileTest BuildBasicProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildBasicProfileInfo002, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    std::shared_ptr<Asn1Node> profileNode = nullptr;
    esimFile->BuildBasicProfileInfo(eProfileInfo, profileNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildBasicProfileInfo003
 * @tc.desc: Test EsimFileTest BuildBasicProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildBasicProfileInfo003, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = nullptr;
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> profileNode = std::make_shared<Asn1Node>(0, src, 0, 0);
    esimFile->BuildBasicProfileInfo(eProfileInfo, profileNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildBasicProfileInfo004
 * @tc.desc: Test EsimFileTest BuildBasicProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildBasicProfileInfo004, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> profileNode = std::make_shared<Asn1Node>(0, src, 0, 0);
    esimFile->BuildBasicProfileInfo(eProfileInfo, profileNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildAdvancedProfileInfo001
 * @tc.desc: Test EsimFileTest BuildAdvancedProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildAdvancedProfileInfo001, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = nullptr;
    std::shared_ptr<Asn1Node> profileNode = nullptr;
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, profileNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildAdvancedProfileInfo002
 * @tc.desc: Test EsimFileTest BuildAdvancedProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildAdvancedProfileInfo002, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    std::shared_ptr<Asn1Node> profileNode = nullptr;
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, profileNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildAdvancedProfileInfo003
 * @tc.desc: Test EsimFileTest BuildAdvancedProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildAdvancedProfileInfo003, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = nullptr;
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> profileNode = std::make_shared<Asn1Node>(0, src, 0, 0);
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, profileNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildAdvancedProfileInfo004
 * @tc.desc: Test EsimFileTest BuildAdvancedProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildAdvancedProfileInfo004, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> profileNode = std::make_shared<Asn1Node>(0, src, 0, 0);
    esimFile->BuildAdvancedProfileInfo(eProfileInfo, profileNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildOperatorId001
 * @tc.desc: Test EsimFileTest BuildOperatorId.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildOperatorId001, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = nullptr;
    std::shared_ptr<Asn1Node> operatorIdNode = nullptr;
    esimFile->BuildOperatorId(eProfileInfo, operatorIdNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildOperatorId002
 * @tc.desc: Test EsimFileTest BuildOperatorId.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildOperatorId002, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    std::shared_ptr<Asn1Node> operatorIdNode = nullptr;
    esimFile->BuildOperatorId(eProfileInfo, operatorIdNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildOperatorId003
 * @tc.desc: Test EsimFileTest BuildOperatorId.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildOperatorId003, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = nullptr;
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> operatorIdNode = std::make_shared<Asn1Node>(0, src, 0, 0);
    esimFile->BuildOperatorId(eProfileInfo, operatorIdNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: BuildOperatorId004
 * @tc.desc: Test EsimFileTest BuildOperatorId.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, BuildOperatorId004, TestSize.Level1)
{
    EuiccProfileInfo *eProfileInfo = new (std::nothrow)EuiccProfileInfo();
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> operatorIdNode = std::make_shared<Asn1Node>(0, src, 0, 0);
    esimFile->BuildOperatorId(eProfileInfo, operatorIdNode);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: DisableProfile001
 * @tc.desc: Test EsimFileTest DisableProfile.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, DisableProfile001, TestSize.Level1)
{
    int32_t portIndex = 0;
    std::u16string iccId = u"test";
    esimFile->currentChannelId_ = 0;
    esimFile->DisableProfile(portIndex, iccId);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ObtainSmdsAddress001
 * @tc.desc: Test EsimFileTest ObtainSmdsAddress.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ObtainSmdsAddress001, TestSize.Level1)
{
    int32_t portIndex = 0;
    esimFile->currentChannelId_ = 0;
    esimFile->ObtainSmdsAddress(portIndex);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ObtainRulesAuthTable001
 * @tc.desc: Test EsimFileTest ObtainRulesAuthTable.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ObtainRulesAuthTable001, TestSize.Level1)
{
    int32_t portIndex = 0;
    esimFile->currentChannelId_ = 0;
    esimFile->ObtainRulesAuthTable(portIndex);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ObtainEuiccChallenge001
 * @tc.desc: Test EsimFileTest ObtainEuiccChallenge.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ObtainEuiccChallenge001, TestSize.Level1)
{
    int32_t portIndex = 0;
    esimFile->currentChannelId_ = 0;
    esimFile->ObtainEuiccChallenge(portIndex);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessGetProfile001
 * @tc.desc: Test EsimFileTest ProcessGetProfile.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessGetProfile001, TestSize.Level1)
{
    int32_t slotId = 0;
    auto responseEvent = AppExecFwk::InnerEvent::Get(0);
    esimFile->currentChannelId_ = 1;
    esimFile->ProcessGetProfile(slotId, responseEvent);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: GetProfileDoneParseProfileInfo001
 * @tc.desc: Test EsimFileTest GetProfileDoneParseProfileInfo.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, GetProfileDoneParseProfileInfo001, TestSize.Level1)
{
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> root = std::make_shared<Asn1Node>(0, src, 0, 0);
    esimFile->GetProfileDoneParseProfileInfo(root);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessGetProfileDone001
 * @tc.desc: Test EsimFileTest ProcessGetProfileDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessGetProfileDone001, TestSize.Level1)
{
    std::vector<uint8_t> src;
    auto rootInfo = std::make_shared<Asn1Node>(0, src, 0, 0);
    auto event = AppExecFwk::InnerEvent::Get(0, rootInfo);
    esimFile->ProcessGetProfileDone(event);
    event = nullptr;
    esimFile->ProcessGetProfileDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SetDefaultSmdpAddress001
 * @tc.desc: Test EsimFileTest SetDefaultSmdpAddress.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SetDefaultSmdpAddress001, TestSize.Level1)
{
    esimFile->currentChannelId_ = 0;
    std::u16string defaultSmdpAddress = u"";
    esimFile->SetDefaultSmdpAddress(defaultSmdpAddress);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessEstablishDefaultSmdpAddress001
 * @tc.desc: Test EsimFileTest ProcessEstablishDefaultSmdpAddress.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessEstablishDefaultSmdpAddress001, TestSize.Level1)
{
    esimFile->currentChannelId_ = 0;
    int32_t slotId = 0;
    auto responseEvent = AppExecFwk::InnerEvent::Get(0);
    esimFile->ProcessEstablishDefaultSmdpAddress(slotId, responseEvent);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessEstablishDefaultSmdpAddress002
 * @tc.desc: Test EsimFileTest ProcessEstablishDefaultSmdpAddress.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessEstablishDefaultSmdpAddress002, TestSize.Level1)
{
    esimFile->currentChannelId_ = 1;
    int32_t slotId = 0;
    std::vector<uint8_t> src;
    auto rootInfo = std::make_shared<Asn1Node>(0, src, 0, 0);
    auto responseEvent = AppExecFwk::InnerEvent::Get(0, rootInfo);
    esimFile->ProcessEstablishDefaultSmdpAddress(slotId, responseEvent);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessEstablishDefaultSmdpAddressDone001
 * @tc.desc: Test EsimFileTest ProcessEstablishDefaultSmdpAddressDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessEstablishDefaultSmdpAddressDone001, TestSize.Level1)
{
    auto event = AppExecFwk::InnerEvent::Get(0);
    esimFile->ProcessEstablishDefaultSmdpAddressDone(event);
    event = nullptr;
    esimFile->ProcessEstablishDefaultSmdpAddressDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: IsSupported001
 * @tc.desc: Test EsimFileTest IsSupported.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, IsSupported001, TestSize.Level1)
{
    esimFile->isSupported_ = false;
    esimFile->IsSupported();
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SendApduData001
 * @tc.desc: Test EsimFileTest SendApduData.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SendApduData001, TestSize.Level1)
{
    std::u16string aid = u"";
    EsimApduData apduData;
    esimFile->SendApduData(aid, apduData);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SendApduData002
 * @tc.desc: Test EsimFileTest SendApduData.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SendApduData002, TestSize.Level1)
{
    std::u16string aid = u"test";
    EsimApduData apduData;
    apduData.closeChannelFlag_ = true;
    esimFile->aidStr_ = u"test";
    esimFile->SendApduData(aid, apduData);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SendApduData003
 * @tc.desc: Test EsimFileTest SendApduData.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SendApduData003, TestSize.Level1)
{
    std::u16string aid = u"test";
    EsimApduData apduData;
    apduData.closeChannelFlag_ = true;
    esimFile->aidStr_ = u"demo";
    esimFile->SendApduData(aid, apduData);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SendApduData004
 * @tc.desc: Test EsimFileTest SendApduData.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SendApduData004, TestSize.Level1)
{
    std::u16string aid = u"test";
    EsimApduData apduData;
    apduData.closeChannelFlag_ = false;
    esimFile->currentChannelId_ = 0;
    esimFile->aidStr_ = u"demo";
    esimFile->SendApduData(aid, apduData);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SendApduData005
 * @tc.desc: Test EsimFileTest SendApduData.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SendApduData005, TestSize.Level1)
{
    std::u16string aid = u"test";
    EsimApduData apduData;
    apduData.closeChannelFlag_ = false;
    esimFile->currentChannelId_ = 0;
    esimFile->aidStr_ = u"";
    esimFile->SendApduData(aid, apduData);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: SendApduData006
 * @tc.desc: Test EsimFileTest SendApduData.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, SendApduData006, TestSize.Level1)
{
    std::u16string aid = u"test";
    EsimApduData apduData;
    apduData.closeChannelFlag_ = false;
    esimFile->currentChannelId_ = 1;
    esimFile->aidStr_ = u"";
    esimFile->SendApduData(aid, apduData);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: CombineResponseDataFinish001
 * @tc.desc: Test EsimFileTest CombineResponseDataFinish.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, CombineResponseDataFinish001, TestSize.Level1)
{
    IccFileData fileData;
    fileData.sw1 = 0x61;
    esimFile->CombineResponseDataFinish(fileData);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessIfNeedMoreResponse001
 * @tc.desc: Test EsimFileTest ProcessIfNeedMoreResponse.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessIfNeedMoreResponse001, TestSize.Level1)
{
    IccFileData fileData;
    fileData.sw1 = 0x61;
    int32_t eventId = 0;
    esimFile->ProcessIfNeedMoreResponse(fileData, eventId);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessIfNeedMoreResponse002
 * @tc.desc: Test EsimFileTest ProcessIfNeedMoreResponse.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessIfNeedMoreResponse002, TestSize.Level1)
{
    IccFileData fileData;
    fileData.sw1 = 0x62;
    int32_t eventId = 0;
    esimFile->ProcessIfNeedMoreResponse(fileData, eventId);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: MergeRecvLongDataComplete001
 * @tc.desc: Test EsimFileTest MergeRecvLongDataComplete.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, MergeRecvLongDataComplete001, TestSize.Level1)
{
    IccFileData fileData;
    fileData.sw1 = 0x62;
    int32_t eventId = 0;
    esimFile->MergeRecvLongDataComplete(fileData, eventId);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessPrepareDownloadDone001
 * @tc.desc: Test EsimFileTest ProcessPrepareDownloadDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessPrepareDownloadDone001, TestSize.Level1)
{
    auto event = AppExecFwk::InnerEvent::Get(0);
    esimFile->ProcessPrepareDownloadDone(event);
    event = nullptr;
    esimFile->ProcessPrepareDownloadDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessPrepareDownloadDone002
 * @tc.desc: Test EsimFileTest ProcessPrepareDownloadDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessPrepareDownloadDone002, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x61;
    esimFile->newRecvData_ = newRecvData;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessPrepareDownloadDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessPrepareDownloadDone003
 * @tc.desc: Test EsimFileTest ProcessPrepareDownloadDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessPrepareDownloadDone003, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x90;
    newRecvData.sw2 = 0x00;
    newRecvData.resultData = "test";
    esimFile->newRecvData_ = newRecvData;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessPrepareDownloadDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: RealProcessPrepareDownloadDone001
 * @tc.desc: Test EsimFileTest RealProcessPrepareDownloadDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, RealProcessPrepareDownloadDone001, TestSize.Level1)
{
    esimFile->RealProcessPrepareDownloadDone();
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: LoadBoundProfilePackageParseNotificationMetadata001
 * @tc.desc: Test EsimFileTest LoadBoundProfilePackageParseNotificationMetadata.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, LoadBoundProfilePackageParseNotificationMetadata001, TestSize.Level1)
{
    std::shared_ptr<Asn1Node> notificationMetadata = nullptr;
    esimFile->LoadBoundProfilePackageParseNotificationMetadata(notificationMetadata);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: LoadBoundProfilePackageParseProfileInstallResult001
 * @tc.desc: Test EsimFileTest LoadBoundProfilePackageParseProfileInstallResult.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, LoadBoundProfilePackageParseProfileInstallResult001, TestSize.Level1)
{
    std::shared_ptr<Asn1Node> root = nullptr;
    esimFile->LoadBoundProfilePackageParseProfileInstallResult(root);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessListNotificationsDone001
 * @tc.desc: Test EsimFileTest ProcessListNotificationsDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessListNotificationsDone001, TestSize.Level1)
{
    auto event = AppExecFwk::InnerEvent::Get(0);
    esimFile->ProcessListNotificationsDone(event);
    event = nullptr;
    esimFile->ProcessListNotificationsDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessListNotificationsDone002
 * @tc.desc: Test EsimFileTest ProcessListNotificationsDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessListNotificationsDone002, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x61;
    esimFile->newRecvData_ = newRecvData;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessListNotificationsDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessListNotificationsDone003
 * @tc.desc: Test EsimFileTest ProcessListNotificationsDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessListNotificationsDone003, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x90;
    newRecvData.sw2 = 0x00;
    newRecvData.resultData = "test";
    esimFile->newRecvData_ = newRecvData;
    esimFile->recvCombineStr_ = BPP_COMBINE_HEX_STR;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessListNotificationsDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessRetrieveNotificationDone001
 * @tc.desc: Test EsimFileTest ProcessRetrieveNotificationDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessRetrieveNotificationDone001, TestSize.Level1)
{
    auto event = AppExecFwk::InnerEvent::Get(0);
    esimFile->ProcessRetrieveNotificationDone(event);
    event = nullptr;
    esimFile->ProcessRetrieveNotificationDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessRetrieveNotificationDone002
 * @tc.desc: Test EsimFileTest ProcessRetrieveNotificationDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessRetrieveNotificationDone002, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x61;
    esimFile->newRecvData_ = newRecvData;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessRetrieveNotificationDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessRetrieveNotificationDone003
 * @tc.desc: Test EsimFileTest ProcessRetrieveNotificationDone.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessRetrieveNotificationDone003, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x90;
    newRecvData.sw2 = 0x00;
    newRecvData.resultData = "test";
    esimFile->newRecvData_ = newRecvData;
    esimFile->recvCombineStr_ = BPP_COMBINE_HEX_STR;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessRetrieveNotificationDone(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: GetImeiBytes0001
 * @tc.desc: Test EsimFileTest GetImeiBytes.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, GetImeiBytes001, TestSize.Level1)
{
    std::vector<uint8_t> imeiBytes;
    std::string imei = "";
    esimFile->GetImeiBytes(imeiBytes, imei);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: GetImeiBytes0002
 * @tc.desc: Test EsimFileTest GetImeiBytes.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, GetImeiBytes002, TestSize.Level1)
{
    std::vector<uint8_t> imeiBytes;
    std::string imei(16, '1');
    esimFile->GetImeiBytes(imeiBytes, imei);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: GetImeiBytes0003
 * @tc.desc: Test EsimFileTest GetImeiBytes.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, GetImeiBytes003, TestSize.Level1)
{
    std::vector<uint8_t> imeiBytes;
    std::string imei(20, '1');
    esimFile->GetImeiBytes(imeiBytes, imei);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: AddCtxParams10001
 * @tc.desc: Test EsimFileTest AddCtxParams1.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, AddCtxParams1001, TestSize.Level1)
{
    std::shared_ptr<Asn1Builder> ctxParams1Builder = nullptr;
    Es9PlusInitAuthResp authRespData;
    esimFile->AddCtxParams1(ctxParams1Builder, authRespData);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessObtainEuiccInfo2Done0001
 * @tc.desc: Test EsimFileTest ProcessObtainEuiccInfo2Done.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessObtainEuiccInfo2Done001, TestSize.Level1)
{
    auto event = AppExecFwk::InnerEvent::Get(0);
    esimFile->ProcessObtainEuiccInfo2Done(event);
    event = nullptr;
    esimFile->ProcessObtainEuiccInfo2Done(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessObtainEuiccInfo2Done0002
 * @tc.desc: Test EsimFileTest ProcessObtainEuiccInfo2Done.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessObtainEuiccInfo2Done002, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x61;
    esimFile->newRecvData_ = newRecvData;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessObtainEuiccInfo2Done(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessObtainEuiccInfo2Done0003
 * @tc.desc: Test EsimFileTest ProcessObtainEuiccInfo2Done.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessObtainEuiccInfo2Done003, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x90;
    newRecvData.sw2 = 0x00;
    newRecvData.resultData = "test";
    esimFile->newRecvData_ = newRecvData;
    esimFile->recvCombineStr_ = BPP_COMBINE_HEX_STR;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessObtainEuiccInfo2Done(event);
    ASSERT_TRUE(esimFile != nullptr);
}

/**
 * @tc.name: ProcessObtainEuiccInfo2Done0004
 * @tc.desc: Test EsimFileTest ProcessObtainEuiccInfo2Done.
 * @tc.type: FUNC
 */
HWTEST_F(EsimFileTest, ProcessObtainEuiccInfo2Done004, TestSize.Level1)
{
    IccFileData newRecvData;
    newRecvData.sw1 = 0x90;
    newRecvData.sw2 = 0x00;
    newRecvData.resultData = "";
    esimFile->newRecvData_ = newRecvData;
    esimFile->recvCombineStr_ = BPP_COMBINE_HEX_STR;
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    esimFile->ProcessObtainEuiccInfo2Done(event);
    ASSERT_TRUE(esimFile != nullptr);
}

HWTEST_F(EsimFileTest, ObtainChannelSuccessAlllowSameAidReuse0001, TestSize.Level1)
{
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(nullptr);
    esimFile->aidStr_ = u"testAid";
    std::u16string testAid = u"testAid1";
    auto ret = esimFile->ObtainChannelSuccessAlllowSameAidReuse(testAid);
    EXPECT_EQ(ret, ResultInnerCode::RESULT_EUICC_CARD_CHANNEL_OTHER_AID);
}

HWTEST_F(EsimFileTest, SyncCloseChannel0001, TestSize.Level1)
{
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(nullptr);
    esimFile->currentChannelId_.store(2);
    esimFile->telRilManager_ = nullptr;
    esimFile->SyncCloseChannel();
    EXPECT_EQ(esimFile->currentChannelId_.load(), 0);
}

HWTEST_F(EsimFileTest, RealProcessRequestAllProfilesDone001, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EXPECT_FALSE(esimFile->RealProcessRequestAllProfilesDone());
}

HWTEST_F(EsimFileTest, RealProcessRequestAllProfilesDone002, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "bf2d820000";
    EXPECT_FALSE(esimFile->RealProcessRequestAllProfilesDone());
}

HWTEST_F(EsimFileTest, RealProcessRequestAllProfilesDone003, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "BF2D14A012E3105A0A896700000000004523019F700101";
    EXPECT_TRUE(esimFile->RealProcessRequestAllProfilesDone());
}

HWTEST_F(EsimFileTest, RealProcessRequestAllProfilesDone004, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "BF2D14A012E3105B0A896700000000004523019F700101";
    EXPECT_TRUE(esimFile->RealProcessRequestAllProfilesDone());
}

HWTEST_F(EsimFileTest, RealProcessAuthenticateServerDone001, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());
}

HWTEST_F(EsimFileTest, RealProcessAuthenticateServerDone002, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "BF3706A10480000200009000";
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());
}

HWTEST_F(EsimFileTest, RealProcessAuthenticateServerDone003, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "BF3706A10480000200009000";
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());
}

HWTEST_F(EsimFileTest, RealProcessAuthenticateServerDone004, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "bf38820019a18200158010d26989bcf14248379c55bb75c9569186020101";
    EXPECT_TRUE(esimFile->RealProcessAuthenticateServerDone());
}

HWTEST_F(EsimFileTest, RealProcessAuthenticateServerDone005, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "bf3882000aa1820006800000020000";
    EXPECT_FALSE(esimFile->RealProcessAuthenticateServerDone());
}

HWTEST_F(EsimFileTest, RealProcessAuthenticateServerDone006, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "bf3882000aa0820006800000020000";
    EXPECT_TRUE(esimFile->RealProcessAuthenticateServerDone());
}

HWTEST_F(EsimFileTest, ProcessEsimCloseSpareChannel0001, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->telRilManager_ = telRilManager;
    esimFile->ProcessEsimCloseSpareChannel();
    EXPECT_EQ(esimFile->currentChannelId_.load(), 0);
}

HWTEST_F(EsimFileTest, CommMergeRecvData001, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::mutex mtx;
    bool lag = false;
    std::condition_variable cv;
    int32_t eventId = 0;
    bool isHandleFinish = false;
    IccFileData newRecvData;
    newRecvData.sw1 = 0x90;
    newRecvData.sw2 = 0x00;
    esimFile->newRecvData_ = newRecvData;
    EXPECT_TRUE(esimFile->CommMergeRecvData(mtx, lag, cv, eventId, isHandleFinish));
}

HWTEST_F(EsimFileTest, CommMergeRecvData002, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::mutex mtx;
    bool lag = false;
    std::condition_variable cv;
    int32_t eventId = 0;
    bool isHandleFinish = false;
    IccFileData newRecvData;
    newRecvData.sw1 = 0x90;
    newRecvData.sw2 = 0x00;
    newRecvData.resultData = "test";
    esimFile->newRecvData_ = newRecvData;
    EXPECT_FALSE(esimFile->CommMergeRecvData(mtx, lag, cv, eventId, isHandleFinish));
}

HWTEST_F(EsimFileTest, CommMergeRecvData003, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::mutex mtx;
    bool lag = false;
    std::condition_variable cv;
    int32_t eventId = 0;
    bool isHandleFinish = false;
    IccFileData newRecvData;
    newRecvData.sw1 = 0x61;
    esimFile->newRecvData_ = newRecvData;
    EXPECT_TRUE(esimFile->CommMergeRecvData(mtx, lag, cv, eventId, isHandleFinish));
}

HWTEST_F(EsimFileTest, RealProcessPrepareDownloadDone0001, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "bf21820019a18200158010d26989bcf14248379c55bb75c9569186020101";
    EXPECT_FALSE(esimFile->RealProcessPrepareDownloadDone());
}

HWTEST_F(EsimFileTest, RealProcessPrepareDownloadDone002, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "bf21820019a18200158010d26989bcf14248379c55bb75c9569186020100";
    EXPECT_TRUE(esimFile->RealProcessPrepareDownloadDone());
}

HWTEST_F(EsimFileTest, RealProcessPrepareDownloadDone003, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "bf21820019a08200158010d26989bcf14248379c55bb75c9569186020101";
    EXPECT_TRUE(esimFile->RealProcessPrepareDownloadDone());
}

HWTEST_F(EsimFileTest, RealProcessPrepareDownloadDone004, TestSize.Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->recvCombineStr_ = "bf21820016a18200128010d26989bcf14248379c55bb75c9569186";
    EXPECT_TRUE(esimFile->RealProcessPrepareDownloadDone());
}
}
}
}
