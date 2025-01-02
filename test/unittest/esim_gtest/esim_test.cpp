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

#include <string>
#include <unistd.h>

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

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimTest::TearDownTestCase() {}

void EsimTest::SetUp() {}

void EsimTest::TearDown() {}

void EsimTest::SetUpTestCase() {}

static const std::string bppCombineHexStr = "BF3781ADBF27678008D14FE1DE62C340D7BF2F3480024C66810207800C1E31302E313"
    "02E31322E3136342F64702D706C75732D696E746572666163655A0A98680010203040506080060388370AA21FA01D4F10A000000559101"
    "0FFFFFFFF890000120004093007A00530038001005F3740B354AE39D08ACD7EDD7D2D01C73378621F623B832DFA3243489C5B42C90F220"
    "14E6C928130D78EE561982EF412AC3D94C04B56F37657DA84FD7BB24DD5634E89";

static const std::string boundProfilePackage = "vzaCFPW/I4GjggEBgAiX"
    "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";

HWTEST_F(EsimTest, SyncOpenChannel_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 2;
    esimFile->ObtainChannelSuccessExclusive();
    EXPECT_TRUE(esimFile->IsLogicChannelOpen());
}

HWTEST_F(EsimTest, SyncOpenChannel_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::u16string aid = Str8ToStr16("123");
    esimFile->currentChannelId_ = 2;
    esimFile->ObtainChannelSuccessAlllowSameAidReuse(aid);
    EXPECT_TRUE(esimFile->IsLogicChannelOpen());
}

HWTEST_F(EsimTest, SyncCloseChannel_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    esimFile->SyncCloseChannel();
    EXPECT_FALSE(esimFile->IsLogicChannelOpen());
}

HWTEST_F(EsimTest, SyncCloseChannel_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    esimFile->SyncCloseChannel();
    EXPECT_TRUE(esimFile->IsLogicChannelOpen());
}

HWTEST_F(EsimTest, ObtainEid_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ("", esimFile->ObtainEid());
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ("", esimFile->ObtainEid());
}

HWTEST_F(EsimTest, ProcessObtainEid_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventGetEid = iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EID_DONE);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(esimFile->ProcessObtainEid(slotId, eventGetEid), false);
    esimFile->currentChannelId_ = 2;
    EXPECT_EQ(esimFile->ProcessObtainEid(slotId, eventGetEid), false);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(esimFile->ProcessObtainEid(slotId, eventGetEid), true);
}

HWTEST_F(EsimTest, ProcessObtainEidDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3E125A1089086030202200000024000070951319";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainEidDone(event));
    auto eventGetEid = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessObtainEidDone(eventGetEid), false);
    eventGetEid = nullptr;
    EXPECT_EQ(esimFile->ProcessObtainEidDone(eventGetEid), false);
}

HWTEST_F(EsimTest, GetEuiccProfileInfoList_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    GetEuiccProfileInfoListResult euiccProfileInfoList_;
    EXPECT_EQ(static_cast<int32_t>(euiccProfileInfoList_.result_), esimFile->GetEuiccProfileInfoList().result_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(static_cast<int32_t>(euiccProfileInfoList_.result_), esimFile->GetEuiccProfileInfoList().result_);
}

HWTEST_F(EsimTest, ProcessRequestAllProfiles_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRequestAllProfiles = iccFile->BuildCallerInfo(MSG_ESIM_REQUEST_ALL_PROFILES);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRequestAllProfiles(slotId, eventRequestAllProfiles));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessRequestAllProfiles(slotId, eventRequestAllProfiles));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRequestAllProfiles(slotId, eventRequestAllProfiles));
}

HWTEST_F(EsimTest, ProcessRequestAllProfilesDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF2D25A023E3215A0A986800102030405060809F7001019105736D617274950102B705800364F007";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessRequestAllProfilesDone(event));
    auto eventRequestAllProfiles = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessRequestAllProfilesDone(eventRequestAllProfiles), false);
    eventRequestAllProfiles = nullptr;
    EXPECT_EQ(esimFile->ProcessRequestAllProfilesDone(eventRequestAllProfiles), false);
}

HWTEST_F(EsimTest, GetEuiccInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo eUiccInfo_;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(eUiccInfo_.osVersion_, esimFile->GetEuiccInfo().osVersion_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(eUiccInfo_.osVersion_, esimFile->GetEuiccInfo().osVersion_);
}

HWTEST_F(EsimTest, CommBuildOneApduReqInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    ApduSimIORequestInfo reqInfo;
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_RAT);
    esimFile->CommBuildOneApduReqInfo(reqInfo, builder);
    EXPECT_NE(esimFile->nextSerialId_, -1);
}

HWTEST_F(EsimTest, ProcessObtainEuiccInfo1_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventEUICCInfo1 = iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO_1_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1(slotId, eventEUICCInfo1), false);
    esimFile->currentChannelId_ = 2;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1(slotId, eventEUICCInfo1), false);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1(slotId, eventEUICCInfo1), true);
}

HWTEST_F(EsimTest, ProcessObtainEuiccInfo1Done_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF20618203020202A92C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30414C0BC70BA369"
        "29D43B467FF57570530E57AB8FCD8AA2C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30414C0BC70BA36929D43B467FF575"
        "70530E57AB8FCD8";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainEuiccInfo1Done(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1Done(event), false);
    event1 = nullptr;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo1Done(event1), false);
}

HWTEST_F(EsimTest, ProcessEsimOpenChannel_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::u16string aid = Str8ToStr16("123");
    int32_t slotId = 0;
    esimFile->ProcessEsimOpenChannel(aid);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    esimFile->ProcessEsimOpenChannel(aid);
    EXPECT_NE(telRilManager, nullptr);
}

HWTEST_F(EsimTest, ProcessEsimOpenChannelDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(false, esimFile->ProcessEsimOpenChannelDone(event));
    event = nullptr;
    EXPECT_EQ(false, esimFile->ProcessEsimOpenChannelDone(event));
}

HWTEST_F(EsimTest, ProcessEsimCloseChannel_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    esimFile->ProcessEsimCloseChannel();
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    esimFile->ProcessEsimCloseChannel();
    EXPECT_NE(telRilManager, nullptr);
}

HWTEST_F(EsimTest, ProcessEsimCloseChannelDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer event = iccFile->BuildCallerInfo(MSG_ESIM_CLOSE_CHANNEL_DONE);
    EXPECT_EQ(true, esimFile->ProcessEsimCloseChannelDone(event));
}

HWTEST_F(EsimTest, ObtainEuiccInfo1ParseTagCtx2_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t tag = 0;
    std::vector<uint8_t> src;
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, src, 0, 0);
    asn1Node->constructed_ = false;
    bool ret = esimFile->ObtainEuiccInfo1ParseTagCtx2(asn1Node);
    EXPECT_EQ(ret, false);
}

HWTEST_F(EsimTest, RequestAllProfilesParseProfileInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020410BF2F128001020C09736D6470322E636F60810204209000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, responseByte.size());
    EXPECT_EQ(esimFile->RequestAllProfilesParseProfileInfo(root), true);
}

HWTEST_F(EsimTest, ProcessEvent_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    esimFile->ProcessEvent(event);
    event = nullptr;
    esimFile->ProcessEvent(event);
    event =esimFile->BuildCallerInfo(MSG_ESIM_REQUEST_ALL_PROFILES);
    esimFile->ProcessEvent(event);
    EXPECT_EQ(event, nullptr);
}

HWTEST_F(EsimTest, ObtainSpnCondition_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    bool roaming = false;
    std::string str = "abc";
    int res = esimFile->ObtainSpnCondition(roaming, str);
    EXPECT_EQ(res, 0);
}

HWTEST_F(EsimTest, ProcessIccReady_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    int res = esimFile->ProcessIccReady(event);
    EXPECT_EQ(res, false);
}

HWTEST_F(EsimTest, UpdateVoiceMail_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string mailName = "wang";
    std::string mailNumber = "123456";
    int res = esimFile->UpdateVoiceMail(mailName, mailNumber);
    EXPECT_EQ(res, false);
}

HWTEST_F(EsimTest, SetVoiceMailCount_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t voiceMailCount = 0;
    int res = esimFile->SetVoiceMailCount(voiceMailCount);
    EXPECT_EQ(res, false);
}

HWTEST_F(EsimTest, SetVoiceCallForwarding_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    bool enable = false;
    std::string number = "123";
    int res = esimFile->SetVoiceCallForwarding(enable, number);
    EXPECT_EQ(res, false);
}

HWTEST_F(EsimTest, GetVoiceMailNumber_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string res = esimFile->GetVoiceMailNumber();
    EXPECT_EQ(res, "");
}

HWTEST_F(EsimTest, InitMemberFunc_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->InitMemberFunc();
    bool ret = esimFile->memberFuncMap_.empty();
    EXPECT_FALSE(ret);
}

HWTEST_F(EsimTest, DisableProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000452301");
    int32_t disableProfileResult = static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER);
    esimFile->currentChannelId_ = 0;
    EXPECT_NE(disableProfileResult, esimFile->DisableProfile(portIndex, iccId));
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_NE(disableProfileResult, esimFile->DisableProfile(portIndex, iccId));
    esimFile->currentChannelId_ = 2;
    EXPECT_NE(disableProfileResult, esimFile->DisableProfile(portIndex, iccId));
}

HWTEST_F(EsimTest, ProcessDisableProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventGetProfile = iccFile->BuildCallerInfo(MSG_ESIM_DISABLE_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));
    esimFile->currentChannelId_ = 2;
    std::string iccIdStr = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdStr);
    EXPECT_FALSE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));
    std::string str = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_TRUE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));
}

HWTEST_F(EsimTest, ProcessDisableProfileDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF32038001009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessDisableProfileDone(event));
    auto eventDisableProfile = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessDisableProfileDone(eventDisableProfile), false);
    eventDisableProfile = nullptr;
    EXPECT_EQ(esimFile->ProcessDisableProfileDone(eventDisableProfile), false);
}

HWTEST_F(EsimTest, ObtainSmdsAddress_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::string smdsAddress = "";
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(smdsAddress, esimFile->ObtainSmdsAddress(portIndex));
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(smdsAddress, esimFile->ObtainSmdsAddress(portIndex));
}

HWTEST_F(EsimTest, ObtainRulesAuthTable_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(eUiccRulesAuthTable.position_, (esimFile->ObtainRulesAuthTable(portIndex)).position_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(eUiccRulesAuthTable.position_, (esimFile->ObtainRulesAuthTable(portIndex)).position_);
}

HWTEST_F(EsimTest, ObtainEuiccChallenge_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    ResponseEsimResult responseChallengeResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(static_cast<int32_t>(responseChallengeResult.resultCode_), 
        (esimFile->ObtainEuiccChallenge(portIndex)).resultCode_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(static_cast<int32_t>(responseChallengeResult.resultCode_), 
        (esimFile->ObtainEuiccChallenge(portIndex)).resultCode_);
}

HWTEST_F(EsimTest, RequestRulesAuthTableParseTagCtxComp0_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData = "BF434B"
        "A0233021"
        "800206C0"
        "A118"
        "B70A800312F3458103010203"
        "B70A800312F3458203040506"
        "820108"
        "A0243022"
        "80020780"
        "A118"
        "B70A800312E3458103010203"
        "B70A8003EEEE458203040506"
        "82020780"
        "9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EXPECT_TRUE(esimFile->RequestRulesAuthTableParseTagCtxComp0(root));
    byteLen = 0;
    EXPECT_TRUE(esimFile->RequestRulesAuthTableParseTagCtxComp0(root));
}

HWTEST_F(EsimTest, ProcessRequestRulesAuthTableDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRequestRulesAuthTable =
        iccFile->BuildCallerInfo(MSG_ESIM_REQUEST_RULES_AUTH_TABLE);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF434B"
        "A0233021"
        "800206C0"
        "A118"
        "B70A800312F3458103010203"
        "B70A800312F3458203040506"
        "820108"
        "A0243022"
        "80020780"
        "A118"
        "B70A800312E3458103010203"
        "B70A8003EEEE458203040506"
        "82020780"
        "9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessRequestRulesAuthTableDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessRequestRulesAuthTableDone(event1), true);
    event1 = nullptr;
    EXPECT_EQ(esimFile->ProcessRequestRulesAuthTableDone(event1), true);
}

HWTEST_F(EsimTest, ProcessRequestRulesAuthTable_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRequestRulesAuthTable =
        iccFile->BuildCallerInfo(MSG_ESIM_REQUEST_RULES_AUTH_TABLE);
    esimFile->currentChannelId_ = 1;
    EXPECT_FALSE(esimFile->ProcessRequestRulesAuthTable(slotId, eventRequestRulesAuthTable));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRequestRulesAuthTable(slotId, eventRequestRulesAuthTable));
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRequestRulesAuthTable(slotId, eventRequestRulesAuthTable));
}

HWTEST_F(EsimTest, ProcessObtainSmdsAddressDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3C148008534D44502E434F4D8108736D64732E636F6D9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainSmdsAddressDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddressDone(event));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddressDone(event));
}

HWTEST_F(EsimTest, ProcessObtainSmdsAddress_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventObtainSmdsAddress = iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_SMDS_ADDRESS);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
}

HWTEST_F(EsimTest, ProcessObtainEuiccChallenge_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventEUICCChanllenge =
        iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_CHALLENGE_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(esimFile->ProcessObtainEuiccChallenge(slotId, eventEUICCChanllenge), false);
    esimFile->currentChannelId_ = 2;
    EXPECT_EQ(esimFile->ProcessObtainEuiccChallenge(slotId, eventEUICCChanllenge), false);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(esimFile->ProcessObtainEuiccChallenge(slotId, eventEUICCChanllenge), true);
}

HWTEST_F(EsimTest, ProcessObtainEuiccChallengeDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF2E1280105DAD74D9F1734CF96CDE5C78FDB0565B";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainEuiccChallengeDone(event));
    auto eventEUICCChanllenge = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessObtainEuiccChallengeDone(eventEUICCChanllenge), false);
    eventEUICCChanllenge = nullptr;
    EXPECT_EQ(esimFile->ProcessObtainEuiccChallengeDone(eventEUICCChanllenge), false);
}

HWTEST_F(EsimTest, ObtainDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string defaultDpAddress_ = "";
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(defaultDpAddress_, esimFile->ObtainDefaultSmdpAddress());
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(defaultDpAddress_, esimFile->ObtainDefaultSmdpAddress());
}

HWTEST_F(EsimTest, CancelSession_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimResult responseResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(static_cast<int32_t>(responseResult.resultCode_),
        (esimFile->CancelSession(transactionId, cancelReason)).resultCode_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(static_cast<int32_t>(responseResult.resultCode_),
        (esimFile->CancelSession(transactionId, cancelReason)).resultCode_);
}

HWTEST_F(EsimTest, ObtainProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000216954");
    EuiccProfile eUiccProfile;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(eUiccProfile.state_, (esimFile->ObtainProfile(portIndex, iccId)).state_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(eUiccProfile.state_, (esimFile->ObtainProfile(portIndex, iccId)).state_);
}

HWTEST_F(EsimTest, ProcessObtainDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSmdpAddress =
        iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_DEFAULT_SMDP_ADDRESS_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));
}

HWTEST_F(EsimTest, ProcessObtainDefaultSmdpAddressDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3C148008534D44502E434F4D8108736D64732E58225F9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainDefaultSmdpAddressDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddressDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddressDone(event1));
}

HWTEST_F(EsimTest, ProcessCancelSession_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventCancelSession = iccFile->BuildCallerInfo(MSG_ESIM_CANCEL_SESSION);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessCancelSession(slotId, eventCancelSession));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessCancelSession(slotId, eventCancelSession));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessCancelSession(slotId, eventCancelSession));
}

HWTEST_F(EsimTest, ProcessCancelSessionDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF41009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessCancelSessionDone(event));
    std::shared_ptr<IccControllerHolder> holder1 = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg1 = std::make_unique<Telephony::IccFromRilMsg>(holder1);
    rcvMsg1->fileData.resultData = "BF4106810456362523";
    event = AppExecFwk::InnerEvent::Get(0, rcvMsg1);
    EXPECT_FALSE(esimFile->ProcessCancelSessionDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessCancelSessionDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessCancelSessionDone(event1));
}

HWTEST_F(EsimTest, ProcessGetProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventGetProfile = iccFile->BuildCallerInfo(MSG_ESIM_GET_PROFILE);
    const int32_t CHANEL_ID_ZERO = 0;
    esimFile->currentChannelId_ = CHANEL_ID_ZERO;
    EXPECT_FALSE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
    const int32_t CHANEL_ID_TWO = 0;
    esimFile->currentChannelId_ = CHANEL_ID_TWO;
    std::string str = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_FALSE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
    std::string iccIdstr = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdstr);
    EXPECT_TRUE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
}

HWTEST_F(EsimTest, ProcessGetProfileDone_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF2D";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_FALSE(esimFile->ProcessGetProfileDone(event));
}

HWTEST_F(EsimTest, ResetMemory_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    ResetOption resetOption = ResetOption::DELETE_FIELD_LOADED_TEST_PROFILES;
    int32_t resetResult = static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER);
    esimFile->currentChannelId_ = 0;
    EXPECT_NE(resetResult, esimFile->ResetMemory(resetOption));
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_NE(resetResult, esimFile->ResetMemory(resetOption));
}

HWTEST_F(EsimTest, ProcessResetMemory_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventResetMemory = iccFile->BuildCallerInfo(MSG_ESIM_RESET_MEMORY);
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(esimFile->ProcessResetMemory(slotId, eventResetMemory), false);
    esimFile->currentChannelId_ = 2;
    EXPECT_EQ(esimFile->ProcessResetMemory(slotId, eventResetMemory), false);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(esimFile->ProcessResetMemory(slotId, eventResetMemory), true);
}

HWTEST_F(EsimTest, ProcessResetMemoryDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF34038001009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessResetMemoryDone(event));
    auto eventResetMemory = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessResetMemoryDone(eventResetMemory), false);
    eventResetMemory = nullptr;
    EXPECT_EQ(esimFile->ProcessResetMemoryDone(eventResetMemory), false);
}

HWTEST_F(EsimTest, ProcessSendApduDataDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessSendApduDataDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessSendApduDataDone(event1), false);
    event1 = nullptr;
    EXPECT_EQ(esimFile->ProcessSendApduDataDone(event1), false);
}

HWTEST_F(EsimTest, ProcessSendApduData_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSendApduData = iccFile->BuildCallerInfo(MSG_ESIM_SEND_APUD_DATA);
    esimFile->currentChannelId_ = 1;
    EXPECT_FALSE(esimFile->ProcessSendApduData(slotId, eventSendApduData));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessSendApduData(slotId, eventSendApduData));
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessSendApduData(slotId, eventSendApduData));
}

HWTEST_F(EsimTest, ObtainPrepareDownload_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    DownLoadConfigInfo downLoadConfigInfo;
    ResponseEsimResult preDownloadResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(static_cast<int32_t>(preDownloadResult.resultCode_),
        (esimFile->ObtainPrepareDownload(downLoadConfigInfo)).resultCode_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(static_cast<int32_t>(preDownloadResult.resultCode_),
        (esimFile->ObtainPrepareDownload(downLoadConfigInfo)).resultCode_);
}

HWTEST_F(EsimTest, ObtainLoadBoundProfilePackage_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string boundProfilePackageStr;
    ResponseEsimBppResult loadBPPResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(static_cast<int32_t>(loadBPPResult.resultCode_), (esimFile->ObtainLoadBoundProfilePackage(
        portIndex, boundProfilePackageStr)).resultCode_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(static_cast<int32_t>(loadBPPResult.resultCode_), (esimFile->ObtainLoadBoundProfilePackage(
        portIndex, boundProfilePackageStr)).resultCode_);
}

HWTEST_F(EsimTest, ListNotifications_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    Event events = Event::EVENT_DONOTHING;
    esimFile->currentChannelId_ = 0;
    EXPECT_TRUE((esimFile->ListNotifications(portIndex, events)).euiccNotification_.empty());
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE((esimFile->ListNotifications(portIndex, events)).euiccNotification_.empty());
}

HWTEST_F(EsimTest, ProcessPrepareDownload_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessPrepareDownload(slotId));

    esimFile->currentChannelId_ = 2;
    EXPECT_TRUE(esimFile->ProcessPrepareDownload(slotId));

    std::u16string str = u"hashCctest";
    esimFile->esimProfile_.hashCc = str;
    EXPECT_TRUE(esimFile->ProcessPrepareDownload(slotId));

    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessPrepareDownload(slotId));
}


HWTEST_F(EsimTest, DecodeBoundProfilePackage_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    std::string boundProfilePackageStr = "some_decode_data";
    EXPECT_FALSE(esimFile->DecodeBoundProfilePackage(boundProfilePackageStr, bppNode));
}

HWTEST_F(EsimTest, BuildApduForInitSecureChannel_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    esimFile->DecodeBoundProfilePackage(boundProfilePackage, bppNode);
    int32_t currentChannelId_ = 1;
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> initSecureChannelReq = bppNode->Asn1GetChild(TAG_ESIM_INITIALISE_SECURE_CHANNEL);
    esimFile->BuildApduForInitSecureChannel(codec, bppNode, initSecureChannelReq);
    bool bRet = codec.GetCommands().size() != 0 ? true : false;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, BuildApduForFirstSequenceOf87_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    esimFile->DecodeBoundProfilePackage(boundProfilePackage, bppNode);
    int32_t currentChannelId_ = 1;
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> firstSequenceOf87 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_0);
    esimFile->BuildApduForFirstSequenceOf87(codec, firstSequenceOf87);
    bool bRet = codec.GetCommands().size() != 0 ? true : false;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, BuildApduForSequenceOf88_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    esimFile->DecodeBoundProfilePackage(boundProfilePackage, bppNode);
    int32_t currentChannelId_ = 1;
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> sequenceOf88 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_1);
    esimFile->BuildApduForSequenceOf88(codec, sequenceOf88);
    bool bRet = codec.GetCommands().size() != 0 ? true : false;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, BuildApduForSequenceOf86_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Asn1Node> bppNode = nullptr;
    esimFile->DecodeBoundProfilePackage(boundProfilePackage, bppNode);
    int32_t currentChannelId_ = 1;
    RequestApduBuild codec(currentChannelId_);
    std::shared_ptr<Asn1Node> sequenceOf86 = bppNode->Asn1GetChild(TAG_ESIM_CTX_COMP_3);
    esimFile->BuildApduForSequenceOf86(codec, bppNode, sequenceOf86);
    bool bRet = codec.GetCommands().size() != 0 ? true : false;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, ProcessLoadBoundProfilePackage_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventGetProfile = iccFile->BuildCallerInfo(MSG_ESIM_GET_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessLoadBoundProfilePackage(slotId));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessLoadBoundProfilePackage(slotId));
    esimFile->esimProfile_.boundProfilePackage = Str8ToStr16(boundProfilePackage);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessLoadBoundProfilePackage(slotId));
}

HWTEST_F(EsimTest, ProcessLoadBoundProfilePackageDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3781ADBF27678008D14FE1DE62C340D7BF2F3480024C66810207800C1E31302E31302E31322E"
        "3136342F64702D706C75732D696E746572666163655A0A98680010203040506080060388370AA21FA01D4F10A0000005591010FFF"
        "FFFFF890000120004093007A00530038001005F3740B354AE39D08ACD7EDD7D2D01C73378621F623B832DFA3243489C5B42C90F22"
        "014E6C928130D78EE561982EF412AC3D94C04B56F37657DA84FD7BB24D15C4783F";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessLoadBoundProfilePackageDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessLoadBoundProfilePackageDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessLoadBoundProfilePackageDone(event1));
}

HWTEST_F(EsimTest, LoadBoundProfilePackageParseNotificationMetadata_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(bppCombineHexStr);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    std::shared_ptr<Asn1Node> nodeNotificationMetadata =
        esimFile->LoadBoundProfilePackageParseProfileInstallResult(root);
    EXPECT_TRUE(esimFile->LoadBoundProfilePackageParseNotificationMetadata(nodeNotificationMetadata));
}

HWTEST_F(EsimTest, RealProcessLoadBoundProfilePackageDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EXPECT_TRUE(esimFile->RealProcessLoadBoundProfilePackageDone(bppCombineHexStr));
}

HWTEST_F(EsimTest, ProcessListNotifications_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventListNotif = iccFile->BuildCallerInfo(MSG_ESIM_LIST_NOTIFICATION);
    esimFile->currentChannelId_ =0 ;
    EXPECT_FALSE(esimFile->ProcessListNotifications(slotId, Event::EVENT_ENABLE, eventListNotif));
    esimFile->currentChannelId_ =2 ;
    EXPECT_FALSE(esimFile->ProcessListNotifications(slotId, Event::EVENT_ENABLE, eventListNotif));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessListNotifications(slotId, Event::EVENT_ENABLE, eventListNotif));
}

HWTEST_F(EsimTest, createNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string resultData = "BF2F118001010C08736D64702E636F6D81020508";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData.c_str());
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> node = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EuiccNotification euicc;
    esimFile->createNotification(node, euicc);
    bool bRet = euicc.targetAddr_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, createNotification_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData = "BF282BA029BF2F118001010C00736D64702E636F6C820";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData.c_str());
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> node = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EuiccNotification euicc;
    esimFile->createNotification(node, euicc);
    bool bRet = euicc.targetAddr_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, createNotification_003, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string resultData = "BF2F118001010C08736D64702E636F6D81020603";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData.c_str());
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> node = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EuiccNotification euicc;
    esimFile->createNotification(node, euicc);
    bool bRet = euicc.targetAddr_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, ProcessListNotificationsAsn1Response_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6D81020410BF2F128001020C09736D6470322E636F6D810205309000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();

    std::shared_ptr<Asn1Node> profileNode = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EXPECT_EQ(esimFile->ProcessListNotificationsAsn1Response(profileNode), false);
}

HWTEST_F(EsimTest, ProcessListNotificationsAsn1Response_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData = "BF2803810106";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();

    std::shared_ptr<Asn1Node> profileNode = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EXPECT_EQ(esimFile->ProcessListNotificationsAsn1Response(profileNode), false);
}

HWTEST_F(EsimTest, ProcessListNotificationsAsn1Response_003, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::string resultData = "BF2803A00106";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();

    std::shared_ptr<Asn1Node> profileNode = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EXPECT_EQ(esimFile->ProcessListNotificationsAsn1Response(profileNode), false);
}

HWTEST_F(EsimTest, RetrieveNotificationList_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    Event events = Event::EVENT_DONOTHING;
    esimFile->currentChannelId_ = 0;
    EXPECT_TRUE((esimFile->RetrieveNotificationList(portIndex, events)).euiccNotification_.empty());

    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE((esimFile->RetrieveNotificationList(portIndex, events)).euiccNotification_.empty());
}

HWTEST_F(EsimTest, ObtainRetrieveNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(notification.seq_, (esimFile->ObtainRetrieveNotification(portIndex, seqNumber)).seq_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(notification.seq_, (esimFile->ObtainRetrieveNotification(portIndex, seqNumber)).seq_);
}

HWTEST_F(EsimTest, RemoveNotificationFromList_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    int32_t removeNotifResult = static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER);
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(removeNotifResult, esimFile->RemoveNotificationFromList(portIndex, seqNumber));
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(removeNotifResult, esimFile->RemoveNotificationFromList(portIndex, seqNumber));
}

HWTEST_F(EsimTest, ProcessRemoveNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRemoveNotif = iccFile->BuildCallerInfo(MSG_ESIM_REMOVE_NOTIFICATION);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRemoveNotification(slotId, eventRemoveNotif));
}

HWTEST_F(EsimTest, ProcessRemoveNotificationDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3003800100";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessRemoveNotificationDone(event));
    auto eventRemoveNotif = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessRemoveNotificationDone(eventRemoveNotif), false);
    eventRemoveNotif = nullptr;
    EXPECT_EQ(esimFile->ProcessRemoveNotificationDone(eventRemoveNotif), false);
}

HWTEST_F(EsimTest, ProcessRetrieveNotification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRetrieveNotification =
        iccFile->BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));
    esimFile->currentChannelId_ = 2;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRetrieveNotification(slotId, eventRetrieveNotification));
}

HWTEST_F(EsimTest, ProcessRetrieveNotificationList_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventRetrieveListNotif =
        iccFile->BuildCallerInfo(MSG_ESIM_RETRIEVE_NOTIFICATION_LIST);
    Event events = Event::EVENT_ENABLE;
    esimFile->currentChannelId_ = 1;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessRetrieveNotificationList(slotId, events, eventRetrieveListNotif));
}

HWTEST_F(EsimTest, ProcessRetrieveNotificationListDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData =
        "BF2B2FA02D3014BF2F118001010C08736D64702E636F6D810204103015BF2F128001020C09736D6470322E636F6D810205109000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessRetrieveNotificationListDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessRetrieveNotificationListDone(event1), false);
    event1 = nullptr;
    EXPECT_EQ(esimFile->ProcessRetrieveNotificationListDone(event1), false);
}

HWTEST_F(EsimTest, RetrieveNotificationParseCompTag_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData =
        "BF2B2FA02D3014BF2F118001010C08736D64702E636F6D810204103015BF2F128001020C09736D6470322E636F6D810205109000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(rcvMsg->fileData.resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    EXPECT_TRUE(esimFile->RetrieveNotificationParseCompTag(root));
}

HWTEST_F(EsimTest, DeleteProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::u16string iccId;
    int32_t disableProfileResult_ = static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER);
    esimFile->currentChannelId_ = 0;
    EXPECT_NE(disableProfileResult_, esimFile->DeleteProfile(iccId));

    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_NE(disableProfileResult_, esimFile->DeleteProfile(iccId));
}

HWTEST_F(EsimTest, SwitchToProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    int32_t portIndex = 0;
    std::u16string iccId;
    bool forceDisableProfile = false;
    int32_t switchResult_ = static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER);
    esimFile->currentChannelId_ = 0;
    EXPECT_NE(switchResult_, esimFile->SwitchToProfile(portIndex, iccId, forceDisableProfile));

    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_NE(switchResult_, esimFile->SwitchToProfile(portIndex, iccId, forceDisableProfile));
}

HWTEST_F(EsimTest, SetProfileNickname_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    int32_t updateNicknameResult_ = static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER);
    esimFile->currentChannelId_ = 0;
    EXPECT_NE(updateNicknameResult_, esimFile->SetProfileNickname(iccId, nickname));

    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_NE(updateNicknameResult_, esimFile->SetProfileNickname(iccId, nickname));
}

HWTEST_F(EsimTest, ProcessDeleteProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventDeleteProfile = iccFile->BuildCallerInfo(MSG_ESIM_DELETE_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));

    esimFile->currentChannelId_ = 2;
    std::string iccIdStr = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdStr);
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));

    std::string str = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));
}

HWTEST_F(EsimTest, ProcessDeleteProfileDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF33038001009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessDeleteProfileDone(event));

    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessDeleteProfileDone(event1));

    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessDeleteProfileDone(event1));
}

HWTEST_F(EsimTest, ProcessSwitchToProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSwitchToProfile = iccFile->BuildCallerInfo(MSG_ESIM_SWITCH_PROFILE);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));

    esimFile->currentChannelId_ = 2;
    std::string iccIdStr = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdStr);
    EXPECT_FALSE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));

    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));

    std::string str = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_TRUE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));
}

HWTEST_F(EsimTest, ProcessSwitchToProfileDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF3103800100";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessSwitchToProfileDone(event));

    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessSwitchToProfileDone(event1));

    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessSwitchToProfileDone(event1));
}

HWTEST_F(EsimTest, ProcessSetNickname_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventSetNickName = iccFile->BuildCallerInfo(MSG_ESIM_SET_NICK_NAME);
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessSetNickname(slotId, eventSetNickName));

    esimFile->currentChannelId_ = 2;
    std::string iccIdStr = "ABCDEFG";
    esimFile->esimProfile_.iccId = Str8ToStr16(iccIdStr);
    EXPECT_FALSE(esimFile->ProcessSetNickname(slotId, eventSetNickName));

    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessSetNickname(slotId, eventSetNickName));

    std::string str = "ABCDEFGG";
    esimFile->esimProfile_.iccId = Str8ToStr16(str);
    EXPECT_TRUE(esimFile->ProcessSetNickname(slotId, eventSetNickName));
}

HWTEST_F(EsimTest, ProcessSetNicknameDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF31038001009000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessSetNicknameDone(event));

    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessSetNicknameDone(event1));

    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessSetNicknameDone(event1));
}

HWTEST_F(EsimTest, ProcessAuthenticateServer_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 0;
    EXPECT_FALSE(esimFile->ProcessAuthenticateServer(slotId));
    esimFile->currentChannelId_ = 2;
    EXPECT_TRUE(esimFile->ProcessAuthenticateServer(slotId));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessAuthenticateServer(slotId));
}

HWTEST_F(EsimTest, ProcessAuthenticateServerDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.sw1 = 90;
    rcvMsg->fileData.sw2 = 00;
    rcvMsg->fileData.resultData = "BF388205E5A08205E13082011C8008D14FE1DE62C340D7831E31302E31302E31322E3136342F647"
        "02D706C75732D696E746572666163658410F31F2690404C42718528B2301082A071BF2281A68103020301820302020283030402008"
        "40D81010082040007AE2E83022F378505067F32F7C08603090200870302030088020490A92C0414F54172BDF98A95D65CBEB88A38A"
        "1C11D800A85C30414C0BC70BA36929D43B467FF57570530E57AB8FCD8AA2C0414F54172BDF98A95D65CBEB88A38A1C11D800A85C30"
        "414C0BC70BA36929D43B467FF57570530E57AB8FCD88B010004030100000C0D45442D5A492D55502D30383234A0348017503658313"
        "72D3833594C332D52345230592D4E56523332A119800468396860A10F80030B000081030B000085030B000082005F3740B939AD87D"
        "29B5505CB5C00ACAABD3E156C680EF9A15B99D8C4361A9B4CA59C112D9CC649463515A860F534A1822536F537F7D422651F9D19A40"
        "384C90A2FFCCC308201FE308201A5A0030201020209020000000000000001300A06082A8648CE3D0403023037310B3009060355040"
        "61302455331153013060355040A0C0C52535020546573742045554D3111300F06035504030C0845554D20546573743020170D32303"
        "03430313039343835385A180F37343936303132343039343835385A3064310B300906035504061302455331153013060355040A0C0"
        "C52535020546573742045554D312930270603550405132038393038363033303230323230303030303032343030303037303935313"
        "331393113301106035504030C0A546573742065554943433059301306072A8648CE3D020106082A8648CE3D030107034200046DB3F"
        "53ADC87DC2FF10C7BFCD87AD13AE97009AFA065A6757EE571B3F2EBB18F46C1D68F3EDEB0E74B2E5D542051E7D27F50952028605AF"
        "DEF79FE9FFFD03959A36B3069301F0603551D23041830168014DD3DA24D350C1CC5D0AF0965F40EC34C5EE409F1301D0603551D0E0"
        "4160414A52476AF5D50AA376437CCB1DA2172EF45F484F0300E0603551D0F0101FF04040302078030170603551D200101FF040D300"
        "B3009060767811201020101300A06082A8648CE3D040302034700304402200858D232D4649A8BDA7B9441C1215854B1BC48AB52D24"
        "1CF57BA7D6FA0EB5191022009ED2C93F2184ECD34F2E42FD64B1DC68CF38EAB6CDBA9ADDDBD0139629C55CC308202783082021FA00"
        "3020102020412345678300A06082A8648CE3D04030230443110300E06035504030C07546573742043493111300F060355040B0C085"
        "4455354434552543110300E060355040A0C0752535054455354310B30090603550406130249543020170D323030343031303932383"
        "3375A180F32303534303332343039323833375A3037310B300906035504061302455331153013060355040A0C0C525350205465737"
        "42045554D3111300F06035504030C0845554D20546573743059301306072A8648CE3D020106082A8648CE3D030107034200041330D"
        "59256AC0CB50BD928D0F4C68007C485FE3F42988AD3EE3875AE33F4983AB23B4DD4C31340D676DD8E11F9C5CBA1B11EB694EED0994"
        "DB529285E632C8906A382010830820104301F0603551D23041830168014F54172BDF98A95D65CBEB88A38A1C11D800A85C3301D060"
        "3551D0E04160414DD3DA24D350C1CC5D0AF0965F40EC34C5EE409F1300E0603551D0F0101FF04040302020430170603551D200101F"
        "F040D300B3009060767811201020102300E0603551D1104073005880388370530120603551D130101FF040830060101FF020100303"
        "50603551D1F042E302C302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D422E63726"
        "C303E0603551D1E0101FF04343032A030302EA42C302A31153013060355040A0C0C52535020546573742045554D3111300F0603550"
        "40513083839303439303332300A06082A8648CE3D040302034700304402200C567BF01E45244863AD7A4613F7572EEF3439F698B47"
        "11AA397AEEFC5445CE702206E993AA0A505F260B0EEF62CC30A2BBE453B0E8248218FD53304EF7FAABBCCDD";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessAuthenticateServerDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessAuthenticateServerDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessAuthenticateServerDone(event1));
}

HWTEST_F(EsimTest, ConvertAuthInputParaFromApiStru_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    Es9PlusInitAuthResp bytes;
    esimFile->ConvertAuthInputParaFromApiStru(bytes, esimFile->esimProfile_);
    bool bRet = bytes.imei.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, ObtainEuiccInfo2_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    EuiccInfo2 EuiccInfo2;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(EuiccInfo2.svn_, (esimFile->ObtainEuiccInfo2(portIndex)).svn_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(EuiccInfo2.svn_, (esimFile->ObtainEuiccInfo2(portIndex)).svn_);
}

HWTEST_F(EsimTest, ProcessObtainEUICCInfo2_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventEUICCInfo2 = iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_INFO2_DONE);
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo2(slotId, eventEUICCInfo2), false);
    esimFile->currentChannelId_ = 2;
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo2(slotId, eventEUICCInfo2), false);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(esimFile->ProcessObtainEuiccInfo2(slotId, eventEUICCInfo2), true);
}

HWTEST_F(EsimTest, EuiccInfo2ParseProfileVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseProfileVersion(euiccInfo2, root);
    bool bRet = euiccInfo2.profileVersion_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseEuiccFirmwareVer_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseEuiccFirmwareVer(euiccInfo2, root);
    bool bRet = euiccInfo2.globalPlatformVersion_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseExtCardResource_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseExtCardResource(euiccInfo2, root);
    bool bRet = euiccInfo2.extCardResource_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseUiccCapability_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseUiccCapability(euiccInfo2, root);
    bool bRet = euiccInfo2.uiccCapability_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseTs102241Version_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseTs102241Version(euiccInfo2, root);
    bool bRet = euiccInfo2.ts102241Version_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseGlobalPlatformVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseGlobalPlatformVersion(euiccInfo2, root);
    bool bRet = euiccInfo2.globalPlatformVersion_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseRspCapability_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseRspCapability(euiccInfo2, root);
    bool bRet = euiccInfo2.rspCapability_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseEuiccCiPKIdListForVerification_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseEuiccCiPKIdListForVerification(euiccInfo2, root);
    bool bRet = euiccInfo2.euiccCiPKIdListForVerification_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseEuiccCiPKIdListForSigning_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseEuiccCiPKIdListForSigning(euiccInfo2, root);
    bool bRet = euiccInfo2.euiccCiPKIdListForSigning_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParseEuiccCategory_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParseEuiccCategory(euiccInfo2, root);
    bool bRet = euiccInfo2.euiccCategory_ == 0 ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, EuiccInfo2ParsePpVersion_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo2 euiccInfo2;
    std::string resultData =
        "BF282BA029BF2F118001010C08736D64702E636F6081020136BF2F128001020C09736D6470322E636F608102AABB9000";
    std::vector<uint8_t> responseByte = Asn1Utils::HexStrToBytes(resultData);
    uint32_t byteLen = responseByte.size();
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, byteLen);
    esimFile->EuiccInfo2ParsePpVersion(euiccInfo2, root);
    bool bRet = euiccInfo2.ppVersion_.empty() ? false : true;
    EXPECT_TRUE(bRet);
}

HWTEST_F(EsimTest, AuthenticateServer_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    AuthenticateConfigInfo authenticateConfigInfo;
    ResponseEsimResult responseAuthenticateResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(static_cast<int32_t>(responseAuthenticateResult.resultCode_),
        (esimFile->AuthenticateServer(authenticateConfigInfo)).resultCode_);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(static_cast<int32_t>(responseAuthenticateResult.resultCode_),
        (esimFile->AuthenticateServer(authenticateConfigInfo)).resultCode_);
}
} // namespace Telephony
} // namespace OHOS