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

HWTEST_F(EsimTest, SyncOpenChannel_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 2;
    esimFile->SyncOpenChannel();
}

HWTEST_F(EsimTest, SyncOpenChannel_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::u16string aid = Str8ToStr16("123");
    esimFile->currentChannelId_ = 2;
    esimFile->SyncOpenChannel(aid);
}

HWTEST_F(EsimTest, SyncCloseChannel_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    esimFile->SyncCloseChannel();
}

HWTEST_F(EsimTest, SyncCloseChannel_002, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->currentChannelId_ = 0;
    esimFile->SyncCloseChannel();
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
    EXPECT_EQ(euiccProfileInfoList_.result, esimFile->GetEuiccProfileInfoList().result);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(euiccProfileInfoList_.result, esimFile->GetEuiccProfileInfoList().result);
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
    EXPECT_EQ(eUiccInfo_.osVersion, esimFile->GetEuiccInfo().osVersion);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(eUiccInfo_.osVersion, esimFile->GetEuiccInfo().osVersion);
}

HWTEST_F(EsimTest, CommBuildOneApduReqInfo_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    ApduSimIORequestInfo reqInfo;
    std::shared_ptr<Asn1Builder> builder = std::make_shared<Asn1Builder>(TAG_ESIM_GET_RAT);
    esimFile->CommBuildOneApduReqInfo(reqInfo, builder);
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
    int32_t slotId = 0;
    esimFile->ProcessEsimOpenChannel();
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    esimFile->ProcessEsimOpenChannel();
}

HWTEST_F(EsimTest, ProcessEsimOpenChannel_002, Function | MediumTest | Level2)
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
    std::string src;
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
    std::string responseByte = Asn1Utils::HexStrToBytes(resultData);
    std::shared_ptr<Asn1Node> root = esimFile->Asn1ParseResponse(responseByte, responseByte.length());
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

HWTEST_F(EsimTest, SetVoiceMailNumber_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string mailNumber = "123456";
    esimFile->SetVoiceMailNumber(mailNumber);
}

HWTEST_F(EsimTest, ProcessIccRefresh_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int msgId = 0;
    esimFile->ProcessIccRefresh(msgId);
}

HWTEST_F(EsimTest, ProcessFileLoaded_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    bool response = false;
    esimFile->ProcessFileLoaded(response);
}

HWTEST_F(EsimTest, OnAllFilesFetched_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->OnAllFilesFetched();
}

HWTEST_F(EsimTest, StartLoad_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->StartLoad();
}

HWTEST_F(EsimTest, InitMemberFunc_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    esimFile->InitMemberFunc();
}

HWTEST_F(EsimTest, DisableProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000452301");
    ResultState disableProfileResult = ResultState::RESULT_UNDEFINED_ERROR;
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
    EXPECT_EQ(eUiccRulesAuthTable.position, (esimFile->ObtainRulesAuthTable(portIndex)).position);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(eUiccRulesAuthTable.position, (esimFile->ObtainRulesAuthTable(portIndex)).position);
}

HWTEST_F(EsimTest, ObtainEuiccChallenge_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    ResponseEsimResult responseChallengeResult;
    esimFile->currentChannelId_ = 0;
    EXPECT_EQ(responseChallengeResult.resultCode, (esimFile->ObtainEuiccChallenge(portIndex)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(responseChallengeResult.resultCode, (esimFile->ObtainEuiccChallenge(portIndex)).resultCode);
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
    std::string responseByte;
    responseByte =
        Asn1Utils::HexStrToBytes(resultData);
    int32_t byteLen = responseByte.length();
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
    EXPECT_EQ(responseResult.resultCode, (esimFile->CancelSession(transactionId, cancelReason)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(responseResult.resultCode, (esimFile->CancelSession(transactionId, cancelReason)).resultCode);
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
    EXPECT_EQ(eUiccProfile.state, (esimFile->ObtainProfile(portIndex, iccId)).state);
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(eUiccProfile.state, (esimFile->ObtainProfile(portIndex, iccId)).state);
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

HWTEST_F(EsimTest, ProcessGetProfileDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF2D8184A08181E37F"
        "5A0A89670000000000216954"
        "90046E584754"
        "9103746D6F"
        "92027031"
        "B70F800312F34581030102036945226554"
        "9F700387"
        "950101"
        "990206C0"
        "BF7645E243E135C114ABCD92CBB156B280FA4E1429A6ECEEB6E5C1BFE4"
        "CA1D636F6D2E676F6F676C652E616E64726F69642E617070732E6D79617070"
        "E30ADB080000000000000001"
        "9000";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessGetProfileDone(event));
    auto event1 = AppExecFwk::InnerEvent::Get(0);
    EXPECT_FALSE(esimFile->ProcessGetProfileDone(event1));
    event1 = nullptr;
    EXPECT_FALSE(esimFile->ProcessGetProfileDone(event1));
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
    ResultState resetResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    esimFile->currentChannelId_ = 0;
    EXPECT_NE(resetResult_, esimFile->ResetMemory(resetOption));
    int32_t slotId = 0;
    esimFile->currentChannelId_ = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_NE(resetResult_, esimFile->ResetMemory(resetOption));
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
} // namespace Telephony
} // namespace OHOS