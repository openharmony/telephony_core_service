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
#include "gtest/gtest.h"
#include "icc_file.h"
#include "sim_file_manager.h"
#include "sim_constant.h"
#include "sim_file_manager.h"
#include "tel_ril_manager.h"
#include "telephony_tag_def.h"

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
} // namespace Telephony
} // namespace OHOS