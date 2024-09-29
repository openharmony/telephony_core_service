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

HWTEST_F(EsimTest, DisableProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000452301");
    ResultState disableProfileResult = ResultState::RESULT_UNDEFINED_ERROR;
    esimFile->currentChannelId = 0;
    EXPECT_NE(disableProfileResult, esimFile->DisableProfile(portIndex, iccId));
    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_NE(disableProfileResult, esimFile->DisableProfile(portIndex, iccId));
    esimFile->currentChannelId = 2;
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
    esimFile->currentChannelId = 0;
    EXPECT_FALSE(esimFile->ProcessDisableProfile(slotId, eventGetProfile));
    esimFile->currentChannelId = 2;
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
    esimFile->currentChannelId = 0;
    EXPECT_EQ(smdsAddress, esimFile->ObtainSmdsAddress(portIndex));
    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
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
    esimFile->currentChannelId = 0;
    EXPECT_EQ(eUiccRulesAuthTable.position, (esimFile->ObtainRulesAuthTable(portIndex)).position);
    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
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
    esimFile->currentChannelId = 0;
    EXPECT_EQ(responseChallengeResult.resultCode, (esimFile->ObtainEuiccChallenge(portIndex)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
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
    esimFile->currentChannelId = 1;
    EXPECT_FALSE(esimFile->ProcessRequestRulesAuthTable(slotId, eventRequestRulesAuthTable));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessRequestRulesAuthTable(slotId, eventRequestRulesAuthTable));
    esimFile->currentChannelId = 0;
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
    esimFile->currentChannelId = 0;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
    esimFile->currentChannelId = 2;
    EXPECT_FALSE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_TRUE(esimFile->ProcessObtainSmdsAddress(slotId, eventObtainSmdsAddress));
}

HWTEST_F(EsimTest, ProcessObtainEUICCChallenge_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    int slotId = 0;
    std::shared_ptr<Telephony::IccFile> iccFile = std::make_shared<EsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer eventEUICCChanllenge =
        iccFile->BuildCallerInfo(MSG_ESIM_OBTAIN_EUICC_CHALLENGE_DONE);
    esimFile->currentChannelId = 0;
    EXPECT_EQ(esimFile->ProcessObtainEUICCChallenge(slotId, eventEUICCChanllenge), false);
    esimFile->currentChannelId = 2;
    EXPECT_EQ(esimFile->ProcessObtainEUICCChallenge(slotId, eventEUICCChanllenge), false);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_EQ(esimFile->ProcessObtainEUICCChallenge(slotId, eventEUICCChanllenge), true);
}

HWTEST_F(EsimTest, ProcessObtainEUICCChallengeDone_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::shared_ptr<IccControllerHolder> holder = nullptr;
    std::unique_ptr<Telephony::IccFromRilMsg> rcvMsg = std::make_unique<Telephony::IccFromRilMsg>(holder);
    rcvMsg->fileData.resultData = "BF2E1280105DAD74D9F1734CF96CDE5C78FDB0565B";
    auto event = AppExecFwk::InnerEvent::Get(0, rcvMsg);
    EXPECT_TRUE(esimFile->ProcessObtainEUICCChallengeDone(event));
    auto eventEUICCChanllenge = AppExecFwk::InnerEvent::Get(0);
    EXPECT_EQ(esimFile->ProcessObtainEUICCChallengeDone(eventEUICCChanllenge), false);
    eventEUICCChanllenge = nullptr;
    EXPECT_EQ(esimFile->ProcessObtainEUICCChallengeDone(eventEUICCChanllenge), false);
}
} // namespace Telephony
} // namespace OHOS