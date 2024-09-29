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

HWTEST_F(EsimTest, ObtainDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);
    std::string defaultDpAddress_ = "";
    esimFile->currentChannelId = 0;
    EXPECT_EQ(defaultDpAddress_, esimFile->ObtainDefaultSmdpAddress());
    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
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
    esimFile->currentChannelId = 0;
    EXPECT_EQ(responseResult.resultCode, (esimFile->CancelSession(transactionId, cancelReason)).resultCode);
    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
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
    std::u16string iccId = Str8ToStr16("5A0A89670000000000452301");
    EuiccProfile eUiccProfile;
    esimFile->currentChannelId = 0;
    EXPECT_EQ(eUiccProfile.state, (esimFile->ObtainProfile(portIndex, iccId)).state);
    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
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
    esimFile->currentChannelId = 0;
    EXPECT_FALSE(esimFile->ProcessObtainDefaultSmdpAddress(slotId, eventSmdpAddress));
    esimFile->currentChannelId = 2;
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
    rcvMsg->fileData.resultData = "BF3C148008534D44502E434F4D8108736D64732E636F6D9000";
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
    esimFile->currentChannelId = 0;
    EXPECT_FALSE(esimFile->ProcessCancelSession(slotId, eventCancelSession));
    esimFile->currentChannelId = 2;
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
    rcvMsg1->fileData.resultData = "BF4106810400000001";
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
    esimFile->currentChannelId = 0;
    EXPECT_FALSE(esimFile->ProcessGetProfile(slotId, eventGetProfile));
    esimFile->currentChannelId = 2;
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
        "5A0A89670000000000452301"
        "90046E69636B"
        "9103746D6F"
        "92027031"
        "B70F800312F34581030102038203040506"
        "9F700101"
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
} // namespace Telephony
} // namespace OHOS