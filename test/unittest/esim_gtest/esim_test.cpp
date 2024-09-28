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

HWTEST_F(EsimTest, DeleteProfile_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::u16string iccId;
    ResultState disableProfileResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    esimFile->currentChannelId = 0;
    EXPECT_NE(disableProfileResult_, esimFile->DeleteProfile(iccId));

    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
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
    bool forceDeactivateSim = false;
    ResultState switchResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    esimFile->currentChannelId = 0;
    EXPECT_NE(switchResult_, esimFile->SwitchToProfile(portIndex, iccId, forceDeactivateSim));

    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    esimFile->SetRilAndFileController(telRilManager, file, handler);
    EXPECT_NE(switchResult_, esimFile->SwitchToProfile(portIndex, iccId, forceDeactivateSim));
}

HWTEST_F(EsimTest, SetProfileNickname_001, Function | MediumTest | Level2)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::EsimFile> esimFile = std::make_shared<EsimFile>(simStateManager);

    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    ResultState updateNicknameResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    esimFile->currentChannelId = 0;
    EXPECT_NE(updateNicknameResult_, esimFile->SetProfileNickname(iccId, nickname));

    int32_t slotId = 0;
    esimFile->currentChannelId = 2;
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
    
    esimFile->currentChannelId = 0;
    EXPECT_FALSE(esimFile->ProcessDeleteProfile(slotId, eventDeleteProfile));

    esimFile->currentChannelId = 2;
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
    
    esimFile->currentChannelId = 0;
    EXPECT_FALSE(esimFile->ProcessSwitchToProfile(slotId, eventSwitchToProfile));

    esimFile->currentChannelId = 2;
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
    esimFile->currentChannelId = 0;
    EXPECT_FALSE(esimFile->ProcessSetNickname(slotId, eventSetNickName));

    esimFile->currentChannelId = 2;
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
} // namespace Telephony
} // namespace OHOS