/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "sim_manager.h"
#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"
#include "gtest/gtest.h"
#include "tel_ril_manager.h"
#include "mock_tel_ril_manager.h"
#include "sim_constant.h"
#include "icc_dialling_numbers_handler.h"
#include "icc_file_controller.h"
#include "isim_file.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;

class RuimFileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void RuimFileTest::SetUpTestCase() {}

void RuimFileTest::TearDownTestCase() {}

void RuimFileTest::SetUp() {}

void RuimFileTest::TearDown() {}

HWTEST_F(RuimFileTest, RuimFileTest001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<RuimFile> ruimFile = std::make_shared<RuimFile>(simStateManager);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    ruimFile->SetRilAndFileController(telRilManager, file, handler);
    ruimFile->StartLoad();
    int32_t validEventId = 0x03;
    int32_t invalidEventId = 0xFFFF78;
    auto validEvent = AppExecFwk::InnerEvent::Get(validEventId);
    auto invalidEvent = AppExecFwk::InnerEvent::Get(invalidEventId);
    auto nullEvent = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    ruimFile->InitMemberFunc();
    ruimFile->ProcessEvent(validEvent);
    ruimFile->ProcessEvent(invalidEvent);
    ruimFile->ProcessIccRefresh(0);
    ruimFile->ProcessFileLoaded(false);
    ruimFile->ProcessFileLoaded(true);
    ruimFile->ProcessLockedAllFilesFetched();
    ruimFile->OnAllFilesFetched();
    ruimFile->ProcessIccReady(validEvent);
    ruimFile->ProcessIccLocked(validEvent);
    ruimFile->LoadRuimFiles();
    ruimFile->ProcessGetSubscriptionDone(nullEvent);
    ruimFile->ProcessGetIccidDone(nullEvent);
    ruimFile->ProcessGetIccidDone(validEvent);
    ruimFile->ProcessGetImsiDone(nullEvent);
    ruimFile->ProcessGetImsiDone(validEvent);
    ruimFile->ObtainMdnNumber();
    ruimFile->ObtainCdmaMin();
    ruimFile->ObtainPrlVersion();
    ruimFile->ObtainNAI();
    ruimFile->ObtainMdn();
    ruimFile->ObtainMin();
    ruimFile->ObtainSid();
    ruimFile->ObtainNid();
    ruimFile->ObtainCsimSpnDisplayCondition();
    ruimFile->ProcessGetSpnDone(validEvent);
    EXPECT_TRUE(ruimFile->ProcessGetSpnDone(nullEvent));
}

HWTEST_F(RuimFileTest, RuimFileTest002, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<RuimFile> ruimFile = std::make_shared<RuimFile>(simStateManager);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    ruimFile->SetRilAndFileController(telRilManager, file, handler);
    ruimFile->StartLoad();
    int32_t validEventId = 0x03;
    int32_t invalidEventId = 0xFFFF78;
    auto validEvent = AppExecFwk::InnerEvent::Get(validEventId);
    auto invalidEvent = AppExecFwk::InnerEvent::Get(invalidEventId);
    auto nullEvent = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    unsigned char spnNameArr[] = "cnNet";
    unsigned char const *spnName = static_cast<unsigned char const *>(spnNameArr);
    std::string operatorNum, mailName, mailNumber;
    ruimFile->ParseSpnName(CSIM_SPN_OCTET, spnName, 5);
    ruimFile->ParseSpnName(CSIM_SPN_LATIN, spnName, 5);
    ruimFile->ParseSpnName(CSIM_SPN_IA5, spnName, 5);
    ruimFile->ParseSpnName(CSIM_SPN_7BIT_ALPHABET, spnName, 5);
    ruimFile->ParseSpnName(CSIM_SPN_7BIT_ASCII, spnName, 5);
    ruimFile->ParseSpnName(CSIM_SPN_IA5, spnName, 5);
    ruimFile->ObtainSpnCondition(true, operatorNum);
    ruimFile->UpdateVoiceMail(mailName, mailNumber);
    EXPECT_TRUE(ruimFile->ProcessGetSpnDone(nullEvent));
}

HWTEST_F(RuimFileTest, RuimFileControllerTest001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<RuimFile> ruimFile = std::make_shared<RuimFile>(simStateManager);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    ruimFile->SetRilAndFileController(telRilManager, file, handler);
    std::shared_ptr<RuimFileController> ruimFileController = std::make_shared<RuimFileController>(slotId);
    ruimFileController->ObtainElementFilePath(ELEMENTARY_FILE_USIM_ADN);
    EXPECT_NE(ruimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SMS).c_str(), nullptr);
}

}
}
