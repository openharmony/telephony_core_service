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
#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_manager.h"
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
#include "isim_file_controller.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;

class ISimFileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void ISimFileTest::SetUpTestCase() {}

void ISimFileTest::TearDownTestCase() {}

void ISimFileTest::SetUp() {}

void ISimFileTest::TearDown() {}

HWTEST_F(ISimFileTest, ISimFileTest001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IsimFile> iSimFile = std::make_shared<IsimFile>(simStateManager);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    iSimFile->SetRilAndFileController(telRilManager, file, handler);
    int32_t validEventId = 0x03;
    int32_t invalidEventId = 0xFFFF78;
    iSimFile->StartLoad();
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(validEventId);
    iSimFile->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(invalidEventId);
    iSimFile->ProcessEvent(event);
    iSimFile->ProcessFileLoaded(true);
    iSimFile->ProcessFileLoaded(false);
    iSimFile->ProcessLockedAllFilesFetched();
    iSimFile->OnAllFilesFetched();
    EXPECT_FALSE(iSimFile->ProcessIccReady(event));
}

HWTEST_F(ISimFileTest, ISimFileTest002, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IsimFile> iSimFile = std::make_shared<IsimFile>(simStateManager);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    iSimFile->SetRilAndFileController(telRilManager, file, handler);
    iSimFile->LoadIsimFiles();
    int32_t validEventId = 0x03;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(validEventId);
    auto nullEvent = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    iSimFile->ProcessGetIccidDone(event);
    iSimFile->ProcessGetIccidDone(nullEvent);
    iSimFile->ProcessGetImsiDone(event);
    iSimFile->ProcessGetImsiDone(nullEvent);
    iSimFile->ProcessGetImpiDone(event);
    iSimFile->ProcessGetImpiDone(nullEvent);
    iSimFile->ProcessGetIstDone(event);
    iSimFile->ProcessGetIstDone(nullEvent);
    iSimFile->ObtainIsimImpi();
    iSimFile->ObtainIsimDomain();
    iSimFile->ObtainIsimImpu();
    iSimFile->ObtainIsimPcscf();
    std::string mailName, mailNumber;
    iSimFile->UpdateVoiceMail(mailName, mailNumber);
    iSimFile->SetVoiceMailCount(0);
    iSimFile->SetVoiceCallForwarding(true, mailNumber);
    iSimFile->ObtainSpnCondition(true, mailNumber);
    iSimFile->ObtainIsoCountryCode();
    iSimFile->SetVoiceMailNumber(mailNumber);
    iSimFile->GetVoiceMailNumber();
    EXPECT_FALSE(iSimFile->ProcessIsimRefresh(nullEvent));
}

HWTEST_F(ISimFileTest, ISimFileControllerTest001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IsimFile> iSimFile = std::make_shared<IsimFile>(simStateManager);
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    iSimFile->SetRilAndFileController(telRilManager, file, handler);
    std::shared_ptr<IsimFileController> iSimFileController = std::make_shared<IsimFileController>(slotId);
    iSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_USIM_ADN);
    EXPECT_NE(iSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_IMPI).c_str(), nullptr);
}

}
}
