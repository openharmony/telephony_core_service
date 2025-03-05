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

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class StkControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StkControllerTest::TearDownTestCase() {}

void StkControllerTest::SetUp() {}

void StkControllerTest::TearDown() {}

void StkControllerTest::SetUpTestCase() {}

HWTEST_F(StkControllerTest, Telephony_Sim_ProcessEvent_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto stkController = std::make_shared<StkController>(telRilManager, simStateManager, 0);
    AppExecFwk::InnerEvent::Pointer event1 = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SESSION_END, 1);
    stkController->ProcessEvent(event1);

    sleep(1);
    AppExecFwk::InnerEvent::Pointer event2 = AppExecFwk::InnerEvent::Get(
        RadioEvent::RADIO_STK_PROACTIVE_COMMAND, 1);
    stkController->ProcessEvent(event2);

    sleep(1);
    AppExecFwk::InnerEvent::Pointer event3 = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_ALPHA_NOTIFY, 1);
    stkController->ProcessEvent(event3);

    sleep(1);
    AppExecFwk::InnerEvent::Pointer event4 = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_EVENT_NOTIFY, 1);
    stkController->ProcessEvent(event4);

    sleep(1);
    AppExecFwk::InnerEvent::Pointer event5 = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_CALL_SETUP, 1);
    stkController->ProcessEvent(event5);

    sleep(1);
    AppExecFwk::InnerEvent::Pointer event6 = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_ICC_REFRESH, 1);
    stkController->ProcessEvent(event6);

    sleep(1);
    AppExecFwk::InnerEvent::Pointer event7 = AppExecFwk::InnerEvent::Get(
        RadioEvent::RADIO_STK_SEND_TERMINAL_RESPONSE, 1);
    stkController->ProcessEvent(event7);

    sleep(1);
    AppExecFwk::InnerEvent::Pointer event8 = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_ENVELOPE, 1);
    stkController->ProcessEvent(event8);

    sleep(1);
    stkController->remainTryCount_ = 1;
    AppExecFwk::InnerEvent::Pointer event9 = AppExecFwk::InnerEvent::Get(
        StkController::RETRY_SEND_RIL_PROACTIVE_COMMAND, 1);
    stkController->ProcessEvent(event9);

    sleep(1);
    AppExecFwk::InnerEvent::Pointer event10 = AppExecFwk::InnerEvent::Get(0, 1);
    stkController->ProcessEvent(event10);
    EXPECT_EQ(stkController->remainTryCount_, -1);
}
}
}