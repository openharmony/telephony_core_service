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
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"
#include "gtest/gtest.h"
#include "sim_constant.h"
#include "usim_dialling_numbers_service.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;

class UsimDiallingNumbersServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void UsimDiallingNumbersServiceTest::SetUpTestCase() {}

void UsimDiallingNumbersServiceTest::TearDownTestCase() {}

void UsimDiallingNumbersServiceTest::SetUp() {}

void UsimDiallingNumbersServiceTest::TearDown() {}

HWTEST_F(UsimDiallingNumbersServiceTest, ProcessEventTest001, Function | MediumTest | Level1)
{
    auto usimDiallingNumbersService = std::make_shared<UsimDiallingNumbersService>();
    usimDiallingNumbersService->InitFuncMap();
    int32_t invalidEventId = 0xFF3807;
    auto event1 = AppExecFwk::InnerEvent::Get(MSG_USIM_PBR_LOAD_DONE);
    auto event2 = AppExecFwk::InnerEvent::Get(invalidEventId);
    usimDiallingNumbersService->ProcessEvent(event1);
    usimDiallingNumbersService->ProcessEvent(event2);
    std::unique_ptr<ControllerToFileMsg> obj;
    event1->SaveUniquePtr<std::unique_ptr<ControllerToFileMsg>>(obj);
    usimDiallingNumbersService->ProcessEvent(event1);
    EXPECT_FALSE(usimDiallingNumbersService->memberFuncMap_.empty());
}

HWTEST_F(UsimDiallingNumbersServiceTest, LoadPbrFilesTest001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    auto usimDiallingNumbersService = std::make_shared<UsimDiallingNumbersService>();
    usimDiallingNumbersService->InitFuncMap();
    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(slotId);
    std::shared_ptr<IccDiallingNumbersHandler> handler = std::make_shared<IccDiallingNumbersHandler>(file);
    usimDiallingNumbersService->SetFileControllerAndDiallingNumberHandler(file, handler);
    usimDiallingNumbersService->LoadPbrFiles();
    EXPECT_NE(usimDiallingNumbersService->fileController_, nullptr);
}

}
}
