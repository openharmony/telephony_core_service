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

#include "core_service.h"
#include "esim_state_type.h"
#include "gmock/gmock.h"
#include "string_ex.h"
#include "str_convert.h"
#include "sim_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimCoreServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimCoreServiceTest::SetUpTestCase() {}

void EsimCoreServiceTest::TearDownTestCase() {}

void EsimCoreServiceTest::SetUp() {}

void EsimCoreServiceTest::TearDown() {}


HWTEST_F(EsimCoreServiceTest, SendApduData_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    std::u16string aid = Str8ToStr16("aid test");
    EsimApduData apduData;
    ResponseEsimResult responseResult;
    EXPECT_NE(mCoreService->SendApduData(
        slotId, aid, apduData, responseResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->SendApduData(
        slotId, aid, apduData, responseResult), TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

}
} // namespace Telephony
} // namespace OHOS