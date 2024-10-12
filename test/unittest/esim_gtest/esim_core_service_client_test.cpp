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

#include "core_service_client.h"
#include "esim_state_type.h"
#include "gtest/gtest.h"
#include "securec.h"
#include "str_convert.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimCoreServiceClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimCoreServiceClientTest::SetUpTestCase() {}

void EsimCoreServiceClientTest::TearDownTestCase() {}

void EsimCoreServiceClientTest::SetUp() {}

void EsimCoreServiceClientTest::TearDown() {}

HWTEST_F(EsimCoreServiceClientTest, RequestDefaultSmdpAddress_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string address = Str8ToStr16("test.com");
    int32_t result = CoreServiceClient::GetInstance().GetDefaultSmdpAddress(slotId, address);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
}

HWTEST_F(EsimCoreServiceClientTest, CancelSession_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimResult responseResult;
    int32_t result = CoreServiceClient::GetInstance().CancelSession(
        slotId, transactionId, cancelReason, responseResult);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
}

HWTEST_F(EsimCoreServiceClientTest, GetProfile_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000216954");
    EuiccProfile eUiccProfile;
    int32_t result = CoreServiceClient::GetInstance().GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS