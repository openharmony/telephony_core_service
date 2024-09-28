/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "if_system_ability_manager_mock.h"
#include "iservice_registry.h"
#include "securec.h"
#include "str_convert.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimCoreServiceClientBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<ISystemAbilityManagerMock> samgr = std::make_shared<ISystemAbilityManagerMock>();
};

void EsimCoreServiceClientBranchTest::SetUpTestCase()
{
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = sptr<ISystemAbilityManager>(samgr.get());
}

void EsimCoreServiceClientBranchTest::TearDownTestCase()
{
    samgr = nullptr;
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = nullptr;
}

void EsimCoreServiceClientBranchTest::SetUp() {}

void EsimCoreServiceClientBranchTest::TearDown() {}

HWTEST_F(EsimCoreServiceClientBranchTest, RequestDefaultSmdpAddress_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string address = Str8ToStr16("SMDP.COM");
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetDefaultSmdpAddress(slotId, address);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, CancelSession_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result =
        CoreServiceClient::GetInstance().CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, GetProfile_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000452301");
    EuiccProfile eUiccProfile;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}
}
}