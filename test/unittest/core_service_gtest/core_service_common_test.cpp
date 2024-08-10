/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <string_ex.h>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_service.h"
#include "core_service_client.h"
#include "core_service_dump_helper.h"
#include "core_service_hisysevent.h"
#include "network_search_manager.h"
#include "operator_name.h"
#include "operator_name_utils.h"
#include "security_token.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int32_t NR_NSA_OPTION_ONLY = 1;
static const int32_t SLEEP_TIME = 3;
class CoreServiceCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void CoreServiceCommonTest::SetUpTestCase() {}

void CoreServiceCommonTest::TearDownTestCase()
{
    sleep(SLEEP_TIME);
}

void CoreServiceCommonTest::SetUp() {}

void CoreServiceCommonTest::TearDown() {}

/**
 * @tc.number   CoreService_SetNrOptionMode_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_SetNrOptionMode_001, Function | MediumTest | Level1)
{
    int32_t mode = NR_NSA_OPTION_ONLY;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetNrOptionMode(0, mode, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   CoreService_SetNrOptionMode_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_SetNrOptionMode_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t mode = NR_NSA_OPTION_ONLY;
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = nullptr;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetNrOptionMode(0, mode, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetCellInfoList_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetCellInfoList_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = nullptr;
    std::vector<sptr<CellInformation>> cellInfo;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetCellInfoList(0, cellInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_InitExtraModule_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_InitExtraModule_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->InitExtraModule(0);
    ASSERT_EQ(result, TELEPHONY_ERROR);
}

/**
 * @tc.number   CoreService_GetNrSsbIdInfo_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetNrSsbIdInfo_001, Function | MediumTest | Level1)
{
    std::shared_ptr<NrSsbInformation> nrSsbInformation;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNrSsbIdInfo(0, nrSsbInformation);
    ASSERT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   CoreService_GetNrSsbIdInfo_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetNrSsbIdInfo_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = nullptr;
    std::shared_ptr<NrSsbInformation> nrSsbInformation;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNrSsbIdInfo(0, nrSsbInformation);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetNrSsbIdInfo_003
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetNrSsbIdInfo_003, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::shared_ptr<NrSsbInformation> nrSsbInformation;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNrSsbIdInfo(0, nrSsbInformation);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_IsAllowedInsertApn_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_IsAllowedInsertApn_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::string value = "";
    auto result = DelayedSingleton<CoreService>::GetInstance()->IsAllowedInsertApn(value);
    ASSERT_EQ(result, true);
}

/**
 * @tc.number   CoreService_GetTargetOpkey_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetTargetOpkey_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string value = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetTargetOpkey(0, value);
    ASSERT_EQ(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   CoreService_GetOpkeyVersion_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetOpkeyVersion_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::string versionInfo = "";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetOpkeyVersion(versionInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetSimIO_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetSimIO_001, Function | MediumTest | Level1)
{
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "";
    std::string path = "";
    SimAuthenticationResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimIO(0, command, fileId, data, path, response);
    ASSERT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   CoreService_GetSimIO_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetSimIO_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "";
    std::string path = "";
    SimAuthenticationResponse response;
    DelayedSingleton<CoreService>::GetInstance()->simManager_ = nullptr;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimIO(0, command, fileId, data, path, response);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetSimIO_003
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetSimIO_003, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "";
    std::string path = "";
    SimAuthenticationResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimIO(0, command, fileId, data, path, response);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}
} // namespace Telephony
} // namespace OHOS