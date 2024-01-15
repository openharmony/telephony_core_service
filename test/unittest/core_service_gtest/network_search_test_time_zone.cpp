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

#include "network_search_manager.h"
#include "network_search_test.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int32_t SLOT_ID_0 = 0;
constexpr int32_t SLOT_ID_1 = 1;

#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_NetworkSearch_FactoryReset_0100
 * @tc.name     Send Cell Location Update
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_FactoryReset_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_0))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().FactoryReset(SLOT_ID_0);
        TELEPHONY_LOGI("TelephonyTestService FactoryReset result: %{public}d", result);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_FactoryReset_0200
 * @tc.name     Send Cell Location Update
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_FactoryReset_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().FactoryReset(SLOT_ID_1);
        TELEPHONY_LOGI("TelephonyTestService FactoryReset result: %{public}d", result);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_FactoryReset_0300
 * @tc.name     Send Cell Location Update without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_FactoryReset_0300, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_0))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    int32_t result = CoreServiceClient::GetInstance().FactoryReset(SLOT_ID_0);
    TELEPHONY_LOGI("TelephonyTestService FactoryReset result: %{public}d", result);
    EXPECT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNrSsbIdInfo_0100
 * @tc.name     Get NR Cell's Ssb Id related info
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNrSsbIdInfo_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_0))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo;
    int32_t result = CoreServiceClient::GetInstance().GetNrSsbIdInfo(SLOT_ID_0, nrCellSsbIdsInfo);
    // Force to set the expected result as failure since incomplete implement in modem.
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    NetworkSearchTest::PrintNrSsbIdInfo(nrCellSsbIdsInfo);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNrSsbIdInfo_0200
 * @tc.name     Get NR Cell's Ssb Id related info
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNrSsbIdInfo_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo;
    int32_t result = CoreServiceClient::GetInstance().GetNrSsbIdInfo(SLOT_ID_1, nrCellSsbIdsInfo);
    // Force to set the expected result as failure since incomplete implement in modem.
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    NetworkSearchTest::PrintNrSsbIdInfo(nrCellSsbIdsInfo);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNrSsbIdInfo_0300
 * @tc.name     Get NR Cell's Ssb Id related info without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNrSsbIdInfo_0300, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_0))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo;
    int32_t result = CoreServiceClient::GetInstance().GetNrSsbIdInfo(SLOT_ID_0, nrCellSsbIdsInfo);
    EXPECT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
    NetworkSearchTest::PrintNrSsbIdInfo(nrCellSsbIdsInfo);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS