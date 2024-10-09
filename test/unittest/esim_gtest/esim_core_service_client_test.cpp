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
#include "securec.h"

#include "core_service_client.h"
#include "esim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "gtest/gtest.h"

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

HWTEST_F(EsimCoreServiceClientTest, RetrieveNotificationList_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList;
    int32_t result = CoreServiceClient::GetInstance().RetrieveNotificationList(
        slotId, portIndex, events, notificationList);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
}

HWTEST_F(EsimCoreServiceClientTest, RetrieveNotification_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    int32_t result = CoreServiceClient::GetInstance().RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
}

HWTEST_F(EsimCoreServiceClientTest, RemoveNotificationFromList_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    ResultState enumResult;
    int32_t result = CoreServiceClient::GetInstance().RemoveNotificationFromList(
        slotId, portIndex, seqNumber, enumResult);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS