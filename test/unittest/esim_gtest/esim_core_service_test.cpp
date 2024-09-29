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

HWTEST_F(EsimCoreServiceTest, RetrieveNotificationList_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList;
    EXPECT_NE(mCoreService->RetrieveNotificationList(
        slotId, portIndex, events, notificationList), TELEPHONY_ERR_SUCCESS);

    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->RetrieveNotificationList(
        slotId, portIndex, events, notificationList), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, RetrieveNotification_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    EXPECT_NE(mCoreService->RetrieveNotification(
        slotId, portIndex, seqNumber, notification), TELEPHONY_ERR_SUCCESS);

    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->RetrieveNotification(
        slotId, portIndex, seqNumber, notification), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, RemoveNotificationFromList_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    ResultState removeNotifFromListResult;
    EXPECT_NE(mCoreService->RemoveNotificationFromList(
        slotId, portIndex, seqNumber, removeNotifFromListResult), TELEPHONY_ERR_SUCCESS);

    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->RemoveNotificationFromList(
        slotId, portIndex, seqNumber, removeNotifFromListResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
} // namespace Telephony
} // namespace OHOS