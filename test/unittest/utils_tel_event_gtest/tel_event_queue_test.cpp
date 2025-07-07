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

#include "tel_event_queue.h"
#include "tel_event_handler.h"
#include <fcntl.h>
#include
#include <gtest/gtest.h>
#include <gmock/gmock.h>
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT

class TelEventQueueTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void TelEventQueueTest::SetUpTestCase() {}

void TelEventQueueTest::TearDownTestCase() {}

void TelEventQueueTest::SetUp() {}

void TelEventQueueTest::TearDown() {}

/**
 * @tc.number SubmitToFFRT_001
 * @tc.name test function branch
 * @tc.desc Function test
 */
HWTEST_F(TelEventQueueTest, SubmitToFFRT_001, Function | MediumTest | Level0)
{
    std::shared_ptr telEventQueue = std::make_shared("TelEventQueue");
    auto event = AppExecFwk::InnerEvent::Get(31);
    std::shared_ptr telEventHandler = std::make_shared("TelEventHandler");
    event->SetOwner(telEventHandler);
    int32_t queueId = telEventQueue->queueId_;
    telEventQueue->InsertEventsInner(event, AppExecFwk::EventQueue::Priority::LOW);
    AppExecFwk::InnerEvent::TimePoint now = AppExecFwk::InnerEvent::Clock::now();
    telEventQueue->SubmitToFFRT(telEventQueue->queueId_, now, 0);
    EXPECT_EQ(queueId, telEventQueue->queueId_);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS