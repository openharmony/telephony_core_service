/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "core_service_client.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include "telephony_data_helper.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "mock_remote_object.h"
#include "telephony_state_registry_proxy.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
static const int32_t SLEEP_TIME = 3;
} // namespace

class BranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BranchTest::TearDownTestCase()
{
    sleep(SLEEP_TIME);
}

void BranchTest::SetUp() {}

void BranchTest::TearDown() {}

void BranchTest::SetUpTestCase() {}

/**
 * @tc.name: Telephony_ProxyUpdateSimActiveState
 * @tc.desc: proxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BranchTest, Telephony_ProxyUpdateSimActiveState, Function | MediumTest | Level1)
{
    sptr<TEST::MockRemoteObject> sptrRemoteObj = new TEST::MockRemoteObject();
    EXPECT_FALSE(sptrRemoteObj == nullptr);
    std::shared_ptr<TelephonyStateRegistryProxy> proxy =
        std::make_shared<TelephonyStateRegistryProxy>(sptrRemoteObj);
    EXPECT_FALSE(proxy == nullptr);
    EXPECT_FALSE(proxy->UpdateSimActiveState(0, true) == 0);
}
} // namespace Telephony
} // namespace OHOS
