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

#include "core_service_ipc_interface_code.h"
#include "esim_core_service_stub_test.h"
#include "gtest/gtest.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

using namespace testing::ext;
namespace OHOS {
namespace Telephony {
class EsimCoreServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<CoreServiceStub> instance_ = std::make_shared<MockCoreServiceStub>();
    static int32_t SendRemoteRequest(MessageParcel &data, CoreServiceInterfaceCode code);
};

void EsimCoreServiceStubTest::SetUpTestCase() {}

void EsimCoreServiceStubTest::TearDownTestCase() {}

void EsimCoreServiceStubTest::SetUp() {}

void EsimCoreServiceStubTest::TearDown() {}

HWTEST_F(EsimCoreServiceStubTest, OnPrepareDownload_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::PREPARE_DOWNLOAD);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnLoadBoundProfilePackage_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::LOAD_BOUND_PROFILE_PACKAGE);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnListNotifications_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::LIST_NOTIFICATIONS);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}
}
}