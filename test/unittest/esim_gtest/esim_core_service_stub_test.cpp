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
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "gtest/gtest.h"

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

int32_t EsimCoreServiceStubTest::SendRemoteRequest(MessageParcel &data, CoreServiceInterfaceCode code)
{
    MessageParcel reply;
    MessageOption option;
    return instance_->OnRemoteRequest(static_cast<uint32_t>(code), data, reply, option);
}

HWTEST_F(EsimCoreServiceStubTest, OnGetEid_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::GET_EID);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnGetEuiccProfileInfoList_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::GET_EUICC_PROFILE_INFO_LIST);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnGetEuiccInfo_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::GET_EUICC_INFO);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnDisableProfile_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::DISABLE_PROFILE);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnGetSmdsAddress_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::GET_SMDSADDRESS);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnGetRulesAuthTable_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::GET_RULES_AUTH_TABLE);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnGetEuiccChallenge_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::GET_EUICC_CHALLENGE);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnRequestDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::REQUEST_DEFAULT_SMDP_ADDRESS);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnCancelSession_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::CANCEL_SESSION);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnGetProfile_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::GET_PROFILE);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnResetMemory_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::RESET_MEMORY);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnSetDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::SET_DEFAULT_SMDP_ADDRESS);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimCoreServiceStubTest, OnSendApduData_001, Function | MediumTest | Level2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, CoreServiceInterfaceCode::SEND_APDU_DATA);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS