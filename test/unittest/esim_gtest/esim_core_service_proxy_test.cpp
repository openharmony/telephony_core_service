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

#include <chrono>
#include <thread>

#include "core_service_proxy.h"
#include "esim_state_type.h"
#include "gmock/gmock.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "gtest/gtest.h"

namespace OHOS {
class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u"mock_i_remote_object") {}

    ~MockIRemoteObject() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    MOCK_METHOD4(SendRequest, int(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};
} // namespace OHOS

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int32_t SLOT_ID = 0;
class EsimCoreServiceProxyTest : public testing::Test {
public:
    int32_t slotId_ = 0;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimCoreServiceProxyTest::TearDownTestCase() {}

void EsimCoreServiceProxyTest::SetUp() {}

void EsimCoreServiceProxyTest::TearDown() {}

void EsimCoreServiceProxyTest::SetUpTestCase() {}

HWTEST_F(EsimCoreServiceProxyTest, GetEid_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    std::u16string eId;
    EXPECT_EQ(proxy.GetEid(SLOT_ID, eId), TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEid_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string eId;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_EQ(proxy.GetEid(SLOT_ID, eId), TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEid_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string eId;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.GetEid(SLOT_ID, eId), 0);
}

HWTEST_F(EsimCoreServiceProxyTest, ReadEuiccProfileFromReply_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    MessageParcel reply;
    EuiccProfile euiccProfile;
    proxy.ReadEuiccProfileFromReply(reply, euiccProfile);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccProfileInfoList_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    int32_t ret = proxy.GetEuiccProfileInfoList(SLOT_ID, euiccProfileInfoList);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccProfileInfoList_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.GetEuiccProfileInfoList(SLOT_ID, euiccProfileInfoList);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccProfileInfoList_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.GetEuiccProfileInfoList(SLOT_ID, euiccProfileInfoList);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccInfo_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    EuiccInfo eUiccInfo;
    int32_t ret = proxy.GetEuiccInfo(SLOT_ID, eUiccInfo);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccInfo_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    EuiccInfo eUiccInfo;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.GetEuiccInfo(SLOT_ID, eUiccInfo);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccInfo_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    EuiccInfo eUiccInfo;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.GetEuiccInfo(SLOT_ID, eUiccInfo);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, DisableProfile_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    ResultState DisableProfileResult;
    int32_t ret = proxy.DisableProfile(SLOT_ID, portIndex, iccId, refresh, DisableProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, DisableProfile_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    ResultState DisableProfileResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.DisableProfile(SLOT_ID, portIndex, iccId, refresh, DisableProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, DisableProfile_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    ResultState DisableProfileResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.DisableProfile(SLOT_ID, portIndex, iccId, refresh, DisableProfileResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, GetSmdsAddress_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    int32_t ret = proxy.GetSmdsAddress(SLOT_ID, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetSmdsAddress_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.GetSmdsAddress(SLOT_ID, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetSmdsAddress_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.GetSmdsAddress(SLOT_ID, portIndex, smdsAddress);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, ParseRulesAuthTableReply_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    MessageParcel reply;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    int32_t ret = proxy.ParseRulesAuthTableReply(reply, eUiccRulesAuthTable);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, GetRulesAuthTable_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    int32_t ret = proxy.GetRulesAuthTable(SLOT_ID, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetRulesAuthTable_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.GetRulesAuthTable(SLOT_ID, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetRulesAuthTable_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.GetRulesAuthTable(SLOT_ID, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccChallenge_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    ResponseEsimResult responseResult;
    int32_t ret = proxy.GetEuiccChallenge(SLOT_ID, portIndex, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccChallenge_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.GetEuiccChallenge(SLOT_ID, portIndex, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccChallenge_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.GetEuiccChallenge(SLOT_ID, portIndex, responseResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, RequestDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    std::u16string defaultSmdpAddress;
    int32_t ret = proxy.GetDefaultSmdpAddress(SLOT_ID, defaultSmdpAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, RequestDefaultSmdpAddress_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string defaultSmdpAddress;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.GetDefaultSmdpAddress(SLOT_ID, defaultSmdpAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, RequestDefaultSmdpAddress_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string defaultSmdpAddress;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.GetDefaultSmdpAddress(SLOT_ID, defaultSmdpAddress);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, CancelSession_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimResult responseResult;
    int32_t ret = proxy.CancelSession(SLOT_ID, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, CancelSession_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.CancelSession(SLOT_ID, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, CancelSession_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.CancelSession(SLOT_ID, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, GetProfile_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string iccId;
    EuiccProfile eUiccProfile;
    int32_t ret = proxy.GetProfile(SLOT_ID, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetProfile_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string iccId;
    EuiccProfile eUiccProfile;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.GetProfile(SLOT_ID, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetProfile_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string iccId;
    EuiccProfile eUiccProfile;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.GetProfile(SLOT_ID, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, ResetMemory_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);

    ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    ResultState resetMemoryResult;
    int32_t ret = proxy.ResetMemory(SLOT_ID, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, ResetMemory_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    ResultState resetMemoryResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.ResetMemory(SLOT_ID, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, ResetMemory_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    ResultState resetMemoryResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.ResetMemory(SLOT_ID, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, SetDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    ResultState setAddressResult;
    int32_t ret = proxy.SetDefaultSmdpAddress(SLOT_ID, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SetDefaultSmdpAddress_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    ResultState setAddressResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.SetDefaultSmdpAddress(SLOT_ID, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SetDefaultSmdpAddress_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    ResultState setAddressResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.SetDefaultSmdpAddress(SLOT_ID, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, IsEsimSupported_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    EXPECT_FALSE(proxy.IsEsimSupported(SLOT_ID));
}

HWTEST_F(EsimCoreServiceProxyTest, IsEsimSupported_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_FALSE(proxy.IsEsimSupported(SLOT_ID));
}

HWTEST_F(EsimCoreServiceProxyTest, IsEsimSupported_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_FALSE(proxy.IsEsimSupported(SLOT_ID));
}

HWTEST_F(EsimCoreServiceProxyTest, SendApduData_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    std::u16string aid = Str8ToStr16("aid test");
    std::u16string apduData = Str8ToStr16("apduData test");
    ResponseEsimResult responseResult;
    std::u16string eId;
    EXPECT_EQ(proxy.SendApduData(SLOT_ID, aid, apduData, responseResult), TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SendApduData_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string aid = Str8ToStr16("aid test");
    std::u16string apduData = Str8ToStr16("apduData test");
    ResponseEsimResult responseResult;
    std::u16string eId;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_EQ(proxy.SendApduData(SLOT_ID, aid, apduData, responseResult), TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SendApduData_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string aid = Str8ToStr16("aid test");
    std::u16string apduData = Str8ToStr16("apduData test");
    ResponseEsimResult responseResult;
    std::u16string eId;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.SendApduData(SLOT_ID, aid, apduData, responseResult), 0);
}

HWTEST_F(EsimCoreServiceProxyTest, PrepareDownload_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex = 0;
    downLoadConfigInfo.hashCc = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    EXPECT_EQ(proxy.PrepareDownload(SLOT_ID, downLoadConfigInfo, responseResult), TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, PrepareDownload_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex = 0;
    downLoadConfigInfo.hashCc = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_EQ(proxy.PrepareDownload(SLOT_ID, downLoadConfigInfo, responseResult), TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, PrepareDownload_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex = 0;
    downLoadConfigInfo.hashCc = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.PrepareDownload(SLOT_ID, downLoadConfigInfo, responseResult), 0);
}

HWTEST_F(EsimCoreServiceProxyTest, LoadBoundProfilePackage_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string boundProfilePackage;
    ResponseEsimBppResult responseResult;
    EXPECT_EQ(proxy.LoadBoundProfilePackage(SLOT_ID, portIndex, boundProfilePackage, responseResult),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, LoadBoundProfilePackage_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string boundProfilePackage;
    ResponseEsimBppResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_EQ(proxy.LoadBoundProfilePackage(SLOT_ID, portIndex, boundProfilePackage, responseResult),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, LoadBoundProfilePackage_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    std::u16string boundProfilePackage;
    ResponseEsimBppResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.LoadBoundProfilePackage(SLOT_ID, portIndex, boundProfilePackage, responseResult), 0);
}

HWTEST_F(EsimCoreServiceProxyTest, ListNotifications_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList;
    std::u16string boundProfilePackage;
    ResponseEsimResult responseResult;
    EXPECT_EQ(proxy.ListNotifications(SLOT_ID, portIndex, events, notificationList),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, ListNotifications_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList;
    std::u16string boundProfilePackage;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_EQ(proxy.ListNotifications(SLOT_ID, portIndex, events, notificationList),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, ListNotifications_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList;
    std::u16string boundProfilePackage;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.ListNotifications(SLOT_ID, portIndex, events, notificationList), 0);
}

HWTEST_F(EsimCoreServiceProxyTest, RetrieveNotificationList_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DISABLE;
    EuiccNotificationList notificationList;
    EXPECT_EQ(proxy.RetrieveNotificationList(SLOT_ID, portIndex, events, notificationList),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, RetrieveNotificationList_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DISABLE;
    EuiccNotificationList notificationList;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_EQ(proxy.RetrieveNotificationList(SLOT_ID, portIndex, events, notificationList),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, RetrieveNotificationList_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DISABLE;
    EuiccNotificationList notificationList;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.RetrieveNotificationList(SLOT_ID, portIndex, events, notificationList), 0);
}

HWTEST_F(EsimCoreServiceProxyTest, RetrieveNotification_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    EXPECT_EQ(proxy.RetrieveNotification(SLOT_ID, portIndex, seqNumber, notification),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, RetrieveNotification_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_EQ(proxy.RetrieveNotification(SLOT_ID, portIndex, seqNumber, notification),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, RetrieveNotification_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.RetrieveNotification(SLOT_ID, portIndex, seqNumber, notification), 0);
}

HWTEST_F(EsimCoreServiceProxyTest, RemoveNotificationFromList_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    ResultState enumResult;
    EXPECT_EQ(proxy.RemoveNotificationFromList(SLOT_ID, portIndex, seqNumber, enumResult),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, RemoveNotificationFromList_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    ResultState enumResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    EXPECT_EQ(proxy.RemoveNotificationFromList(SLOT_ID, portIndex, seqNumber, enumResult),
        TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, RemoveNotificationFromList_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    ResultState enumResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.RemoveNotificationFromList(SLOT_ID, portIndex, seqNumber, enumResult), 0);
}

HWTEST_F(EsimCoreServiceProxyTest, DeleteProfile_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);

    std::u16string iccId = Str8ToStr16("98760000000000543210");
    ResultState deleteProfileResult;
    int32_t ret = proxy.DeleteProfile(SLOT_ID, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, DeleteProfile_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);

    std::u16string iccId = Str8ToStr16("98760000000000543210");
    ResultState deleteProfileResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.DeleteProfile(SLOT_ID, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, DeleteProfile_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);

    std::u16string iccId = Str8ToStr16("98760000000000543210");
    ResultState deleteProfileResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.DeleteProfile(SLOT_ID, iccId, deleteProfileResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, SwitchToProfile_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);

    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDisableProfile = true;
    ResultState SwitchProfileResult;
    int32_t ret = proxy.SwitchToProfile(SLOT_ID, portIndex, iccId, forceDisableProfile, SwitchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SwitchToProfile_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);

    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDisableProfile = true;
    ResultState SwitchProfileResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.SwitchToProfile(SLOT_ID, portIndex, iccId, forceDisableProfile, SwitchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SwitchToProfile_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);

    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDisableProfile = true;
    ResultState SwitchProfileResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.SwitchToProfile(SLOT_ID, portIndex, iccId, forceDisableProfile, SwitchProfileResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, SetProfileNickname_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);

    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    ResultState setProfileNicknameResult;
    int32_t ret = proxy.SetProfileNickname(SLOT_ID, iccId, nickname, setProfileNicknameResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SetProfileNickname_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);

    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    ResultState setProfileNicknameResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.SetProfileNickname(SLOT_ID, iccId, nickname, setProfileNicknameResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SetProfileNickname_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);

    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    ResultState setProfileNicknameResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.SetProfileNickname(SLOT_ID, iccId, nickname, setProfileNicknameResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccInfo2_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    int32_t portIndex = 0;
    ResponseEsimResult responseResult;
    int32_t ret = proxy.GetEuiccInfo2(SLOT_ID, portIndex, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccInfo2_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);

    int32_t portIndex = 0;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.GetEuiccInfo2(SLOT_ID, portIndex, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, GetEuiccInfo2_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);

    int32_t portIndex = 0;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.GetEuiccInfo2(SLOT_ID, portIndex, responseResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(EsimCoreServiceProxyTest, AuthenticateServer_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    AuthenticateConfigInfo authenticateConfigInfo;
    authenticateConfigInfo.portIndex = 0;
    authenticateConfigInfo.matchingId = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    int32_t ret = proxy.AuthenticateServer(SLOT_ID, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, AuthenticateServer_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    AuthenticateConfigInfo authenticateConfigInfo;
    authenticateConfigInfo.portIndex = 0;
    authenticateConfigInfo.matchingId = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(-500));
    int32_t ret = proxy.AuthenticateServer(SLOT_ID, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, AuthenticateServer_003, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    AuthenticateConfigInfo authenticateConfigInfo;
    authenticateConfigInfo.portIndex = 0;
    authenticateConfigInfo.matchingId = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    int32_t ret = proxy.AuthenticateServer(SLOT_ID, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, 0);
}
} // namespace Telephony
} // namespace OHOS
