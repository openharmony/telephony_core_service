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

#include <thread>
#include "mock_i_core_service.h"
#include "core_service_client.h"
#include "telephony_errors.h"
#include "sim_state_type.h"
#include "raw_parcel_callback_stub.h"

namespace OHOS {
namespace Telephony {
using namespace testing;
using namespace testing::ext;
namespace {

class MockCoreServiceClient : public CoreServiceClient {
public:
    sptr<ICoreService> GetProxy() override;
private:
    bool getProxyNullptr_ = false;
};

sptr<MockICoreService> proxy = nullptr;
std::shared_ptr<MockCoreServiceClient> client = std::make_shared<MockCoreServiceClient>();
sptr<RawParcelCallbackStub> savedCallback = nullptr;

sptr<ICoreService> MockCoreServiceClient::GetProxy()
{
    return getProxyNullptr_ ? nullptr : proxy;
}

class CoreServiceClientTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    void SetUp()
    {
        proxy = sptr<MockICoreService>::MakeSptr();
        client->getProxyNullptr_ = false;
    }
    void TearDown()
    {
        proxy = nullptr;
    }
};

/***************************************************** GetImei ******************************************************/
HWTEST_F(CoreServiceClientTest, GetImei001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    std::u16string imei;
    int32_t ret = client->GetImei(0, imei, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetImei002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImei(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imei;
    int32_t ret = client->GetImei(0, imei, 0);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetImei003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImei(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imei = u"unchanged";
    int32_t ret = client->GetImei(0, imei, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
    EXPECT_EQ(imei, u"unchanged");
}

HWTEST_F(CoreServiceClientTest, GetImei004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImei(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imei;
    int32_t ret = client->GetImei(0, imei, 1000);
    EXPECT_EQ(ret, ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetImei005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImei(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteString16(u"8674009876543210");
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imei;
    int32_t ret = client->GetImei(0, imei, 1000);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(imei, u"8674009876543210");
}

HWTEST_F(CoreServiceClientTest, GetImei006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImei(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteString16(u"");
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imei = u"default_imei";
    int32_t ret = client->GetImei(0, imei, 1000);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(imei.empty());
}

HWTEST_F(CoreServiceClientTest, GetImei007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImei(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imei;
    int32_t ret = client->GetImei(0, imei, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** GetImeiSv ******************************************************/
HWTEST_F(CoreServiceClientTest, GetImeiSv001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    std::u16string imeiSv;
    int32_t ret = client->GetImeiSv(0, imeiSv, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetImeiSv002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImeiSv(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imeiSv;
    int32_t ret = client->GetImeiSv(0, imeiSv, 0);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetImeiSv003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImeiSv(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imeiSv = u"default";
    int32_t ret = client->GetImeiSv(0, imeiSv, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
    EXPECT_EQ(imeiSv, u"default");
}

HWTEST_F(CoreServiceClientTest, GetImeiSv004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImeiSv(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imeiSv;
    int32_t ret = client->GetImeiSv(0, imeiSv, 1000);
    EXPECT_EQ(ret, ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetImeiSv005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImeiSv(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteString16(u"8674001234567890");
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imeiSv;
    int32_t ret = client->GetImeiSv(0, imeiSv, 1000);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(imeiSv, u"8674001234567890");
}

HWTEST_F(CoreServiceClientTest, GetImeiSv006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImeiSv(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteString16(u"");
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imeiSv = u"previous";
    int32_t ret = client->GetImeiSv(0, imeiSv, 1000);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(imeiSv.empty());
}

HWTEST_F(CoreServiceClientTest, GetImeiSv007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImeiSv(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imeiSv;
    int32_t ret = client->GetImeiSv(0, imeiSv, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/*************************************************** IsCTSimCard ****************************************************/
HWTEST_F(CoreServiceClientTest, IsCTSimCard001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    bool isCT = true;
    int32_t ret = client->IsCTSimCard(0, isCT, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, IsCTSimCard002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsCTSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    bool isCT = true;
    int32_t ret = client->IsCTSimCard(0, isCT, 0);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(isCT); // 未写入应保留原值
}

HWTEST_F(CoreServiceClientTest, IsCTSimCard003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsCTSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool isCT = false;
    int32_t ret = client->IsCTSimCard(0, isCT, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
    EXPECT_FALSE(isCT);
}

HWTEST_F(CoreServiceClientTest, IsCTSimCard004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsCTSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool isCT = false;
    int32_t ret = client->IsCTSimCard(0, isCT, 1000);
    EXPECT_EQ(ret, ~TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(isCT);
}

HWTEST_F(CoreServiceClientTest, IsCTSimCard005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsCTSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteBool(true);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool isCT = false;
    int32_t ret = client->IsCTSimCard(0, isCT, 1000);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(isCT);
}

HWTEST_F(CoreServiceClientTest, IsCTSimCard006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsCTSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteBool(false);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool isCT = true;
    int32_t ret = client->IsCTSimCard(0, isCT, 1000);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(isCT);
}

HWTEST_F(CoreServiceClientTest, IsCTSimCard007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsCTSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool isCT = false;
    int32_t ret = client->IsCTSimCard(0, isCT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
    EXPECT_FALSE(isCT);
}

/*************************************************** IsSimActive ****************************************************/
HWTEST_F(CoreServiceClientTest, IsSimActive001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    bool ret = client->IsSimActive(0, 0);
    EXPECT_FALSE(ret);
}

HWTEST_F(CoreServiceClientTest, IsSimActive002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsSimActive(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return false;
        }));
    bool ret = client->IsSimActive(0, 0);
    EXPECT_FALSE(ret);
}

HWTEST_F(CoreServiceClientTest, IsSimActive003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsSimActive(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return true;
        }));
    bool ret = client->IsSimActive(0, 0);
    EXPECT_FALSE(ret);
}

HWTEST_F(CoreServiceClientTest, IsSimActive004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsSimActive(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteBool(false);
            cb->OnRemoteRequest(0, data, reply, option);
            return true;
        }));
    bool ret = client->IsSimActive(0, 1000);
    EXPECT_FALSE(ret);
}

HWTEST_F(CoreServiceClientTest, IsSimActive005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsSimActive(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteBool(true);
            cb->OnRemoteRequest(0, data, reply, option);
            return true;
        }));
    bool ret = client->IsSimActive(0, 1000);
    EXPECT_TRUE(ret);
}

HWTEST_F(CoreServiceClientTest, IsSimActive006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsSimActive(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return true;
        }));
    bool ret = client->IsSimActive(0, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteBool(false);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_FALSE(ret);
}

HWTEST_F(CoreServiceClientTest, IsSimActive007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, IsSimActive(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return true;
        }));
    bool ret = client->IsSimActive(0, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteBool(true);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_FALSE(ret);
}

/******************************************* GetDefaultVoiceSimId ********************************************/
HWTEST_F(CoreServiceClientTest, GetDefaultVoiceSimId001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    int32_t simId = -1;
    int32_t ret = client->GetDefaultVoiceSimId(simId, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetDefaultVoiceSimId002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetDefaultVoiceSimId(_))
        .WillOnce(Invoke([](const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    int32_t simId = -1;
    int32_t ret = client->GetDefaultVoiceSimId(simId, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetDefaultVoiceSimId003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetDefaultVoiceSimId(_))
        .WillOnce(Invoke([](const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t simId = -1;
    int32_t ret = client->GetDefaultVoiceSimId(simId, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetDefaultVoiceSimId004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetDefaultVoiceSimId(_))
        .WillOnce(Invoke([](const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t simId = -1;
    int32_t ret = client->GetDefaultVoiceSimId(simId, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetDefaultVoiceSimId005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetDefaultVoiceSimId(_))
        .WillOnce(Invoke([](const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(2); // simId
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t simId = -1;
    int32_t ret = client->GetDefaultVoiceSimId(simId, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simId, 2);
}

HWTEST_F(CoreServiceClientTest, GetDefaultVoiceSimId006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetDefaultVoiceSimId(_))
        .WillOnce(Invoke([](const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(9999); // abnormal success code
            data.WriteInt32(99);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t simId = -1;
    int32_t ret = client->GetDefaultVoiceSimId(simId, 1000);
    EXPECT_EQ(ret, 9999);
    EXPECT_EQ(simId, -1); // 不应修改 simId
}

HWTEST_F(CoreServiceClientTest, GetDefaultVoiceSimId007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetDefaultVoiceSimId(_))
        .WillOnce(Invoke([](const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t simId = -1;
    int32_t ret = client->GetDefaultVoiceSimId(simId, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/*************************************************** SetShowNumber **************************************************/
HWTEST_F(CoreServiceClientTest, SetShowNumber001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    int32_t ret = client->SetShowNumber(0, u"13300000000", 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, SetShowNumber002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowNumber(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &number,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowNumber(0, u"13300000000", 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, SetShowNumber003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowNumber(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &number,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowNumber(0, u"13300000000", 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, SetShowNumber004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowNumber(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &number,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowNumber(0, u"13300000000", 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, SetShowNumber005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowNumber(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &number,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowNumber(0, u"13300000000", 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, SetShowNumber006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowNumber(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &number,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(13579); // custom non-standard result
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowNumber(0, u"13300000000", 1000);
    EXPECT_TRUE(ret == 13579);
}

HWTEST_F(CoreServiceClientTest, SetShowNumber007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowNumber(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &number,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowNumber(0, u"13300000000", 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/*************************************************** GetShowNumber **************************************************/
HWTEST_F(CoreServiceClientTest, GetShowNumber001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    std::u16string showNumber;
    int32_t ret = client->GetShowNumber(0, showNumber, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetShowNumber002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowNumber(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showNumber;
    int32_t ret = client->GetShowNumber(0, showNumber, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetShowNumber003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowNumber(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showNumber;
    int32_t ret = client->GetShowNumber(0, showNumber, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetShowNumber004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowNumber(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showNumber;
    int32_t ret = client->GetShowNumber(0, showNumber, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetShowNumber005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowNumber(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteString16(u"+8613800000000");
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showNumber;
    int32_t ret = client->GetShowNumber(0, showNumber, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(showNumber == u"+8613800000000");
}

HWTEST_F(CoreServiceClientTest, GetShowNumber006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowNumber(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteString16(u"");
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showNumber = u"default";
    int32_t ret = client->GetShowNumber(0, showNumber, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(showNumber.empty());
}

HWTEST_F(CoreServiceClientTest, GetShowNumber007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowNumber(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showNumber;
    int32_t ret = client->GetShowNumber(0, showNumber, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/*************************************************** SetShowName ****************************************************/
HWTEST_F(CoreServiceClientTest, SetShowName001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    int32_t ret = client->SetShowName(0, u"TestName", 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, SetShowName002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowName(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &name,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowName(0, u"TestName", 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, SetShowName003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowName(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &name,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowName(0, u"TestName", 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, SetShowName004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowName(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &name,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowName(0, u"TestName", 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, SetShowName005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowName(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &name,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowName(0, u"TestName", 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, SetShowName006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowName(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &name,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(12345678); // abnormal but accepted result code
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowName(0, u"TestName", 1000);
    EXPECT_TRUE(ret == 12345678);
}

HWTEST_F(CoreServiceClientTest, SetShowName007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetShowName(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &name,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub *>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    int32_t ret = client->SetShowName(0, u"TestName", 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** GetShowName ***************************************************/
HWTEST_F(CoreServiceClientTest, GetShowName001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    std::u16string showName;
    int32_t ret = client->GetShowName(0, showName, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetShowName002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowName(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showName;
    int32_t ret = client->GetShowName(0, showName, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetShowName003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowName(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showName;
    int32_t ret = client->GetShowName(0, showName, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetShowName004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowName(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS); // result error
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showName;
    int32_t ret = client->GetShowName(0, showName, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetShowName005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowName(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteString16(u"TestShowName");
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showName;
    int32_t ret = client->GetShowName(0, showName, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(showName == u"TestShowName");
}

HWTEST_F(CoreServiceClientTest, GetShowName006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowName(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteString16(u"");
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showName = u"previous";
    int32_t ret = client->GetShowName(0, showName, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(showName.empty());
}

HWTEST_F(CoreServiceClientTest, GetShowName007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetShowName(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string showName;
    int32_t ret = client->GetShowName(0, showName, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** UnlockPin *****************************************************/
HWTEST_F(CoreServiceClientTest, UnlockPin001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    LockStatusResponse response;
    int32_t ret = client->UnlockPin(0, u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, UnlockPin002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin(0, u"", response, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, UnlockPin003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin, const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin(0, u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, UnlockPin004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin(0, u"", response, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, UnlockPin005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(UNLOCK_INCORRECT);
            data.WriteInt32(123);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin(0, u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result == UNLOCK_INCORRECT);
    EXPECT_TRUE(response.remain == 123);
}

HWTEST_F(CoreServiceClientTest, UnlockPin006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(~UNLOCK_INCORRECT);
            data.WriteInt32(0);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin(0, u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result != UNLOCK_INCORRECT);
}

HWTEST_F(CoreServiceClientTest, UnlockPin007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin(0, u"", response, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** UnlockPuk *****************************************************/
HWTEST_F(CoreServiceClientTest, UnlockPuk001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk(0, u"", u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &puk,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk(0, u"", u"", response, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &puk,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk(0, u"", u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &puk,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &puk,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(UNLOCK_INCORRECT);
            data.WriteInt32(3); // remain count
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result == UNLOCK_INCORRECT);
    EXPECT_TRUE(response.remain == 3);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &puk,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(~UNLOCK_INCORRECT);
            data.WriteInt32(0);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result != UNLOCK_INCORRECT);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &puk,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk(0, u"", u"", response, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** AlterPin ******************************************************/
HWTEST_F(CoreServiceClientTest, AlterPin001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    LockStatusResponse response;
    int32_t ret = client->AlterPin(0, u"", u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, AlterPin002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin(0, u"", u"", response, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, AlterPin003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin(0, u"", u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, AlterPin004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, AlterPin005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(UNLOCK_INCORRECT);
            data.WriteInt32(5); // remain count
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result == UNLOCK_INCORRECT);
    EXPECT_TRUE(response.remain == 5);
}

HWTEST_F(CoreServiceClientTest, AlterPin006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(~UNLOCK_INCORRECT);
            data.WriteInt32(0);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result != UNLOCK_INCORRECT);
}

HWTEST_F(CoreServiceClientTest, AlterPin007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin(0, u"", u"", response, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** UnlockPin2 ****************************************************/
HWTEST_F(CoreServiceClientTest, UnlockPin2001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    LockStatusResponse response;
    int32_t ret = client->UnlockPin2(0, u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, UnlockPin2002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin2(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin2,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin2(0, u"", response, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, UnlockPin2003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin2(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin2,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin2(0, u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, UnlockPin2004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin2(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin2(0, u"", response, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, UnlockPin2005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin2(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(UNLOCK_INCORRECT);
            data.WriteInt32(2); // remain
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin2(0, u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result == UNLOCK_INCORRECT);
    EXPECT_TRUE(response.remain == 2);
}

HWTEST_F(CoreServiceClientTest, UnlockPin2006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin2(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(~UNLOCK_INCORRECT);
            data.WriteInt32(0);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin2(0, u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result != UNLOCK_INCORRECT);
}

HWTEST_F(CoreServiceClientTest, UnlockPin2007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPin2(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &pin2,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPin2(0, u"", response, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** UnlockPuk2 ****************************************************/
HWTEST_F(CoreServiceClientTest, UnlockPuk2001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk2(0, u"", u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk2002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk2(0, u"", u"", response, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk2003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk2(0, u"", u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk2004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk2(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk2005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(UNLOCK_INCORRECT);
            data.WriteInt32(4); // remain
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk2(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result == UNLOCK_INCORRECT);
    EXPECT_TRUE(response.remain == 4);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk2006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(~UNLOCK_INCORRECT);
            data.WriteInt32(0);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk2(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result != UNLOCK_INCORRECT);
}

HWTEST_F(CoreServiceClientTest, UnlockPuk2007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, UnlockPuk2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->UnlockPuk2(0, u"", u"", response, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** AlterPin2 *****************************************************/
HWTEST_F(CoreServiceClientTest, AlterPin2001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    LockStatusResponse response;
    int32_t ret = client->AlterPin2(0, u"", u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, AlterPin2002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin2(0, u"", u"", response, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, AlterPin2003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin2(0, u"", u"", response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, AlterPin2004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin2(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, AlterPin2005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(UNLOCK_INCORRECT);
            data.WriteInt32(7); // remain
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin2(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result == UNLOCK_INCORRECT);
    EXPECT_TRUE(response.remain == 7);
}

HWTEST_F(CoreServiceClientTest, AlterPin2006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(~UNLOCK_INCORRECT);
            data.WriteInt32(0);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin2(0, u"", u"", response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result != UNLOCK_INCORRECT);
}

HWTEST_F(CoreServiceClientTest, AlterPin2007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, AlterPin2(_, _, _, _))
        .WillOnce(Invoke([](int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    int32_t ret = client->AlterPin2(0, u"", u"", response, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** SetLockState **************************************************/
HWTEST_F(CoreServiceClientTest, SetLockState001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    LockStatusResponse response;
    LockInfo options;
    int32_t ret = client->SetLockState(0, options, response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, SetLockState002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const LockInfo &options,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    LockInfo options;
    int32_t ret = client->SetLockState(0, options, response, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, SetLockState003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const LockInfo &options,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    LockInfo options;
    int32_t ret = client->SetLockState(0, options, response, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, SetLockState004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const LockInfo &options,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    LockInfo options;
    int32_t ret = client->SetLockState(0, options, response, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, SetLockState005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const LockInfo &options,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(UNLOCK_INCORRECT);
            data.WriteInt32(9); // remain
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    LockInfo options;
    int32_t ret = client->SetLockState(0, options, response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result == UNLOCK_INCORRECT);
    EXPECT_TRUE(response.remain == 9);
}

HWTEST_F(CoreServiceClientTest, SetLockState006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const LockInfo &options,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(~UNLOCK_INCORRECT);
            data.WriteInt32(0);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    LockInfo options;
    int32_t ret = client->SetLockState(0, options, response, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(response.result != UNLOCK_INCORRECT);
}

HWTEST_F(CoreServiceClientTest, SetLockState007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, SetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, const LockInfo &options,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockStatusResponse response;
    LockInfo options;
    int32_t ret = client->SetLockState(0, options, response, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/*************************************************** GetLockState ***************************************************/
HWTEST_F(CoreServiceClientTest, GetLockState001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    LockState lockState;
    int32_t ret = client->GetLockState(0, LockType::PIN_LOCK, lockState, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetLockState002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, LockType lockType,
                            const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    LockState lockState;
    int32_t ret = client->GetLockState(0, LockType::PIN_LOCK, lockState, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetLockState003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, LockType lockType,
                            const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockState lockState;
    int32_t ret = client->GetLockState(0, LockType::PIN_LOCK, lockState, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetLockState004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, LockType lockType,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS); // result error
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockState lockState;
    int32_t ret = client->GetLockState(0, LockType::PIN_LOCK, lockState, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetLockState005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, LockType lockType,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS); // success
            data.WriteInt32(static_cast<int32_t>(LockState::LOCK_OFF));
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockState lockState = LockState::LOCK_ON;
    int32_t ret = client->GetLockState(0, LockType::PIN_LOCK, lockState, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(lockState == LockState::LOCK_OFF);
}

HWTEST_F(CoreServiceClientTest, GetLockState006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, LockType lockType,
                            const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            // Wrong but still testable value
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(999); // invalid LockState
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockState lockState;
    int32_t ret = client->GetLockState(0, LockType::PIN_LOCK, lockState, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(static_cast<int>(lockState) == 999);
}

HWTEST_F(CoreServiceClientTest, GetLockState007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetLockState(_, _, _))
        .WillOnce(Invoke([](int32_t slotId, LockType lockType,
                            const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    LockState lockState;
    int32_t ret = client->GetLockState(0, LockType::PIN_LOCK, lockState, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** HasSimCard ****************************************************/
HWTEST_F(CoreServiceClientTest, HasSimCard001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    bool hasSim = false;
    int32_t ret = client->HasSimCard(0, hasSim, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, HasSimCard002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    bool hasSim = false;
    int32_t ret = client->HasSimCard(0, hasSim, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, HasSimCard003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasSim = false;
    int32_t ret = client->HasSimCard(0, hasSim, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, HasSimCard004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS); // error result
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasSim = false;
    int32_t ret = client->HasSimCard(0, hasSim, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, HasSimCard005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteBool(true); // hasSimCard = true
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasSim = false;
    int32_t ret = client->HasSimCard(0, hasSim, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(hasSim);
}

HWTEST_F(CoreServiceClientTest, HasSimCard006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteBool(false); // hasSimCard = false
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasSim = true;
    int32_t ret = client->HasSimCard(0, hasSim, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(hasSim);
}

HWTEST_F(CoreServiceClientTest, HasSimCard007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasSimCard(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasSim = false;
    int32_t ret = client->HasSimCard(0, hasSim, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/**************************************************** GetSimState ******************************************************/
HWTEST_F(CoreServiceClientTest, GetSimState001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    SimState simState;
    int32_t ret = client->GetSimState(0, simState, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetSimState002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetSimState(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    SimState simState;
    int32_t ret = client->GetSimState(0, simState, 0);
    EXPECT_TRUE(ret != TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetSimState003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetSimState(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    SimState simState;
    int32_t ret = client->GetSimState(0, simState, 0);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, GetSimState004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetSimState(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    SimState simState;
    int32_t ret = client->GetSimState(0, simState, 1000);
    EXPECT_TRUE(ret == ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, GetSimState005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetSimState(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(static_cast<int32_t>(SimState::SIM_STATE_READY));
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    int32_t ret = client->GetSimState(0, simState, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(simState == SimState::SIM_STATE_READY);
}

HWTEST_F(CoreServiceClientTest, GetSimState006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetSimState(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            sptr<RawParcelCallbackStub> cb = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            MessageParcel data;
            MessageParcel reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteInt32(999); // invalid sim state
            cb->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    SimState simState;
    int32_t ret = client->GetSimState(0, simState, 1000);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(simState), 999);
}

HWTEST_F(CoreServiceClientTest, GetSimState007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetSimState(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            savedCallback = static_cast<RawParcelCallbackStub*>(callback.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    SimState simState;
    int32_t ret = client->GetSimState(0, simState, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_TRUE(ret == TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

/********************************************** HasOperatorPrivileges ***********************************************/
HWTEST_F(CoreServiceClientTest, HasOperatorPrivileges001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    bool hasOp = true;
    int32_t ret = client->HasOperatorPrivileges(0, hasOp, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, HasOperatorPrivileges002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasOperatorPrivileges(_, _))
        .WillOnce(Invoke([](int32_t, const sptr<IRawParcelCallback> &cb) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    bool hasOp = true;
    int32_t ret = client->HasOperatorPrivileges(0, hasOp, 0);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, HasOperatorPrivileges003, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasOperatorPrivileges(_, _))
        .WillOnce(Invoke([](int32_t, const sptr<IRawParcelCallback> &cb) {
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasOp = true;
    int32_t ret = client->HasOperatorPrivileges(0, hasOp, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest, HasOperatorPrivileges004, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasOperatorPrivileges(_, _))
        .WillOnce(Invoke([](int32_t, const sptr<IRawParcelCallback> &cb) {
            sptr<RawParcelCallbackStub> callback = static_cast<RawParcelCallbackStub *>(cb.GetRefPtr());
            MessageParcel data, reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
            callback->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasOp = false;
    int32_t ret = client->HasOperatorPrivileges(0, hasOp, 1000);
    EXPECT_EQ(ret, ~TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest, HasOperatorPrivileges005, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasOperatorPrivileges(_, _))
        .WillOnce(Invoke([](int32_t, const sptr<IRawParcelCallback> &cb) {
            sptr<RawParcelCallbackStub> callback = static_cast<RawParcelCallbackStub *>(cb.GetRefPtr());
            MessageParcel data, reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteBool(true);
            callback->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasOp = false;
    int32_t ret = client->HasOperatorPrivileges(0, hasOp, 1000);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(hasOp);
}

HWTEST_F(CoreServiceClientTest, HasOperatorPrivileges006, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasOperatorPrivileges(_, _))
        .WillOnce(Invoke([](int32_t, const sptr<IRawParcelCallback> &cb) {
            sptr<RawParcelCallbackStub> callback = static_cast<RawParcelCallbackStub *>(cb.GetRefPtr());
            MessageParcel data, reply;
            MessageOption option;
            data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
            data.WriteInt32(TELEPHONY_ERR_SUCCESS);
            data.WriteBool(false);
            callback->OnRemoteRequest(0, data, reply, option);
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasOp = true;
    int32_t ret = client->HasOperatorPrivileges(0, hasOp, 1000);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(hasOp);
}

HWTEST_F(CoreServiceClientTest, HasOperatorPrivileges007, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, HasOperatorPrivileges(_, _))
        .WillOnce(Invoke([](int32_t, const sptr<IRawParcelCallback> &cb) {
            savedCallback = static_cast<RawParcelCallbackStub *>(cb.GetRefPtr());
            return TELEPHONY_ERR_SUCCESS;
        }));
    bool hasOp = false;
    int32_t ret = client->HasOperatorPrivileges(0, hasOp, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(u"OHOS.Telephony.IRawParcelCallback");
    data.WriteInt32(~TELEPHONY_ERR_SUCCESS);
    savedCallback->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
    EXPECT_FALSE(hasOp);
}
}
}
}