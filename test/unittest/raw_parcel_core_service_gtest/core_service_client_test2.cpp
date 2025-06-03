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

class CoreServiceClientTest2 : public testing::Test {
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
HWTEST_F(CoreServiceClientTest2, GetImei001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    std::u16string imei;
    int32_t ret = client->GetImei(0, imei, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest2, GetImei002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImei(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imei;
    int32_t ret = client->GetImei(0, imei, 0);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest2, GetImei003, Function | MediumTest | Level1)
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

HWTEST_F(CoreServiceClientTest2, GetImei004, Function | MediumTest | Level1)
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

HWTEST_F(CoreServiceClientTest2, GetImei005, Function | MediumTest | Level1)
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

HWTEST_F(CoreServiceClientTest2, GetImei006, Function | MediumTest | Level1)
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

HWTEST_F(CoreServiceClientTest2, GetImei007, Function | MediumTest | Level1)
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
HWTEST_F(CoreServiceClientTest2, GetImeiSv001, Function | MediumTest | Level1)
{
    client->getProxyNullptr_ = true;
    std::u16string imeiSv;
    int32_t ret = client->GetImeiSv(0, imeiSv, 0);
    EXPECT_EQ(ret, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(CoreServiceClientTest2, GetImeiSv002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*proxy, GetImeiSv(_, _))
        .WillOnce(Invoke([](int32_t slotId, const sptr<IRawParcelCallback> &callback) {
            return ~TELEPHONY_ERR_SUCCESS;
        }));
    std::u16string imeiSv;
    int32_t ret = client->GetImeiSv(0, imeiSv, 0);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceClientTest2, GetImeiSv003, Function | MediumTest | Level1)
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

HWTEST_F(CoreServiceClientTest2, GetImeiSv004, Function | MediumTest | Level1)
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

HWTEST_F(CoreServiceClientTest2, GetImeiSv005, Function | MediumTest | Level1)
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

HWTEST_F(CoreServiceClientTest2, GetImeiSv006, Function | MediumTest | Level1)
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

HWTEST_F(CoreServiceClientTest2, GetImeiSv007, Function | MediumTest | Level1)
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
}
}
}