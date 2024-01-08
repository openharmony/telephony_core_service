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

#include "gtest/gtest.h"
#include "radio_event.h"
#include "satellite_core_callback.h"
#include "satellite_service_ipc_interface_code.h"
#include "satellite_service_proxy.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
const int32_t SLEEP_TIME = 5000;

namespace {
class MockIRemoteObject : public IRemoteObject {
public:
    uint32_t requestCode_ = -1;
    int32_t result_ = 0;

public:
    MockIRemoteObject() : IRemoteObject(u"mock_i_remote_object") {}

    ~MockIRemoteObject() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        TELEPHONY_LOGI("Mock SendRequest");
        requestCode_ = code;
        reply.WriteInt32(result_);
        return 0;
    }

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

class MockHandler : public TelEventHandler {
public:
    uint32_t eventId_ = 0;
    MockHandler() : TelEventHandler("MockHandler") {}
    ~MockHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override
    {
        eventId_ = event->GetInnerEventId();
    }
};
} // namespace

class SatelliteServiceTest : public testing::Test {
public:
    int32_t slotId_ = 0;
    std::u16string callbackToken = u"ohos.telephony.ISatelliteCoreCallback";
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SatelliteServiceTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
}

void SatelliteServiceTest::SetUp() {}

void SatelliteServiceTest::TearDown() {}

void SatelliteServiceTest::SetUpTestCase() {}

template<typename EnumType>
uint32_t ToCode(EnumType code)
{
    return static_cast<uint32_t>(code);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_RegisterCoreNotify_0001
 * @tc.name     register satellite callback
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, RegisterCoreNotify_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::RegisterCoreNotify_0001 -->");
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    SatelliteServiceProxy proxy(remote);

    int32_t ret = proxy.RegisterCoreNotify(slotId_, RadioEvent::SATELLITE_STATUS_CHANGED, nullptr);
    ASSERT_NE(ret, TELEPHONY_SUCCESS);

    sptr<ISatelliteCoreCallback> callback = std::make_unique<SatelliteCoreCallback>(nullptr).release();
    ret = proxy.RegisterCoreNotify(slotId_, RadioEvent::SATELLITE_STATUS_CHANGED, callback);
    ASSERT_EQ(remote->requestCode_, ToCode(SatelliteServiceInterfaceCode::REGISTER_CORE_NOTIFY));
    ASSERT_EQ(ret, TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_UnRegisterCoreNotify_0001
 * @tc.name     unregister satellite callback
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, UnRegisterCoreNotify_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::UnRegisterCoreNotify_0001 -->");
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    SatelliteServiceProxy proxy(remote);

    int32_t ret = proxy.UnRegisterCoreNotify(slotId_, RadioEvent::SATELLITE_STATUS_CHANGED);
    ASSERT_EQ(remote->requestCode_, ToCode(SatelliteServiceInterfaceCode::UNREGISTER_CORE_NOTIFY));
    ASSERT_EQ(ret, TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_SetRadioState_0001
 * @tc.name     set radio state
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, SetRadioState_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::SetRadioState_0001 -->");
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    SatelliteServiceProxy proxy(remote);

    int32_t ret = proxy.SetRadioState(slotId_, static_cast<int32_t>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
    ASSERT_EQ(remote->requestCode_, ToCode(SatelliteServiceInterfaceCode::SET_RADIO_STATE));
    ASSERT_EQ(ret, TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_GetImei_0001
 * @tc.name     get imei
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, GetImei_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::GetImei_0001 -->");
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    SatelliteServiceProxy proxy(remote);

    std::string ret = proxy.GetImei();
    ASSERT_EQ(remote->requestCode_, ToCode(SatelliteServiceInterfaceCode::GET_IMEI));
    ASSERT_EQ(ret, "");
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_IsSatelliteEnabled_0001
 * @tc.name     is satellite enabled
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, IsSatelliteEnabled_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::IsSatelliteEnabled_0001 -->");
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    SatelliteServiceProxy proxy(remote);

    int32_t ret = proxy.IsSatelliteEnabled();
    ASSERT_EQ(remote->requestCode_, ToCode(SatelliteServiceInterfaceCode::IS_SATELLITE_ENABLED));
    ASSERT_EQ(ret, TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_GetSatelliteCapability_0001
 * @tc.name     get satellite capability
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, GetSatelliteCapability_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::GetSatelliteCapability_0001 -->");
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    SatelliteServiceProxy proxy(remote);

    int32_t ret = proxy.GetSatelliteCapability();
    ASSERT_EQ(remote->requestCode_, ToCode(SatelliteServiceInterfaceCode::GET_SATELLITE_CAPABILITY));
    ASSERT_EQ(ret, TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_GetProxyObjectPtr_0001
 * @tc.name     get proxy object ptr
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, GetProxyObjectPtr_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::GetProxyObjectPtr_0001 -->");
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    SatelliteServiceProxy proxy(remote);

    auto ret = proxy.GetProxyObjectPtr(SatelliteServiceProxyType::PROXY_SATELLITE_SMS);
    ASSERT_EQ(remote->requestCode_, ToCode(SatelliteServiceInterfaceCode::GET_PROXY_OBJECT_PTR));
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_SetRadioStateCallback_0001
 * @tc.name     set radio state callback
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, SetRadioStateCallback_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::SetRadioStateCallback_0001 -->");
    std::shared_ptr<MockHandler> handler = std::make_shared<MockHandler>();
    SatelliteCoreCallback callback(handler);

    MessageParcel reply;
    MessageOption option;
    MessageParcel data;
    data.WriteInterfaceToken(callbackToken);
    data.WriteInt32(RadioEvent::RADIO_SET_STATUS);
    data.WriteInt32(SatelliteRadioResponseType::DEFAULT_RADIO_RESPONSE);
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    auto ret = callback.OnRemoteRequest(
        ToCode(SatelliteCoreCallbackInterfaceCode::SET_RADIO_STATE_RESPONSE), data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->eventId_, RadioEvent::RADIO_SET_STATUS);
    EXPECT_EQ(reply.ReadInt32(), TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_SetRadioStateCallback_0002
 * @tc.name     set radio state callback
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, SetRadioStateCallback_0002, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::SetRadioStateCallback_0002 -->");
    std::shared_ptr<MockHandler> handler = std::make_shared<MockHandler>();
    SatelliteCoreCallback callback(handler);

    MessageParcel reply;
    MessageOption option;
    MessageParcel data;
    data.WriteInterfaceToken(callbackToken);
    data.WriteInt32(RadioEvent::RADIO_SET_STATUS);
    data.WriteInt32(SatelliteRadioResponseType::RADIO_STATE_INFO);
    data.WriteInt64(0);
    data.WriteInt32(0);
    auto ret = callback.OnRemoteRequest(
        ToCode(SatelliteCoreCallbackInterfaceCode::SET_RADIO_STATE_RESPONSE), data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->eventId_, RadioEvent::RADIO_SET_STATUS);
    EXPECT_EQ(reply.ReadInt32(), TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_RadioStateChangedCallback_0001
 * @tc.name     radio state changed callback
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, RadioStateChangedCallback_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::RadioStateChangedCallback_0001 -->");
    std::shared_ptr<MockHandler> handler = std::make_shared<MockHandler>();
    SatelliteCoreCallback callback(handler);

    MessageParcel reply;
    MessageOption option;
    MessageParcel data;
    data.WriteInterfaceToken(callbackToken);
    data.WriteInt32(RadioEvent::RADIO_STATE_CHANGED);
    data.WriteInt32(0);
    auto ret =
        callback.OnRemoteRequest(ToCode(SatelliteCoreCallbackInterfaceCode::RADIO_STATE_CHANGED), data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->eventId_, RadioEvent::RADIO_STATE_CHANGED);
    EXPECT_EQ(reply.ReadInt32(), TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_SatelliteStatusChangedCallback_0001
 * @tc.name     satellite status changed callback
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, SatelliteStatusChangedCallback_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::SatelliteStatusChangedCallback_0001 -->");
    std::shared_ptr<MockHandler> handler = std::make_shared<MockHandler>();
    SatelliteCoreCallback callback(handler);

    MessageParcel reply;
    MessageOption option;
    MessageParcel data;
    data.WriteInterfaceToken(callbackToken);
    data.WriteInt32(RadioEvent::SATELLITE_STATUS_CHANGED);
    data.WriteInt32(0);
    data.WriteInt32(0);
    auto ret = callback.OnRemoteRequest(
        ToCode(SatelliteCoreCallbackInterfaceCode::SATELLITE_STATUS_CHANGED), data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->eventId_, RadioEvent::SATELLITE_STATUS_CHANGED);
    EXPECT_EQ(reply.ReadInt32(), TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_SatelliteServiceTest_SimStateChangedCallback_0001
 * @tc.name     sim state changed callback
 * @tc.desc     Function test
 */
HWTEST_F(SatelliteServiceTest, SimStateChangedCallback_0001, Function | MediumTest | Level2)
{
    TELEPHONY_LOGI("SatelliteServiceTest::SimStateChangedCallback_0001 -->");
    std::shared_ptr<MockHandler> handler = std::make_shared<MockHandler>();
    SatelliteCoreCallback callback(handler);

    MessageParcel reply;
    MessageOption option;
    MessageParcel data;
    data.WriteInterfaceToken(callbackToken);
    data.WriteInt32(RadioEvent::RADIO_SIM_STATE_CHANGE);
    auto ret =
        callback.OnRemoteRequest(ToCode(SatelliteCoreCallbackInterfaceCode::SIM_STATE_CHANGED), data, reply, option);
    EXPECT_EQ(ret, TELEPHONY_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->eventId_, RadioEvent::RADIO_SIM_STATE_CHANGE);
    EXPECT_EQ(reply.ReadInt32(), TELEPHONY_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS