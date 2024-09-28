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
#include "core_service_proxy.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "core_service_proxy.h"
#include "esim_state_type.h"
#include "string_ex.h"
#include "gmock/gmock.h"
#include "iremote_broker.h"
#include "iremote_object.h"

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
}
}