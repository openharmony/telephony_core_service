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

HWTEST_F(EsimCoreServiceProxyTest, SendApduData_001, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = nullptr;
    CoreServiceProxy proxy(remote);
    std::u16string aid = Str8ToStr16("aid test");
    EsimApduData apduData;
    ResponseEsimResult responseResult;
    std::u16string eId;
    EXPECT_EQ(proxy.SendApduData(SLOT_ID, aid, apduData, responseResult), TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceProxyTest, SendApduData_002, Function | MediumTest | Level2)
{
    sptr<MockIRemoteObject> remote = new (std::nothrow) MockIRemoteObject();
    CoreServiceProxy proxy(remote);
    std::u16string aid = Str8ToStr16("aid test");
    EsimApduData apduData;
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
    EsimApduData apduData;
    ResponseEsimResult responseResult;
    std::u16string eId;
    EXPECT_CALL(*remote, SendRequest(testing::_, testing::_, testing::_, testing::_)).WillOnce(testing::Return(0));
    EXPECT_EQ(proxy.SendApduData(SLOT_ID, aid, apduData, responseResult), 0);
}

} // namespace Telephony
} // namespace OHOS
