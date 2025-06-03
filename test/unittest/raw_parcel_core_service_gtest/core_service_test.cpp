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
#include "core_service.h"
#include "telephony_errors.h"
#include "sim_state_type.h"
#include "raw_parcel_callback_stub.h"
#include "sim_manager.h"
#include "network_search_manager.h"
#include "tel_ril_manager.h"
#include "telephony_permission_test_helper.h"

namespace OHOS {
namespace Telephony {
using namespace testing;
using namespace testing::ext;
namespace {
constexpr int64_t DELAY_TIME_MS = 10;
constexpr int64_t WAIT_TIME_MS = 2 * DELAY_TIME_MS;
constexpr int64_t DEFAULT_WAIT_TIME_MS = 1000;
std::shared_ptr<CoreService> coreService;

MockSimManager *mockSimManager;
MockINetworkSearch *mockNetworkSearchManager;
MockTelRilManager *mockTelRilManager;

std::shared_ptr<AppExecFwk::EventHandler> defaultHandler;
bool runInCaller = true;

sptr<IRawParcelCallback> directCall = nullptr;

void RunInCaller(const std::function<void()> task)
{
    task();
}
void RunInHandler(const std::function<void()> task, int64_t delayed)
{
    defaultHandler->PostTask(task, "", delayed);
}
void AsyncRun(const std::function<void()> task)
{
    if (runInCaller) {
        RunInCaller(task);
        return;
    }
    RunInHandler(task, DELAY_TIME_MS);
}
void SetRunInCaller()
{
    runInCaller = true;
}
void SetDelayRunInHandler()
{
    runInCaller = false;
}

class MockCoreService : public CoreService {
private:
    void AsyncNetSearchExecute(const std::function<void()> task) override
    {
        AsyncRun(task);
    }
    void AsyncSimGeneralExecute(const std::function<void()> task) override
    {
        AsyncRun(task);
    }
    void AsyncSimPinExecute(const std::function<void()> task) override
    {
        AsyncRun(task);
    }
};

class DirectCallRawParcelCallback : public IRawParcelCallback {
public:
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
    void Transfer(std::function<void(MessageParcel &)> func, MessageParcel &data)
    {
        func(data);
    }
};

class CoreServiceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        coreService = std::make_shared<MockCoreService>();
        directCall = sptr<DirectCallRawParcelCallback>::MakeSptr();

        auto runner = AppExecFwk::EventRunner::Create("dt_defaultHandler", AppExecFwk::ThreadMode::FFRT);
        defaultHandler = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    static void TearDownTestCase()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_WAIT_TIME_MS));
    }
    void SetUp()
    {
        auto simManager = std::make_shared<SimManager>(nullptr);
        auto networkSearchManager = std::make_shared<NetworkSearchManager>(nullptr, nullptr);
        auto telRilManager = std::make_shared<TelRilManager>();

        mockSimManager = std::static_pointer_cast<MockSimManager>(simManager).get();
        mockNetworkSearchManager = std::static_pointer_cast<MockINetworkSearch>(networkSearchManager).get();
        mockTelRilManager = std::static_pointer_cast<MockTelRilManager>(telRilManager).get();
        
        coreService->simManager_ = simManager;
        coreService->networkSearchManager_ = networkSearchManager;
        coreService->telRilManager_ = telRilManager;
    }
    void TearDown()
    {
        coreService->simManager_ = nullptr;
        coreService->networkSearchManager_ = nullptr;
        coreService->telRilManager_ = nullptr;
    }
};

/****************************************************** GetImei *****************************************************/
HWTEST_F(CoreServiceTest, GetImei001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->GetImei(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, GetImei002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->GetImei(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, GetImei003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    coreService->networkSearchManager_ = nullptr;
    int32_t ret = coreService->GetImei(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetImei004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    int32_t ret = coreService->GetImei(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetImei005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->GetImei(0, directCall);
    coreService->networkSearchManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, GetImei006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockNetworkSearchManager, GetImei(_, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->GetImei(0, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/**************************************************** GetImeiSv *****************************************************/
HWTEST_F(CoreServiceTest, GetImeiSv001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->GetImeiSv(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, GetImeiSv002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->GetImeiSv(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, GetImeiSv003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    coreService->networkSearchManager_ = nullptr;
    int32_t ret = coreService->GetImeiSv(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetImeiSv004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    int32_t ret = coreService->GetImeiSv(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetImeiSv005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->GetImeiSv(0, directCall);
    coreService->networkSearchManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, GetImeiSv006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockNetworkSearchManager, GetImeiSv(_, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->GetImeiSv(0, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/**************************************************** IsCTSimCard ***************************************************/
HWTEST_F(CoreServiceTest, IsCTSimCard001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->IsCTSimCard(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, IsCTSimCard002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->IsCTSimCard(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, IsCTSimCard003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->IsCTSimCard(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, IsCTSimCard004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    SetDelayRunInHandler();
    int32_t ret = coreService->IsCTSimCard(0, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, IsCTSimCard005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, IsCTSimCard(_, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->IsCTSimCard(0, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/**************************************************** IsSimActive ***************************************************/
HWTEST_F(CoreServiceTest, IsSimActive001, Function | MediumTest | Level1)
{
    coreService->simManager_ = nullptr;
    bool ret = coreService->IsSimActive(0, nullptr);
    EXPECT_FALSE(ret);
}

HWTEST_F(CoreServiceTest, IsSimActive002, Function | MediumTest | Level1)
{
    bool ret = coreService->IsSimActive(0, nullptr);
    EXPECT_FALSE(ret);
}

HWTEST_F(CoreServiceTest, IsSimActive003, Function | MediumTest | Level1)
{
    SetDelayRunInHandler();
    bool ret = coreService->IsSimActive(0, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret);
}

HWTEST_F(CoreServiceTest, IsSimActive004, Function | MediumTest | Level1)
{
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, IsSimActive(_))
        .WillOnce(Return(true));
    bool ret = coreService->IsSimActive(0, directCall);
    EXPECT_TRUE(ret);
}

HWTEST_F(CoreServiceTest, IsSimActive005, Function | MediumTest | Level1)
{
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, IsSimActive(_))
        .WillOnce(Return(false));
    bool ret = coreService->IsSimActive(0, directCall);
    EXPECT_TRUE(ret);
}

/************************************************* GetDefaultVoiceSimId *********************************************/
HWTEST_F(CoreServiceTest, GetDefaultVoiceSimId001, Function | MediumTest | Level1)
{
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->GetDefaultVoiceSimId(nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetDefaultVoiceSimId002, Function | MediumTest | Level1)
{
    int32_t ret = coreService->GetDefaultVoiceSimId(nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetDefaultVoiceSimId003, Function | MediumTest | Level1)
{
    SetDelayRunInHandler();
    int32_t ret = coreService->GetDefaultVoiceSimId(directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, GetDefaultVoiceSimId004, Function | MediumTest | Level1)
{
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, GetDefaultVoiceSimId(_))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->GetDefaultVoiceSimId(directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/*************************************************** GetShowNumber **************************************************/
HWTEST_F(CoreServiceTest, GetShowNumber001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->GetShowNumber(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, GetShowNumber002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->GetShowNumber(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, GetShowNumber003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->GetShowNumber(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetShowNumber004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    int32_t ret = coreService->GetShowNumber(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetShowNumber005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->GetShowNumber(0, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, GetShowNumber006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, GetShowNumber(_, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->GetShowNumber(0, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/*************************************************** SetShowNumber **************************************************/
HWTEST_F(CoreServiceTest, SetShowNumber001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->SetShowNumber(0, u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, SetShowNumber002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->SetShowNumber(0, u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, SetShowNumber003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->SetShowNumber(0, u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, SetShowNumber004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    int32_t ret = coreService->SetShowNumber(0, u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, SetShowNumber005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->SetShowNumber(0, u"", directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, SetShowNumber006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, SetShowNumber(_, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->SetShowNumber(0, u"", directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/**************************************************** SetShowName ***************************************************/
HWTEST_F(CoreServiceTest, SetShowName001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->SetShowName(0, u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, SetShowName002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->SetShowName(0, u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, SetShowName003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->SetShowName(0, u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, SetShowName004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    int32_t ret = coreService->SetShowName(0, u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, SetShowName005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->SetShowName(0, u"", directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, SetShowName006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, SetShowName(_, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->SetShowName(0, u"", directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/**************************************************** GetShowName ***************************************************/
HWTEST_F(CoreServiceTest, GetShowName001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->GetShowName(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, GetShowName002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->GetShowName(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, GetShowName003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->GetShowName(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetShowName004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    int32_t ret = coreService->GetShowName(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetShowName005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->GetShowName(0, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, GetShowName006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, GetShowName(_, _))
        .WillOnce(DoAll(
            Invoke([](int32_t, std::u16string &name) { name = u"TestName"; return TELEPHONY_ERR_SUCCESS; }),
            Return(TELEPHONY_ERR_SUCCESS)));
    int32_t ret = coreService->GetShowName(0, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/***************************************************** UnlockPin ****************************************************/
HWTEST_F(CoreServiceTest, UnlockPin001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->UnlockPin(0, u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, UnlockPin002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->UnlockPin(0, u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, UnlockPin003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->UnlockPin(0, u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, UnlockPin004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    int32_t ret = coreService->UnlockPin(0, u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, UnlockPin005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->UnlockPin(0, u"", directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, UnlockPin006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, UnlockPin(_, _, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->UnlockPin(0, u"", directCall);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

/***************************************************** UnlockPin2 ***************************************************/
HWTEST_F(CoreServiceTest, UnlockPin2001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->UnlockPin2(0, u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, UnlockPin2002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->UnlockPin2(0, u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, UnlockPin2003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->UnlockPin2(0, u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, UnlockPin2004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    int32_t ret = coreService->UnlockPin2(0, u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, UnlockPin2005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->UnlockPin2(0, u"", directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, UnlockPin2006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, UnlockPin2(_, _, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->UnlockPin2(0, u"", directCall);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

/******************************************************* UnlockPuk **************************************************/
HWTEST_F(CoreServiceTest, UnlockPuk001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->UnlockPuk(0, u"", u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, UnlockPuk002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->UnlockPuk(0, u"", u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, UnlockPuk003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->UnlockPuk(0, u"", u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, UnlockPuk004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    int32_t ret = coreService->UnlockPuk(0, u"", u"", nullptr);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, UnlockPuk005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->UnlockPuk(0, u"", u"", directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, UnlockPuk006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, UnlockPuk(_, _, _, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->UnlockPuk(0, u"1234", u"5678", directCall);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

/******************************************************** UnlockPuk2 ************************************************/
HWTEST_F(CoreServiceTest, UnlockPuk2001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->UnlockPuk2(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, UnlockPuk2002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->UnlockPuk2(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, UnlockPuk2003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->UnlockPuk2(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, UnlockPuk2004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    int32_t ret = coreService->UnlockPuk2(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, UnlockPuk2005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->UnlockPuk2(0, u"", u"", directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, UnlockPuk2006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, UnlockPuk2(_, _, _, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->UnlockPuk2(0, u"", u"", directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/***************************************************** AlterPin *****************************************************/
HWTEST_F(CoreServiceTest, AlterPin001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->AlterPin(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, AlterPin002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->AlterPin(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, AlterPin003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->AlterPin(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, AlterPin004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    int32_t ret = coreService->AlterPin(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, AlterPin005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->AlterPin(0, u"", u"", directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, AlterPin006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, AlterPin(_, _, _, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->AlterPin(0, u"", u"", directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/***************************************************** AlterPin2 ****************************************************/
HWTEST_F(CoreServiceTest, AlterPin2001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->AlterPin2(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, AlterPin2002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->AlterPin2(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, AlterPin2003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->AlterPin2(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, AlterPin2004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    int32_t ret = coreService->AlterPin2(0, u"", u"", nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, AlterPin2005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->AlterPin2(0, u"", u"", directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, AlterPin2006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, AlterPin2(_, _, _, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->AlterPin2(0, u"", u"", directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/**************************************************** SetLockState **************************************************/
HWTEST_F(CoreServiceTest, SetLockState001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    LockInfo options = {};
    int32_t ret = coreService->SetLockState(0, options, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, SetLockState002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    LockInfo options = {};
    int32_t ret = coreService->SetLockState(0, options, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, SetLockState003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    LockInfo options = {};
    int32_t ret = coreService->SetLockState(0, options, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, SetLockState004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    LockInfo options = {};
    int32_t ret = coreService->SetLockState(0, options, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, SetLockState005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    LockInfo options = {};
    int32_t ret = coreService->SetLockState(0, options, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, SetLockState006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::SET_TELEPHONY_STATE);
    SetRunInCaller();
    LockInfo options = {};
    EXPECT_CALL(*mockSimManager, SetLockState(_, _, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->SetLockState(0, options, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/**************************************************** GetLockState **************************************************/
HWTEST_F(CoreServiceTest, GetLockState001, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(false);
    int32_t ret = coreService->GetLockState(0, LockType::PIN_LOCK, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

HWTEST_F(CoreServiceTest, GetLockState002, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    int32_t ret = coreService->GetLockState(0, LockType::PIN_LOCK, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_PERMISSION_ERR);
}

HWTEST_F(CoreServiceTest, GetLockState003, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->GetLockState(0, LockType::PIN_LOCK, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetLockState004, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    int32_t ret = coreService->GetLockState(0, LockType::PIN_LOCK, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetLockState005, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetDelayRunInHandler();
    int32_t ret = coreService->GetLockState(0, LockType::PIN_LOCK, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, GetLockState006, Function | MediumTest | Level1)
{
    TelephonyPermissionTestHelper helper(true);
    helper.GrantPermission(Permission::GET_TELEPHONY_STATE);
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, GetLockState(_, _, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->GetLockState(0, LockType::PIN_LOCK, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/***************************************************** HasSimCard ***************************************************/
HWTEST_F(CoreServiceTest, HasSimCard001, Function | MediumTest | Level1)
{
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->HasSimCard(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, HasSimCard002, Function | MediumTest | Level1)
{
    int32_t ret = coreService->HasSimCard(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, HasSimCard003, Function | MediumTest | Level1)
{
    SetDelayRunInHandler();
    int32_t ret = coreService->HasSimCard(0, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, HasSimCard004, Function | MediumTest | Level1)
{
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, HasSimCard(,))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->HasSimCard(0, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/***************************************************** GetSimState **************************************************/
HWTEST_F(CoreServiceTest, GetSimState001, Function | MediumTest | Level1)
{
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->GetSimState(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetSimState002, Function | MediumTest | Level1)
{
    int32_t ret = coreService->GetSimState(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, GetSimState003, Function | MediumTest | Level1)
{
    SetDelayRunInHandler();
    int32_t ret = coreService->GetSimState(0, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, GetSimState004, Function | MediumTest | Level1)
{
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, GetSimState(_, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->GetSimState(0, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

/************************************************* HasOperatorPrivileges ********************************************/
HWTEST_F(CoreServiceTest, HasOperatorPrivileges001, Function | MediumTest | Level1)
{
    coreService->simManager_ = nullptr;
    int32_t ret = coreService->HasOperatorPrivileges(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, HasOperatorPrivileges002, Function | MediumTest | Level1)
{
    int32_t ret = coreService->HasOperatorPrivileges(0, nullptr);
    EXPECT_TRUE(ret == TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(CoreServiceTest, HasOperatorPrivileges003, Function | MediumTest | Level1)
{
    SetDelayRunInHandler();
    int32_t ret = coreService->HasOperatorPrivileges(0, directCall);
    coreService->simManager_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreServiceTest, HasOperatorPrivileges004, Function | MediumTest | Level1)
{
    SetRunInCaller();
    EXPECT_CALL(*mockSimManager, HasOperatorPrivileges(_, _))
        .WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    int32_t ret = coreService->HasOperatorPrivileges(0, directCall);
    EXPECT_TRUE(ret == TELEPHONY_ERR_SUCCESS);
}
}
}
}