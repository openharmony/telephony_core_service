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
#include <future>
#include <gtest/gtest.h>
#include <string_ex.h>

#include "core_manager_inner.h"
#include "core_service.h"
#include "icc_dialling_numbers_handler.h"
#include "icc_dialling_numbers_manager.h"
#include "icc_file_controller.h"
#include "icc_operator_privilege_controller.h"
#include "mcc_pool.h"
#include "operator_config_cache.h"
#include "operator_config_loader.h"
#include "parcel.h"
#include "plmn_file.h"
#include "sim_account_manager.h"
#include "sim_data_type.h"
#include "sim_file_controller.h"
#include "sim_manager.h"
#include "sim_rdb_helper.h"
#include "sim_sms_manager.h"
#include "telephony_ext_wrapper.h"
#include "telephony_log_wrapper.h"
#include "usim_dialling_numbers_service.h"
#include "want.h"
#include "sim_constant.h"
#include "mock_tel_ril_manager.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;

class DemoHandler : public AppExecFwk::EventHandler {
public:
    explicit DemoHandler(std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner) {}
    virtual ~DemoHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}
};

class SimStateHandleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const int32_t slotId = 10;
    static MockTelRilManager *telRilManager_;
    static std::shared_ptr<SimStateManager> simStateManager_;
};

MockTelRilManager *SimStateHandleTest::telRilManager_;
std::shared_ptr<SimStateManager> SimStateHandleTest::simStateManager_;

void SimStateHandleTest::SetUpTestCase()
{
    telRilManager_ = new MockTelRilManager();
    std::shared_ptr<MockTelRilManager> telRilManager(telRilManager_);
    simStateManager_ = std::make_shared<SimStateManager>(telRilManager);
    simStateManager_->Init(10);
    EXPECT_CALL(*telRilManager_, UnRegisterCoreNotify(_, _, _))
        .WillRepeatedly(Return(0));
}

void SimStateHandleTest::TearDownTestCase()
{
    Mock::AllowLeak(telRilManager_);
    telRilManager_ = nullptr;
    simStateManager_->telRilManager_ = nullptr;
}

void SimStateHandleTest::SetUp() {}

void SimStateHandleTest::TearDown() {}

/**
 * @tc.number   Telephony_SimStateHandle_001
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_001, Function | MediumTest | Level1)
{
    LockInfo options;
    options.lockType = LockType::PIN_LOCK;
    options.lockState = LockState::LOCK_OFF;
    std::shared_ptr<ITelRilManager> telRilManager1 = std::make_shared<TelRilManager>();
    std::weak_ptr<Telephony::ITelRilManager> weakTelRilManager = telRilManager1;
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager_);
    simStateHandle->SetRilManager(weakTelRilManager);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_ENABLE_PIN_DONE);
    ASSERT_NE(event, nullptr);
    simStateHandle->SetLockState(slotId, options);
}

/**
 * @tc.number   Telephony_SimStateHandle_002
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_002, Function | MediumTest | Level1)
{
    LockInfo options;
    options.lockType = LockType::FDN_LOCK;
    options.lockState = LockState::LOCK_ON;
    std::shared_ptr<ITelRilManager> telRilManager1 = nullptr;
    std::weak_ptr<Telephony::ITelRilManager> weakTelRilManager = telRilManager1;
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager_);
    simStateHandle->SetRilManager(weakTelRilManager);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_ENABLE_PIN_DONE);
    ASSERT_NE(event, nullptr);
    simStateHandle->SetLockState(slotId, options);
}

/**
 * @tc.number   Telephony_SimStateHandle_003
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_003, Function | MediumTest | Level1)
{
    LockType lockType = LockType::PIN_LOCK;
    std::shared_ptr<ITelRilManager> telRilManager1 = std::make_shared<TelRilManager>();
    std::weak_ptr<Telephony::ITelRilManager> weakTelRilManager = telRilManager1;
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager_);
    simStateHandle->SetRilManager(weakTelRilManager);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHECK_PIN_DONE);
    ASSERT_NE(event, nullptr);
    simStateHandle->GetLockState(slotId, lockType);
}

/**
 * @tc.number   Telephony_SimStateHandle_004
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_004, Function | MediumTest | Level1)
{
    LockType lockType = LockType::FDN_LOCK;
    std::shared_ptr<ITelRilManager> telRilManager1 = nullptr;
    std::weak_ptr<Telephony::ITelRilManager> weakTelRilManager = telRilManager1;
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager_);
    simStateHandle->SetRilManager(weakTelRilManager);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHECK_PIN_DONE);
    ASSERT_NE(event, nullptr);
    simStateHandle->GetLockState(slotId, lockType);
}

/**
 * @tc.number   Telephony_SimStateHandle_005
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_005, Function | MediumTest | Level1)
{
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager_);
    int32_t ret = simStateHandle->IsSatelliteSupported();
    EXPECT_GE(ret, 0);
    simStateHandle->UnregisterSatelliteCallback();
}

/**
 * @tc.number   Telephony_SimStateHandle_006
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_006, Function | MediumTest | Level1)
{
    SimIoRequestInfo requestInfo;
    std::shared_ptr<ITelRilManager> telRilManager1 = std::make_shared<TelRilManager>();
    std::weak_ptr<Telephony::ITelRilManager> weakTelRilManager = telRilManager1;
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager_);
    simStateHandle->SetRilManager(weakTelRilManager);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_SIM_IO_DONE);
    ASSERT_NE(event, nullptr);
    int32_t ret = simStateHandle->GetSimIO(slotId, requestInfo);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   Telephony_SimStateHandle_007
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_007, Function | MediumTest | Level1)
{
    SimIoRequestInfo requestInfo;
    std::shared_ptr<ITelRilManager> telRilManager1 = nullptr;
    std::weak_ptr<Telephony::ITelRilManager> weakTelRilManager = telRilManager1;
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager_);
    simStateHandle->SetRilManager(weakTelRilManager);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_SIM_IO_DONE);
    ASSERT_NE(event, nullptr);
    int32_t ret = simStateHandle->GetSimIO(slotId, requestInfo);
    EXPECT_EQ(ret, SIM_AUTH_FAIL);
}

/**
 * @tc.number   Telephony_SimStateHandle_008
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_008, Function | MediumTest | Level1)
{
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(1, 1);
    ASSERT_NE(event, nullptr);
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager_);
    simStateHandle->GetSimIOResult(slotId, event);
}

/**
 * @tc.number   Telephony_SimStateHandle_009
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_009, Function | MediumTest | Level1)
{
    auto future = std::async(std::launch::async, [this]() {
        simStateManager_->simStateHandle_->SetSimState(SimState::SIM_STATE_LOCKED);
        LockStatusResponse response;
        simStateManager_->simStateHandle_->unlockRespon_.result = UNLOCK_OK;
        simStateManager_->simStateHandle_->unlockRespon_.remain = -1;
        simStateManager_->simStateHandle_->unlockRespon_.lockState = 1;
        simStateManager_->UnlockPin(slotId, "1234", response);
        EXPECT_TRUE(simStateManager_->simStateHandle_->GetSimState() == SimState::SIM_STATE_NOT_READY);
    });
    usleep(100 * 1000);
    simStateManager_->SyncUnlockPinResponse();
    usleep(100 * 1000);
    future.get();
}

/**
 * @tc.number   Telephony_SimStateHandle_011
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_010, Function | MediumTest | Level1)
{
    auto future = std::async(std::launch::async, [this]() {
        simStateManager_->simStateHandle_->SetSimState(SimState::SIM_STATE_LOADED);
        LockStatusResponse response;
        simStateManager_->simStateHandle_->unlockRespon_.result = UNLOCK_OK;
        simStateManager_->simStateHandle_->unlockRespon_.remain = -1;
        simStateManager_->simStateHandle_->unlockRespon_.lockState = 1;
        simStateManager_->UnlockPin(slotId, "1234", response);
        EXPECT_TRUE(simStateManager_->simStateHandle_->GetSimState() == SimState::SIM_STATE_LOADED);
    });
    usleep(100 * 1000);
    simStateManager_->SyncUnlockPinResponse();
    usleep(100 * 1000);
    future.get();
}

/**
 * @tc.number   Telephony_SimStateHandle_011
 * @tc.name     sst_test
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_011, Function | MediumTest | Level1)
{
    auto simFile_ = std::make_shared<SimFile>(simStateManager_);
    simFile_->fileController_ = std::make_shared<UsimFileController>(0);
    simFile_->serviceTable_ = "";
    EXPECT_FALSE(simFile_->IsServiceAvailable(UsimService::USIM_FDN));
    simFile_->serviceTable_ = "867F1F1C234E0000400050";
    EXPECT_TRUE(simFile_->IsServiceAvailable(UsimService::USIM_FDN));
    simFile_->serviceTable_ = "00000000000000000000";
    EXPECT_FALSE(simFile_->IsSimServiceAvailable(UsimService::USIM_SPN));
    EXPECT_FALSE(simFile_->IsSimServiceAvailable(UsimService::USIM_PLMN_NETWORK_NAME));
    EXPECT_TRUE(simFile_->IsSimServiceAvailable(UsimService::USIM_FDN));
}

/**
 * @tc.number   Telephony_SimStateHandle_012
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_012, Function | MediumTest | Level1)
{
    auto future = std::async(std::launch::async, [this]() {
        simStateManager_->simStateHandle_->SetSimState(SimState::SIM_STATE_LOADED);
        LockStatusResponse response;
        simStateManager_->simStateHandle_->unlockRespon_.result = UNLOCK_OK;
        simStateManager_->simStateHandle_->unlockRespon_.remain = -1;
        simStateManager_->simStateHandle_->unlockRespon_.lockState = 1;
        simStateManager_->UnlockPuk(slotId, "1234", "12345678", response);
        EXPECT_TRUE(simStateManager_->simStateHandle_->GetSimState() == SimState::SIM_STATE_LOADED);
    });
    usleep(100 * 1000);
    simStateManager_->SyncCmdResponse();
    usleep(100 * 1000);
    future.get();
}

/**
 * @tc.number   Telephony_SimStateHandle_013
 * @tc.name     test SimStateHandle
 * @tc.desc     Function test
 */
HWTEST_F(SimStateHandleTest, Telephony_SimStateHandle_013, Function | MediumTest | Level1)
{
    auto future = std::async(std::launch::async, [this]() {
        simStateManager_->simStateHandle_->SetSimState(SimState::SIM_STATE_LOCKED);
        LockStatusResponse response;
        simStateManager_->simStateHandle_->unlockRespon_.result = UNLOCK_OK;
        simStateManager_->simStateHandle_->unlockRespon_.remain = -1;
        simStateManager_->simStateHandle_->unlockRespon_.lockState = 1;
        simStateManager_->UnlockPuk(slotId, "1234", "12345678", response);
        EXPECT_TRUE(simStateManager_->simStateHandle_->GetSimState() == SimState::SIM_STATE_NOT_READY);
    });
    usleep(100 * 1000);
    simStateManager_->SyncCmdResponse();
    usleep(100 * 1000);
    future.get();
}
}
}