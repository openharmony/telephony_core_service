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

#include <string>
#include <set>
#include <unistd.h>
#include "sim_manager.h"
#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"
#include "gtest/gtest.h"
#include "tel_ril_manager.h"
#include "mock_tel_ril_manager.h"
#include "mock_sim_manager.h"
#include "sim_state_type.h"
#include "sim_rdb_helper.h"
#include "icc_file.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;

class SimManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static MockTelRilManager *telRilManager_;
    static std::shared_ptr<SimManager> simManager_;
};

MockTelRilManager *SimManagerTest::telRilManager_ = nullptr;
std::shared_ptr<SimManager> SimManagerTest::simManager_ = nullptr;

void SimManagerTest::SetUpTestCase()
{
    telRilManager_ = new MockTelRilManager();
    std::shared_ptr<MockTelRilManager> telRilManager(telRilManager_);
    simManager_ = std::make_shared<SimManager>(telRilManager);
    EXPECT_CALL(*telRilManager_, UnRegisterCoreNotify(_, _, _))
        .WillRepeatedly(Return(0));
}

void SimManagerTest::TearDownTestCase()
{
    Mock::AllowLeak(telRilManager_);
    telRilManager_ = nullptr;
    simManager_->telRilManager_ = nullptr;
}

void SimManagerTest::SetUp() {}

void SimManagerTest::TearDown() {}

/**
 * @tc.number   Telephony_Sim_SimManager_0100
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t ret = simManager_->InitTelExtraModule(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERROR);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0200
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_002, Function | MediumTest | Level1)
{
    int32_t simId = 0;
    int32_t ret = simManager_->GetDefaultSmsSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0300
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_003, Function | MediumTest | Level1)
{
    int32_t simId = 0;
    int32_t ret = simManager_->GetDefaultCellularDataSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0400
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_004, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t ret = simManager_->UpdateOperatorConfigs(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0500
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_005, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "ABCDEFG";
    std::string path = "";
    SimAuthenticationResponse mResponse;
    IccSimStatus iccStatus = IccSimStatus::ICC_CONTENT_READY;
    CardType cardType = CardType::SINGLE_MODE_USIM_CARD;

    int32_t ret = simManager_->GetSimIO(slotId, command, fileId, data, path, mResponse);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
    auto simManager = std::make_shared<MockSimManager>();
    EXPECT_CALL(*simManager, HasSimCard(slotId, _))
        .WillRepeatedly(Return(true));
    simManager->GetSimIccStatus(slotId, iccStatus);
    simManager->GetCardType(slotId, cardType);
    ret = simManager->GetSimIO(slotId, command, fileId, data, path, mResponse);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_SimManager_006
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_006, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    simManager_->UpdateImsCapFromChip(slotId, {0, 0, 0, 0});
    EXPECT_EQ(slotId, 0);
}

/**
 * @tc.number   Telephony_Sim_SimManager_007
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_007, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    simManager_->UpdateImsCapFromChip(slotId, {0, 0, 0, 0});
    EXPECT_EQ(slotId, -1);
}

/**
 * @tc.number   Telephony_Sim_SimManager_008
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_008, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    simManager_->UpdateImsCapFromChip(slotId, {0, 0, 0, 0});
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

/**
 * @tc.number   Telephony_Sim_SimManager_009
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_009, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::set<std::string> ehPlmns;
    std::set<std::string> spdiPlmns;
    simManager_->GetEhPlmns(slotId, ehPlmns);
    simManager_->GetSpdiPlmns(slotId, spdiPlmns);
    simManager_->slotCount_  = -1;
    simManager_->InitMultiSimObject();
    simManager_->slotCount_  = 10;
    simManager_->InitMultiSimObject();
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

/**
 * @tc.number   Telephony_Sim_SimManager_010
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_010, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    simManager_->SetActiveSim(slotId, 0);
    slotId = -1;
    simManager_->SetActiveSim(slotId, 0);
    slotId = 4;
    simManager_->SetActiveSim(slotId, 0);
    slotId = 0;
    simManager_->multiSimController_ = nullptr;
    simManager_->SetActiveSim(slotId, 0);
    simManager_->SetActiveSim(slotId, 0);
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

/**
 * @tc.number   Telephony_Sim_SimManager_011
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_011, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    simManager_->SetActiveSimSatellite(slotId, 0);
    slotId = -1;
    simManager_->SetActiveSimSatellite(slotId, 0);
    slotId = 4;
    simManager_->SetActiveSimSatellite(slotId, 0);
    slotId = 0;
    simManager_->multiSimController_ = nullptr;
    simManager_->SetActiveSimSatellite(slotId, 0);
    telRilManager_ = new MockTelRilManager();
    simManager_->SetActiveSimSatellite(slotId, 0);
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

/**
 * @tc.number   Telephony_Sim_SimManager_012
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_012, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    simManager_->SetDefaultCellularDataSlotId(slotId);
    simManager_->ResetSimLoadAccount(slotId);
    slotId = -1;
    simManager_->SetDefaultCellularDataSlotId(slotId);
    simManager_->ResetSimLoadAccount(slotId);
    slotId = 4;
    simManager_->ResetSimLoadAccount(slotId);
    slotId = 0;
    simManager_->multiSimController_ = nullptr;
    simManager_->ResetSimLoadAccount(slotId);
    simManager_->ResetSimLoadAccount(slotId);
    simManager_->SetDefaultCellularDataSlotId(slotId);
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

HWTEST_F(SimManagerTest, GetSimIccStatustest, Function | MediumTest | Level1)
{
    IccSimStatus status;
    int32_t result = simManager_->GetSimIccStatus(-1, status);
    EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);

    simManager_->simStateManager_.resize(MAX_SLOT_COUNT);
    result = simManager_->InitTelExtraModule(SIM_SLOT_2);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);

    result = simManager_->InitTelExtraModule(SIM_SLOT_2);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimManagerTest, SetModemInittest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    bool state = true;
    int32_t result = simManager_->SetModemInit(slotId, state);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = -1;
    state = true;
    result = simManager_->SetModemInit(slotId, state);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    state = true;
    simManager_->simStateManager_[slotId] = nullptr;
    result = simManager_->SetModemInit(slotId, state);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimManagerTest, UnlockPintest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::string pin = "1234";
    LockStatusResponse response;
    simManager_->simStateManager_[slotId] = nullptr;
    int32_t result = simManager_->UnlockPin(slotId, pin, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPin2(slotId, pin, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);

    slotId = 0;
    std::string correctPin = "1234";
    
    result = simManager_->UnlockPin(slotId, correctPin, response);
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    result = simManager_->UnlockPin2(slotId, correctPin, response);
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);

    slotId = 0;
    std::string wrongPin = "1235";
    
    result = simManager_->UnlockPin(slotId, wrongPin, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPin2(slotId, wrongPin, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(SimManagerTest, SetLockStatetest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    LockInfo options;
    LockStatusResponse response;
    
    simManager_->simStateManager_[slotId] = nullptr;
    int32_t result = simManager_->SetLockState(slotId, options, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(SimManagerTest, RefreshSimStatetest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t result = simManager_->RefreshSimState(slotId);
    EXPECT_EQ(result, TELEPHONY_ERROR);

    slotId = -1;
    result = simManager_->RefreshSimState(slotId);
    EXPECT_EQ(result, TELEPHONY_ERROR);

    slotId = 1;
    simManager_->simStateManager_[slotId] = nullptr;
    result = simManager_->RefreshSimState(slotId);
    EXPECT_EQ(result, TELEPHONY_ERROR);
}

HWTEST_F(SimManagerTest, UnlockPuktest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::string newPin = "1234";
    std::string correctPuk = "123456";
    LockStatusResponse response;
    int32_t result = simManager_->UnlockPuk(slotId, newPin, correctPuk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPuk2(slotId, newPin, correctPuk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);

    slotId = 0;
    newPin = "1234";
    std::string wrongPuk = "123457";
    
    result = simManager_->UnlockPuk(slotId, newPin, wrongPuk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPuk2(slotId, newPin, wrongPuk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);

    slotId = -1;
    newPin = "1234";
    std::string puk = "123456";
    
    result = simManager_->UnlockPuk(slotId, newPin, puk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPuk(slotId, newPin, puk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(SimManagerTest, GetLockStatetest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    // LockType lockType;
    LockState lockState;
    
    int32_t result = simManager_->GetLockState(slotId, LockType::PIN_LOCK, lockState);
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);

    slotId = -1;
    result = simManager_->GetLockState(slotId, LockType::PIN_LOCK, lockState);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);

    slotId = 0;
    
    simManager_->simStateManager_[slotId] = nullptr;
    result = simManager_->GetLockState(slotId, LockType::PIN_LOCK, lockState);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
}
}
}