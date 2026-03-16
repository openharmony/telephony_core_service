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
#define private public
#define protected public

#include <string>
#include <unistd.h>
#include "gtest/gtest.h"
#include "sim_constant.h"
#include "sim_manager.h"
#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"

#include "multi_sim_controller.h"
#include "mock_sim_fil_manage.h"
#include "mock_multi_sim_controller.h"
#include "mock_sim_rdb_helper.h"
#include "mock_sim_manager.h"
#include "tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_ext_wrapper.h"
#include "mock_sim_manager.h"
#include "multi_sim_helper.h"
#include "sim_cache_sync_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;
const int SLOT_COUNT = 2;
static const std::string ESIM_SUPPORT_PARAM = "const.ril.esim_type";
const std::string LAST_DEACTIVE_PROFILE_SLOT0 = "persist.telephony.last_deactive_profile0";
const std::string LAST_DEACTIVE_PROFILE_SLOT1 = "persist.telephony.last_deactive_profile1";
const std::string SUPPORT_ESIM_MEP = "const.ril.sim.esim_support_mep";
constexpr int32_t PSIM1 = 1;
constexpr int32_t PSIM2 = 2;
class MultiSimControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void MultiSimControllerTest::SetUpTestCase() {}

void MultiSimControllerTest::TearDownTestCase() {}

void MultiSimControllerTest::SetUp() {}

void MultiSimControllerTest::TearDown() {}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_Init_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    multiSimController->ResetDataShareError();
    multiSimController->radioProtocolController_ = nullptr;
    multiSimController->Init();
    multiSimController->radioProtocolController_ = radioProtocolController;
    multiSimController->GetRadioProtocol(1);
    EXPECT_EQ(multiSimController->isSetActiveSimInProgress_.size(), SIM_SLOT_COUNT);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_ForgetAllData_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
    bool ret = multiSimController->ForgetAllData();
    multiSimController->CleanLoadedSimInfo(0);
    multiSimController->ResetDataShareError();
    EXPECT_FALSE(ret);
    OHOS::system::SetParameter(SUPPORT_ESIM_MEP, "true");
    ret = multiSimController->ForgetAllData();
    multiSimController->ResetDataShareError();
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_ForgetAllDataWithSlotId_001, Function | MediumTest | Level1)
{
    int slotId = -1;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
    bool ret = multiSimController->ForgetAllData(slotId);
    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    multiSimController->ForgetAllData(slotId);

    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_UpdateOpKeyInfo_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
    bool ret = multiSimController->UpdateOpKeyInfo();
    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    multiSimController->UpdateOpKeyInfo();
    EXPECT_TRUE(ret);
    multiSimController->simDbHelper_ = nullptr;
    EXPECT_EQ(multiSimController->UpdateOpKeyInfo(), TELEPHONY_ERROR);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InitData_001, Function | MediumTest | Level1)
{
    int32_t slotId = DEFAULT_SIM_SLOT_ID - 1;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    bool ret = multiSimController->InitData(slotId);
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InitData_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager;
    simStateManager.push_back(simStateManager0);
    
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager0);
    simFileManager->simFile_ = std::make_shared<SimFile>(simStateManager0);
    
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    simFileManager_.push_back(simFileManager);
    
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager_);
    
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;

    bool ret = multiSimController->InitData(0);
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InitData_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager;
    simStateManager.push_back(simStateManager0);
    
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager0);
    simFileManager->simFile_ = std::make_shared<SimFile>(simStateManager0);
    
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    simFileManager_.push_back(simFileManager);
    
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager_);
    
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;

    auto multiSimControllerMock = std::make_shared<MultiSimControllerMock>(telRilManager,
        simStateManager, simFileManager_);
    EXPECT_CALL(*multiSimControllerMock, InitIccId(0)).WillRepeatedly(Return(true));
    EXPECT_CALL(*multiSimControllerMock, IsValidData(0)).WillRepeatedly(Return(true));

    bool ret = multiSimController->InitData(0);
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InitActive_001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { simStateManager0, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    bool ret = multiSimController->InitActive(slotId);
    EXPECT_TRUE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_ReCheckPrimary_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { simStateManager0, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->maxCount_ = 1;
    multiSimController->ReCheckPrimary();
    EXPECT_NE(multiSimController->simStateManager_[0], nullptr);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_IsAllCardsLoaded_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { simStateManager0, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;
    bool ret = multiSimController->IsAllCardsLoaded();
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_IsAllCardsLoaded_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { simStateManager0, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;
    bool ret = multiSimController->IsAllCardsLoaded();
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InitIccId_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager;
    simStateManager.push_back(simStateManager0);
    
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager0);
    simFileManager->simFile_ = std::make_shared<SimFile>(simStateManager0);
    
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    simFileManager_.push_back(simFileManager);
    
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager_);
    
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;
    
    bool ret = multiSimController->InitIccId(0);
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InitIccId_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager;
    simStateManager.push_back(simStateManager0);
    
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager0);
    simFileManager->simFile_ = std::make_shared<SimFile>(simStateManager0);
    
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    simFileManager_.push_back(simFileManager);
    
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager_);
    
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;

    auto mockSimRdbHelper = std::make_shared<MockSimRdbHelper>();
    EXPECT_CALL(*mockSimRdbHelper, QueryDataByIccId(_, _)).WillRepeatedly(Return(INVALID_VALUE));
    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    bool ret = multiSimController->InitIccId(0);
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InitIccId_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager;
    simStateManager.push_back(simStateManager0);
    
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager0);
    simFileManager->simFile_ = std::make_shared<SimFile>(simStateManager0);
    
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    simFileManager_.push_back(simFileManager);
    
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager_);
    
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;

    auto mockSimRdbHelper = std::make_shared<MockSimRdbHelper>();
    EXPECT_CALL(*mockSimRdbHelper, QueryDataByIccId(_, _)).WillRepeatedly(Return(TELEPHONY_SUCCESS));
    EXPECT_CALL(*mockSimRdbHelper, UpdateDataByIccId(_, _)).WillRepeatedly(Return(INVALID_VALUE));
    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    bool ret = multiSimController->InitIccId(0);
    EXPECT_FALSE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_GetShowNumber_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    simStateManager0->Init(0);
    simStateManager0->simStateHandle_->iccState_.simStatus_ = ICC_CONTENT_READY;
 
    auto simStateManager1 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    simStateManager1->Init(1);
    simStateManager1->simStateHandle_->iccState_.simStatus_ = ICC_CONTENT_READY;
 
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager_ = { simStateManager0, simStateManager1 };
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager0);
    simFileManager->simFile_ = std::make_shared<SimFile>(simStateManager0);
    simFileManager->simFile_->msisdn_ = "2164181618486135";
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_ = { simFileManager, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager_, simFileManager_);
    multiSimController->maxCount_ = 2;
    multiSimController->Init();

    std::vector<SimRdbInfo> newCache;
    newCache.resize(1);
    std::u16string showNumber = u"";
    newCache[0].phoneNumber = "2164181618486135";
    multiSimController->simStateManager_ = { simStateManager0, simStateManager1 };
    multiSimController->localCacheInfo_ = newCache;
    int32_t result = multiSimController->GetShowNumber(0, showNumber);
    EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    result = multiSimController->GetShowNumber(1, showNumber);
 
    newCache[0].phoneNumber = "2164181618486139";
    multiSimController->localCacheInfo_ = newCache;
    result = multiSimController->GetShowNumber(0, showNumber);
    EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_UpdateDataByIccId_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    radioProtocolController->Init();
    multiSimController->simDbHelper_ = nullptr;

    multiSimController->maxCount_ = 2;
    multiSimController->Init();
    auto ret = multiSimController->UpdateDataByIccId(0, "000011111");

    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    multiSimController->UpdateDataByIccId(1, "000011111");

    EXPECT_EQ(ret, INVALID_VALUE);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_UpdateDataByIccId_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    radioProtocolController->Init();
    multiSimController->simDbHelper_ = std::make_unique<MockSimRdbHelper>();
    auto simDb = static_cast<MockSimRdbHelper*>(multiSimController->simDbHelper_.get());

    OHOS::system::SetParameter(SUPPORT_ESIM_MEP, "true");
    EXPECT_CALL(*simDb, UpdateDataByIccId(_, _)).WillRepeatedly(Return(TELEPHONY_SUCCESS));
    auto ret = multiSimController->UpdateDataByIccId(0, "00002222");
    multiSimController->UpdateDataByIccId(1, "00002222");
    EXPECT_EQ(ret, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InsertData_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    multiSimController->simDbHelper_ = nullptr;

    multiSimController->maxCount_ = 2;
    multiSimController->Init();
    auto ret = multiSimController->InsertData(0, "000011111");

    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    multiSimController->InsertData(1, "000011111");

    multiSimController->UpdateSubState(0, 1);

    EXPECT_EQ(ret, INVALID_VALUE);

    multiSimController->InsertData(0, "01234567890");
    EXPECT_EQ(ret, INVALID_VALUE);

    OHOS::system::SetParameter(SUPPORT_ESIM_MEP, "true");
    multiSimController->InsertData(0, "01234567890");
    EXPECT_EQ(ret, INVALID_VALUE);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_GetEsimLabelIdx_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    multiSimController->simDbHelper_ = nullptr;
    multiSimController->maxCount_ = 2;
    multiSimController->Init();

    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[0].isEsim = 1;
    newCache[0].simLabelIndex = 2;
    newCache[1].iccId.clear();
    multiSimController->allLocalCacheInfo_ = newCache;

    auto ret = multiSimController->GetEsimLabelIdx();
    EXPECT_EQ(ret, 2);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InsertDataMep_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    multiSimController->simDbHelper_ = nullptr;

    multiSimController->maxCount_ = 2;
    multiSimController->Init();
    OHOS::system::SetParameter(SUPPORT_ESIM_MEP, "true");
    auto ret = multiSimController->InsertData(0, "000011111");
    EXPECT_EQ(ret, INVALID_VALUE);

    multiSimController->simDbHelper_ = std::make_unique<MockSimRdbHelper>();
    auto simDb = static_cast<MockSimRdbHelper*>(multiSimController->simDbHelper_.get());
    EXPECT_CALL(*simDb, UpdateDataByIccId(_, _)).WillRepeatedly(Return(TELEPHONY_SUCCESS));
    ret = multiSimController->InsertData(1, "00002222");
    EXPECT_EQ(ret, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_SetPrimarySlotId_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->RefreshSimManagerCache();
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    multiSimController->simDbHelper_ = nullptr;

    multiSimController->maxCount_ = 2;
    multiSimController->Init();
    auto ret = multiSimController->SetPrimarySlotId(0, false);

    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    multiSimController->SetPrimarySlotId(1, false);

    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);

    multiSimController->isRilSetPrimarySlotSupport_ = true;
    multiSimController->SetPrimarySlotId(1, true);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_SetPrimarySlotId_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    multiSimController->simDbHelper_ = nullptr;
    multiSimController->maxCount_ = 2;
    multiSimController->Init();
    multiSimController->isRilSetPrimarySlotSupport_ = true;
    multiSimController->isSettingPrimarySlotToRil_ = true;
    EXPECT_FALSE(multiSimController->SetPrimarySlotToRil(0));

    multiSimController->isSettingPrimarySlotToRil_ = false;
    telRilManager = nullptr;
    multiSimController->SetPrimarySlotToRil(0);
    multiSimController->SendSetPrimarySlotEvent(0);
}

HWTEST_F(MultiSimControllerTest, GetSimLabelMeptest_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    OHOS::system::SetParameter(SUPPORT_ESIM_MEP, "true");
    OHOS::system::SetParameter("persist.ril.sim_switch", "0");
    int32_t slotId = 0;
    SimLabel simLabel;
    OHOS::system::SetParameter(ESIM_SUPPORT_PARAM, "0");
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
 
    std::shared_ptr<MockSimManager> mockeSimManager = std::make_shared<MockSimManager>();
    EXPECT_CALL(*mockeSimManager, IsEsim(_)).WillRepeatedly(
        Return(false));
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simLabel.index, PSIM1);

    slotId = 1;
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simLabel.index, PSIM2);
}

HWTEST_F(MultiSimControllerTest, GetSimLabelMeptest_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    OHOS::system::SetParameter(SUPPORT_ESIM_MEP, "true");
    OHOS::system::SetParameter("persist.ril.sim_switch", "1");
    int32_t slotId = 0;
    SimLabel simLabel;
    OHOS::system::SetParameter(ESIM_SUPPORT_PARAM, "0");
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
 
    std::shared_ptr<MockSimManager> mockeSimManager = std::make_shared<MockSimManager>();
    EXPECT_CALL(*mockeSimManager, IsEsim(_)).WillRepeatedly(
        Return(false));
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simLabel.index, PSIM1);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_ProcessEvent_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    multiSimController->simDbHelper_ = nullptr;

    multiSimController->maxCount_ = 2;
    multiSimController->Init();
    multiSimController->isRilSetPrimarySlotSupport_ = true;
    AppExecFwk::InnerEvent::Pointer event1 = AppExecFwk::InnerEvent::
        Get(RADIO_SIM_SET_PRIMARY_SLOT, 0);
    multiSimController->ProcessEvent(event1);
    AppExecFwk::InnerEvent::Pointer event2 = AppExecFwk::InnerEvent::
        Get(RADIO_SIM_SET_PRIMARY_SLOT, 0);
    multiSimController->ProcessEvent(event2);
    auto nullEvent = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    multiSimController->OnRilSetPrimarySlotDone(nullEvent);
    multiSimController->OnRilSetPrimarySlotTimeout(nullEvent);
    EXPECT_FALSE(multiSimController->setPrimarySlotResponseResult_);
}

HWTEST_F(MultiSimControllerTest, GetSimLabelIdxFromAllLocalCache, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
 
    int32_t simIdx = 0;
    SimRdbInfo simRdb1;
    simRdb1.simLabelIndex = 3;
    std::vector<SimRdbInfo> cache;
    {
        std::unique_lock<ffrt::shared_mutex> lock(multiSimController->mutex_);
        cache = multiSimController->allLocalCacheInfo_;
        cache.push_back(simRdb1);
    }
    multiSimController->GetSimLabelIdxFromAllLocalCache(simIdx, 1);
    EXPECT_EQ(simIdx, 1);
 
    OHOS::system::SetParameter("persist.telephony.last_deactive_profile1", "1");
    multiSimController->GetSimLabelIdxFromAllLocalCache(simIdx, 1);
    EXPECT_EQ(simIdx, 3);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_SendMainCardBroadCast_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    multiSimController->simDbHelper_ = nullptr;

    multiSimController->maxCount_ = 2;
    multiSimController->Init();
    multiSimController->SendMainCardBroadCast(1);

    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;
    multiSimController->ResetSetPrimarySlotRemain(0);
    multiSimController->ResetSetPrimarySlotRemain(-1);
    multiSimController->ResetSetPrimarySlotRemain(5);
    multiSimController->SendMainCardBroadCast(0);
    multiSimController->SendDefaultCellularDataBroadCast(0);
    EXPECT_EQ(multiSimController->localCacheInfo_.size(), 2);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_GetSimTelephoneNumber_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    simStateManager0->Init(0);
    simStateManager0->simStateHandle_->iccState_.simStatus_ = ICC_CONTENT_READY;
 
    auto simStateManager1 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    simStateManager1->Init(1);
    simStateManager1->simStateHandle_->iccState_.simStatus_ = ICC_CONTENT_READY;
 
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager_ = { simStateManager0, simStateManager1 };
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager0);
    simFileManager->simFile_ = std::make_shared<SimFile>(simStateManager0);
    simFileManager->simFile_->msisdn_ = "2164181618486135";
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_ = { simFileManager, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager_, simFileManager_);
    multiSimController->maxCount_ = 2;
    multiSimController->Init();

    std::vector<SimRdbInfo> newCache;
    newCache.resize(1);
    std::u16string showNumber = u"";
    newCache[0].phoneNumber = "2164181618486135";
    multiSimController->simStateManager_ = { simStateManager0, simStateManager1 };
    multiSimController->localCacheInfo_ = newCache;
    int32_t result = multiSimController->GetSimTelephoneNumber(0, showNumber);
    EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    result = multiSimController->GetSimTelephoneNumber(1, showNumber);
 
    newCache[0].phoneNumber = "2164181618486139";
    multiSimController->localCacheInfo_ = newCache;
    result = multiSimController->GetSimTelephoneNumber(0, showNumber);
    EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, BuildRadioProtocolForCommunication_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    radioProtocolController->slotCount_ = 2;
    radioProtocolController->Init();
    radioProtocolController->BuildRadioProtocolForCommunication(
        RadioProtocolPhase::RADIO_PROTOCOL_PHASE_CHECK, RadioProtocolStatus::RADIO_PROTOCOL_STATUS_FAIL);
    EXPECT_EQ(multiSimController->localCacheInfo_.size(), 0);
}

HWTEST_F(MultiSimControllerTest, WhenForgetAllDataReturnsValidValue, Function | MediumTest | Level1)
{
    MockSimRdbHelper mockSimRdbHelper;
    EXPECT_CALL(mockSimRdbHelper, ForgetAllData())
        .WillRepeatedly(Return(1));
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    EXPECT_FALSE(multiSimController->ForgetAllData());
}

HWTEST_F(MultiSimControllerTest, WhenForgetAllDataReturnsInvalidValue, Function | MediumTest | Level1)
{
    MockSimRdbHelper mockSimRdbHelper;
    EXPECT_CALL(mockSimRdbHelper, ForgetAllData())
        .WillRepeatedly(Return(0));
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->CleanLoadedSimInfo(-1);
    multiSimController->CleanLoadedSimInfo(0);
    multiSimController->CleanLoadedSimInfo(4);
    EXPECT_FALSE(multiSimController->ForgetAllData());
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_SetPrimarySlotId_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager;
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager;
    simStateManager.resize(SLOT_COUNT);
    simFileManager.resize(SLOT_COUNT);
    for (int32_t slotId = 0; slotId < SLOT_COUNT; slotId++) {
        simStateManager[slotId] = std::make_shared<SimStateManager>(telRilManager);
        simStateManager[slotId]->Init(slotId);
        simStateManager[slotId]->simStateHandle_->externalState_ = SimState::SIM_STATE_READY;
        simStateManager[slotId]->simStateHandle_->externalType_ = CardType::SINGLE_MODE_USIM_CARD;
        simFileManager[slotId] = SimFileManager::CreateInstance(
            std::weak_ptr<ITelRilManager>(telRilManager), std::weak_ptr<SimStateManager>(simStateManager[slotId]));
        simFileManager[slotId]->Init(slotId);
    }
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->Init();
    auto ret = multiSimController->SetPrimarySlotId(2, false);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
    IccState iccState;
    iccState.iccid_ = "012345678901234";
    iccState.simStatus_ = ICC_CONTENT_READY;
    iccState.simType_ = ICC_USIM_TYPE;
    multiSimController->simStateManager_[0]->simStateHandle_->iccState_ = iccState;
    multiSimController->simStateManager_[0]->simStateHandle_->iccid_ = "012345678901234";
    ret = multiSimController->SetPrimarySlotId(0, false);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
    TELEPHONY_EXT_WRAPPER.isHandleVSim_ = []() { return true; };
    TELEPHONY_EXT_WRAPPER.isVSimInDisableProcess_ = []() { return false; };
    ret = multiSimController->SetPrimarySlotId(0, false);
    EXPECT_EQ(ret, TELEPHONY_ERR_FAIL);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_SetActiveCommonSim_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->isSetActiveSimInProgress_.resize(2, 0);
    multiSimController->radioProtocolController_ = nullptr;
    int32_t slotId = 0;
    int32_t enable = 1;
    bool force = false;
    int32_t curSimId = 0;
    int32_t result = multiSimController->SetActiveCommonSim(slotId, enable, force, curSimId);

    force = true;
    result = multiSimController->SetActiveCommonSim(slotId, enable, force, curSimId);

    EXPECT_EQ(result, TELEPHONY_ERR_RIL_CMD_FAIL);
}
 
HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_UpdataCacheSetActiveState_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->isSetActiveSimInProgress_.resize(2, 0);
    multiSimController->radioProtocolController_ = nullptr;
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;
 
    auto result = multiSimController->UpdataCacheActiveState(0, 1, 0);

    result = multiSimController->UpdataCacheActiveState(0, 1, 0);
    EXPECT_EQ(result, TELEPHONY_ERR_ARRAY_OUT_OF_BOUNDS);
}
 
HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_UpdateDBSetActiveResult_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->isSetActiveSimInProgress_.resize(2, 0);
    multiSimController->radioProtocolController_ = nullptr;
    auto result = multiSimController->UpdateDBActiveResult(0, 1, 0);
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;
 
    result = multiSimController->UpdateDBActiveResult(0, 1, 0);

    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_ClearSimLabel_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
    EXPECT_EQ(multiSimController->ClearSimLabel(SimType::ESIM), TELEPHONY_ERR_LOCAL_PTR_NULL);
    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    std::shared_ptr<MockSimRdbHelper> mocksimrdbhelper =std::make_shared<MockSimRdbHelper>();
    EXPECT_CALL(*mocksimrdbhelper, ClearSimLabel(_))
        .WillRepeatedly(Return(0));
    EXPECT_EQ(multiSimController->ClearSimLabel(SimType::PSIM), INVALID_VALUE);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_UpdateSimPresent_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
    int32_t ret = multiSimController->UpdateSimPresent(1, true);
    EXPECT_EQ(ret, INVALID_VALUE);
    std::shared_ptr<MockSimRdbHelper> mocksimrdbhelper =std::make_shared<MockSimRdbHelper>();
    EXPECT_CALL(*mocksimrdbhelper, InsertData(_, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*mocksimrdbhelper, ClearData(_))
        .WillRepeatedly(Return(0));
    ret = multiSimController->UpdateSimPresent(1, true);
    ret = multiSimController->UpdateSimPresent(1, false);
    EXPECT_EQ(ret, TELEPHONY_ERROR);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_UpdateEsimOpName_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
    std::string iccId = "12345123451234512345";
    std::string opName = "中国移动";
    EXPECT_EQ(multiSimController->UpdateEsimOpName(iccId, opName), TELEPHONY_ERR_LOCAL_PTR_NULL);
    MockSimRdbHelper mockSimRdbHelper;
    EXPECT_CALL(mockSimRdbHelper, UpdateEsimOpName(_, _))
        .WillRepeatedly(Return(0));
    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    EXPECT_EQ(multiSimController->UpdateEsimOpName(iccId, opName), INVALID_VALUE);
}

HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_020, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t imsSwitchValue = 0;
    const int32_t imsSwitchValueUnknown = -1;
    int32_t result = multiSimController->QueryImsSwitch(-1, imsSwitchValue);
    EXPECT_EQ(result, TELEPHONY_ERROR);
    EXPECT_EQ(imsSwitchValue, imsSwitchValueUnknown);
}
 
HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_021, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t imsSwitchValue = 0;
    const int32_t imsSwitchValueUnknown = -1;
    int32_t result =  multiSimController->QueryImsSwitch(0, imsSwitchValue);
    EXPECT_EQ(result, TELEPHONY_ERROR);
    EXPECT_EQ(imsSwitchValue, imsSwitchValueUnknown);
}
 
HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_022, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t imsSwitchValue = 0;
    const int32_t imsSwitchValueUnknown = -1;
    int32_t result = multiSimController->QueryImsSwitch(0, imsSwitchValue);
    EXPECT_EQ(result, TELEPHONY_ERROR);
    EXPECT_EQ(imsSwitchValue, imsSwitchValueUnknown);
}
 
HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_023, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t imsSwitchValue = 0;
    int32_t result = multiSimController->QueryImsSwitch(0, imsSwitchValue);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
    EXPECT_NE(imsSwitchValue, 1); // 假设查询成功时imsSwitch为1
}
 
HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_024, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t imsSwitchValue = 0;
    const int32_t imsSwitchValueUnknown = -1;
    int32_t result = multiSimController->QueryImsSwitch(0, imsSwitchValue);
    EXPECT_EQ(result, TELEPHONY_ERROR);
    EXPECT_EQ(imsSwitchValue, imsSwitchValueUnknown);
}
 
HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_025, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    std::vector<IccAccountInfo> iccAccountInfoList;
    int32_t result = multiSimController->GetActiveSimAccountInfoList(false, iccAccountInfoList);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    EXPECT_TRUE(iccAccountInfoList.empty());
}
 
HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_026, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t result = multiSimController->SetPrimarySlotIdWithoutModemReboot(0);
    EXPECT_EQ(result, TELEPHONY_ERR_FAIL);
}
 
HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_027, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t result = multiSimController->SetPrimarySlotIdWithoutModemReboot(-1);
    EXPECT_NE(result, TELEPHONY_ERR_NO_SIM_CARD);
}
 
HWTEST_F(MultiSimControllerTest, Telephony_MultiSimController_028, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t result = multiSimController->SetPrimarySlotIdWithoutModemReboot(0);
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(multiSimController->isSetPrimarySlotIdInProgress_);
}

HWTEST_F(MultiSimControllerTest, InsertEsimDatatest_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    string iccId;
    int32_t esimLabel = 3;
    string operatorName;
    int32_t labelIndex = 0;
    multiSimController->simDbHelper_ = nullptr;
    int32_t result = multiSimController->InsertEsimData(iccId, esimLabel, operatorName);
    EXPECT_EQ(result, INVALID_VALUE);
    result = multiSimController->SetSimLabelIndex(iccId, labelIndex);
    EXPECT_EQ(result, INVALID_VALUE);

    multiSimController->simDbHelper_ = {};
    result = multiSimController->InsertEsimData(iccId, esimLabel, operatorName);
    EXPECT_EQ(result, INVALID_VALUE);
    multiSimController->simDbHelper_ = std::make_unique<SimRdbHelper>();
    result = multiSimController->SetSimLabelIndex(iccId, labelIndex);
    EXPECT_NE(result, INVALID_VALUE);

    auto mocksimdbhelper = std::make_shared<MockSimRdbHelper>();
    EXPECT_CALL(*mocksimdbhelper, InsertData(_, _)).WillRepeatedly(Return(TELEPHONY_SUCCESS));
    auto multiSimControllerMock = std::make_shared<MultiSimControllerMock>(telRilManager,
        simStateManager, simFileManager);
    EXPECT_CALL(*multiSimControllerMock, GetAllListFromDataBase(_)).WillRepeatedly(Return(false));
    result = multiSimController->InsertEsimData(iccId, esimLabel, operatorName);
    EXPECT_EQ(result, INVALID_VALUE);
}

HWTEST_F(MultiSimControllerTest, InsertEsimDatatest_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    string iccId;
    int32_t esimLabel = 3;
    string operatorName;
    multiSimController->simDbHelper_ = {};
    auto multiSimControllerMock = std::make_shared<MultiSimControllerMock>(telRilManager,
        simStateManager, simFileManager);
    EXPECT_CALL(*multiSimControllerMock, GetAllListFromDataBase(_)).WillRepeatedly(Return(false));
    int32_t result = multiSimController->InsertEsimData(iccId, esimLabel, operatorName);
    EXPECT_NE(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SetSimLabelIndeeAndSetTargetPrimarySlotIdtest, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = {};
    auto mocksimdbhelper = std::make_shared<MockSimRdbHelper>();
    EXPECT_CALL(*mocksimdbhelper, UpdateDataByIccId(_, _)).WillRepeatedly(Return(TELEPHONY_SUCCESS));
    multiSimController->allLocalCacheInfo_.clear();
    EXPECT_EQ(multiSimController->SetSimLabelIndex("iccId", 1), INVALID_VALUE);

    EXPECT_EQ(multiSimController->SetTargetPrimarySlotId(true, 0), TELEPHONY_SUCCESS);

    EXPECT_EQ(multiSimController->SetTargetPrimarySlotId(false, 0), TELEPHONY_SUCCESS);
}
 
HWTEST_F(MultiSimControllerTest, IsAllCardsReadytest, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    simStateManager0->Init(0);
    auto simStateManager1 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    simStateManager1->Init(1);
    multiSimController->simStateManager_ = { simStateManager0, simStateManager1 };
    multiSimController->simStateManager_[0]->simStateHandle_ = std::make_shared<SimStateHandle>(simStateManager0);
    multiSimController->simStateManager_[0]->simStateHandle_->externalState_ = SimState::SIM_STATE_NOT_PRESENT;
    multiSimController->waitCardsReady_ = true;
    EXPECT_TRUE(multiSimController->IsAllCardsReady());
 
    multiSimController->waitCardsReady_ = false;
    EXPECT_FALSE(multiSimController->IsAllCardsReady());
 
    multiSimController->simStateManager_[0]->simStateHandle_->externalState_ = SimState::SIM_STATE_READY;
    EXPECT_FALSE(multiSimController->IsAllCardsReady());
}
 
HWTEST_F(MultiSimControllerTest, SetTargetPrimarySlotIdtest, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    EXPECT_EQ(multiSimController->SetTargetPrimarySlotId(true, 0), TELEPHONY_SUCCESS);
    EXPECT_EQ(multiSimController->SetTargetPrimarySlotId(false, 0), TELEPHONY_SUCCESS);
}
 
HWTEST_F(MultiSimControllerTest, GetSimLabeltest, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t slotId = 0;
    SimLabel simLabel;
    OHOS::system::SetParameter(ESIM_SUPPORT_PARAM, "6");
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_SUCCESS);
    slotId = 1;
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
    OHOS::system::SetParameter(ESIM_SUPPORT_PARAM, "0");
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
 
    std::shared_ptr<MockSimManager> mockeSimManager = std::make_shared<MockSimManager>();
    EXPECT_CALL(*mockeSimManager, IsEsim(_)).WillRepeatedly(
        Return(true));
    EXPECT_FALSE(CoreManagerInner::GetInstance().IsSupported(slotId));
    std::vector<SimRdbInfo> newCache;
    newCache.resize(2);
    newCache[0].iccId = "2164181618486135";
    newCache[1].iccId.clear();
    multiSimController->localCacheInfo_ = newCache;
    multiSimController->allLocalCacheInfo_ = newCache;
    OHOS::system::SetParameter(LAST_DEACTIVE_PROFILE_SLOT0, "3");
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simLabel.index, 1);
 
    OHOS::system::SetParameter(LAST_DEACTIVE_PROFILE_SLOT0, "");
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simLabel.index, 1);
 
    OHOS::system::SetParameter(LAST_DEACTIVE_PROFILE_SLOT0, "1");
    EXPECT_EQ(multiSimController->GetSimLabel(slotId, simLabel), TELEPHONY_ERR_SUCCESS);
}
 
HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_ProcessEvent_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::
        Get(MultiSimController::WAIT_FOR_ALL_CARDS_READY_EVENT, 0);
    multiSimController->ProcessEvent(event);
    EXPECT_FALSE(multiSimController->waitCardsReady_);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_GetSimLabelIdxFromAllLocalCache, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
 
    int32_t simIdx = 0;
    SimRdbInfo simRdb1;
    simRdb1.simLabelIndex = 3;
    multiSimController->allLocalCacheInfo_.push_back(simRdb1);
    OHOS::system::SetParameter("persist.telephony.last_deactive_profile1", "");
    multiSimController->GetSimLabelIdxFromAllLocalCache(simIdx, 1);
    EXPECT_EQ(simIdx, 1);
 
    OHOS::system::SetParameter("persist.telephony.last_deactive_profile0", "1");
    multiSimController->GetSimLabelIdxFromAllLocalCache(simIdx, 0);
    EXPECT_EQ(simIdx, 3);
}

HWTEST_F(MultiSimControllerTest, SavePrimaryCardInfoTest_SetPrimarySlotid, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager0 = std::make_shared<Telephony::SimStateManager>(telRilManager);
    
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager;
    simStateManager.push_back(simStateManager0);
    
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager0);
    simFileManager->simFile_ = std::make_shared<SimFile>(simStateManager0);
    
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    simFileManager_.push_back(simFileManager);
    
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager_);
    auto mocksimFileManager = std::make_shared<MockSimFileManager>(telRilManager, simStateManager0);
 
    EXPECT_CALL(*mocksimFileManager, GetSimIccId()).WillRepeatedly(Return(u"123456789012345678"));
    multiSimController->SavePrimaryCardInfo(0);
    EXPECT_EQ(multiSimController->lastPrimarySlotId_, 0);
 
    EXPECT_CALL(*mocksimFileManager, GetSimIccId()).WillRepeatedly(Return(u""));
    multiSimController->SavePrimaryCardInfo(0);
    EXPECT_EQ(multiSimController->lastPrimarySlotId_, 0);
 
    multiSimController->simFileManager_[0] = nullptr;
    multiSimController->SavePrimaryCardInfo(0);
    EXPECT_EQ(multiSimController->lastPrimarySlotId_, 0);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_CheckIfNeedSwitchMainSlotId, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;

    multiSimController->targetPrimarySlotId_ = SIM_SLOT_1;
    multiSimController->CheckIfNeedSwitchMainSlotId(true);
    EXPECT_EQ(multiSimController->targetPrimarySlotId_, 1);
    multiSimController->CheckIfNeedSwitchMainSlotId(false);
    EXPECT_EQ(multiSimController->targetPrimarySlotId_, INVALID_VALUE);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_SetTargetPrimarySlotId001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
    
    multiSimController->SetTargetPrimarySlotId(true, SIM_SLOT_1);
    bool ret = multiSimController->HasInnerEvent(MultiSimController::WAIT_FOR_ALL_CARDS_READY_EVENT);
    EXPECT_TRUE(ret);
    multiSimController->RemoveEvent(MultiSimController::WAIT_FOR_ALL_CARDS_READY_EVENT);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_SavePrimarySlotId001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->simDbHelper_ = nullptr;
 
    EXPECT_EQ(multiSimController->SavePrimarySlotId(SLOT_COUNT), TELEPHONY_ERR_ARGUMENT_INVALID);
    EXPECT_EQ(multiSimController->SavePrimarySlotId(SIM_SLOT_1), TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_RefreshSimAccountLoaded001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManagerPtr = std::make_shared<SimStateManager>(telRilManager);
    auto telRilManagerWeak = std::weak_ptr<TelRilManager>(telRilManager);
    auto simFileManagerPtr = std::make_shared<Telephony::SimFileManager>(
        telRilManagerWeak, std::weak_ptr<Telephony::SimStateManager>(simStateManagerPtr));
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { simStateManagerPtr,
        simStateManagerPtr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { simFileManagerPtr, simFileManagerPtr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManagerWeak = {
        std::weak_ptr<Telephony::SimFileManager>(simFileManagerPtr),
        std::weak_ptr<Telephony::SimFileManager>(simFileManagerPtr)
    };
    auto multiSimMonitor = std::make_shared<MultiSimMonitor>(multiSimController, simStateManager, simFileManagerWeak);
    std::unordered_map<int32_t, std::string> simInfo;
    simInfo[0] = "000000000";
    simInfo[1] = "000000001";
 
    multiSimMonitor->RefreshSimAccountLoaded();
    EXPECT_TRUE(multiSimMonitor->controller_->loadedSimCardInfo_.empty());
    multiSimMonitor->controller_->loadedSimCardInfo_ = simInfo;
    multiSimMonitor->RefreshSimAccountLoaded();

    auto multiSimMonitor1 = std::make_shared<MultiSimMonitor>(multiSimController, simStateManager, simFileManagerWeak);
    multiSimMonitor1->controller_->loadedSimCardInfo_ = simInfo;
    multiSimMonitor1->observerHandler_ = nullptr;
    multiSimMonitor1->RefreshSimAccountLoaded();

    EXPECT_TRUE(multiSimMonitor1->controller_->loadedSimCardInfo_[0] == "000000000");
}
HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_GetListFromDataBase001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MockSimRdbHelper> mocksimrdbhelper =std::make_shared<MockSimRdbHelper>();
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->Init();
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    radioProtocolController->Init();
    multiSimController->simDbHelper_ = std::make_unique<MockSimRdbHelper>();
    auto simDb = static_cast<MockSimRdbHelper*>(multiSimController->simDbHelper_.get());
    EXPECT_CALL(*simDb, QueryAllValidData(_)).Times(AnyNumber()).WillOnce(Return(TELEPHONY_SUCCESS));
    std::vector<SimRdbInfo> newCache;
    multiSimController->localCacheInfo_ = newCache;
    bool ret1 = multiSimController->GetListFromDataBase(false);
    EXPECT_EQ(ret1, true);
    EXPECT_CALL(*simDb, QueryAllValidData(_)).Times(AnyNumber()).WillRepeatedly(Return(TELEPHONY_ERROR));
    multiSimController->refreshLocalCacheRemainCount_ = 1;
    bool ret2 = multiSimController->GetListFromDataBase(true);
    EXPECT_EQ(ret2, false);
    bool ret3 = multiSimController->GetListFromDataBase(false);
    EXPECT_EQ(ret3, false);
}
 
HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_GetAllListFromDataBase001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MockSimRdbHelper> mocksimrdbhelper =std::make_shared<MockSimRdbHelper>();
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    multiSimController->Init();
    auto radioProtocolController =
        std::make_shared<RadioProtocolController>(std::weak_ptr<TelRilManager>(telRilManager));
    radioProtocolController->Init();
    multiSimController->simDbHelper_ = std::make_unique<MockSimRdbHelper>();
    auto simDb = static_cast<MockSimRdbHelper*>(multiSimController->simDbHelper_.get());
    EXPECT_CALL(*simDb, QueryAllData(_)).Times(AnyNumber()).WillOnce(Return(TELEPHONY_SUCCESS));
    std::vector<SimRdbInfo> newCache;
    multiSimController->allLocalCacheInfo_ = newCache;
    bool ret1 = multiSimController->GetAllListFromDataBase(false);
    EXPECT_EQ(ret1, true);
    EXPECT_CALL(*simDb, QueryAllData(_)).Times(AnyNumber()).WillRepeatedly(Return(TELEPHONY_ERROR));
    multiSimController->refreshLocalCacheRemainCount_ = 1;
    bool ret2 = multiSimController->GetAllListFromDataBase(true);
    EXPECT_EQ(ret2, false);
    bool ret3 = multiSimController->GetAllListFromDataBase(false);
    EXPECT_EQ(ret3, false);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(100, -1);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(100, 101);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_004, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo localRecord;
    localRecord.iccId = "12345123451234512345";
    localRecord.showName = "主空间卡";
    localRecord.phoneNumber = "13800138000";
    localRecord.slotIndex = 0;
    localRecord.cardType = 1;
    localRecord.imsSwitch = 1;
    localRecord.isMainCard = 1;
    localRecord.isVoiceCard = 1;
    localRecord.isMessageCard = 1;
    localRecord.isCellularDataCard = 1;
    localRecord.isActive = 1;
    localRecord.isEsim = 0;
    localRecord.simLabelIndex = 1;
    
    std::vector<SimRdbInfo> cache;
    {
        std::unique_lock<ffrt::shared_mutex> lock(multiSimController->mutex_);
        cache = multiSimController->allLocalCacheInfo_;
        cache.push_back(localRecord);
    }
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_005, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo localRecord;
    localRecord.iccId = "12345123451234512345";
    localRecord.showName = "隐私空间卡";
    localRecord.phoneNumber = "13900139000";
    localRecord.slotIndex = 0;
    localRecord.cardType = 1;
    localRecord.imsSwitch = 1;
    localRecord.isMainCard = 1;
    localRecord.isVoiceCard = 1;
    localRecord.isMessageCard = 1;
    localRecord.isCellularDataCard = 1;
    localRecord.isActive = 1;
    localRecord.isEsim = 0;
    localRecord.simLabelIndex = 1;
    
    std::vector<SimRdbInfo> cache;
    {
        std::unique_lock<ffrt::shared_mutex> lock(multiSimController->mutex_);
        cache = multiSimController->allLocalCacheInfo_;
        cache.push_back(localRecord);
    }
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(100, 101);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_006, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo localRecord;
    localRecord.iccId = "12345123451234512345";
    localRecord.showName = "主空间卡";
    localRecord.phoneNumber = "13800138000";
    localRecord.slotIndex = 0;
    localRecord.cardType = 1;
    localRecord.imsSwitch = 1;
    localRecord.isMainCard = 1;
    localRecord.isVoiceCard = 1;
    localRecord.isMessageCard = 1;
    localRecord.isCellularDataCard = 1;
    localRecord.isActive = 1;
    localRecord.isEsim = 0;
    localRecord.simLabelIndex = 1;
    
    std::vector<SimRdbInfo> cache;
    {
        std::unique_lock<ffrt::shared_mutex> lock(multiSimController->mutex_);
        cache = multiSimController->allLocalCacheInfo_;
        cache.push_back(localRecord);
    }
    
    int32_t result1 = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result1, TELEPHONY_SUCCESS);
    
    localRecord.showName = "隐私空间卡";
    localRecord.phoneNumber = "13900139000";
    
    {
        std::unique_lock<ffrt::shared_mutex> lock(multiSimController->mutex_);
        cache = multiSimController->allLocalCacheInfo_;
        cache[0].showName = "隐私空间卡";
        cache[0].phoneNumber = "13900139000";
    }
    
    int32_t result2 = cacheSyncManager->SyncCacheOnUserSwitch(100, 101);
    EXPECT_EQ(result2, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_007, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo localRecord;
    localRecord.iccId = "12345123451234512345";
    localRecord.showName = "主空间卡";
    localRecord.phoneNumber = "13800138000";
    localRecord.slotIndex = 0;
    localRecord.cardType = 1;
    localRecord.imsSwitch = 1;
    localRecord.isMainCard = 1;
    localRecord.isVoiceCard = 1;
    localRecord.isMessageCard = 1;
    localRecord.isCellularDataCard = 1;
    localRecord.isActive = 1;
    localRecord.isEsim = 0;
    localRecord.simLabelIndex = 1;
    
    std::vector<SimRdbInfo> cache;
    {
        std::unique_lock<ffrt::shared_mutex> lock(multiSimController->mutex_);
        cache = multiSimController->allLocalCacheInfo_;
        cache.push_back(localRecord);
    }
    
    multiSimController->cacheModified_  = true;
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
    EXPECT_EQ(multiSimController->cacheModified_, false);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_008, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo localRecord;
    localRecord.iccId = "12345123451234512345";
    localRecord.showName = "主空间卡";
    localRecord.phoneNumber = "13800138000";
    localRecord.slotIndex = 0;
    localRecord.cardType = 1;
    localRecord.imsSwitch = 1;
    localRecord.isMainCard = 1;
    localRecord.isVoiceCard = 1;
    localRecord.isMessageCard = 1;
    localRecord.isCellularDataCard = 1;
    localRecord.isActive = 1;
    localRecord.isEsim = 0;
    localRecord.simLabelIndex = 1;
    
    std::vector<SimRdbInfo> cache;
    {
        std::unique_lock<ffrt::shared_mutex> lock(multiSimController->mutex_);
        cache = multiSimController->allLocalCacheInfo_;
        cache.push_back(localRecord);
    }
    
    multiSimController->cacheModified_ = false;
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
    EXPECT_EQ(multiSimController->cacheModified_, false);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_009, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(100, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_010, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(102, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_011, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(100, 102);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(MultiSimControllerTest, SimCacheSyncManager_IsFieldEmptyOrDefault_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    EXPECT_TRUE(cacheSyncManager->IsFieldEmptyOrDefault(""));
    EXPECT_FALSE(cacheSyncManager->IsFieldEmptyOrDefault("test"));
    EXPECT_TRUE(cacheSyncManager->IsFieldEmptyOrDefault(0));
    EXPECT_TRUE(cacheSyncManager->IsFieldEmptyOrDefault(-1));
    EXPECT_FALSE(cacheSyncManager->IsFieldEmptyOrDefault(1));
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_IsDataShareReady_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    // Default value should be false
    EXPECT_FALSE(multiSimController->IsDataShareReady());
    
    // Set to true
    multiSimController->SetDataShareReady(true);
    EXPECT_TRUE(multiSimController->IsDataShareReady());
    
    // Set to false
    multiSimController->SetDataShareReady(false);
    EXPECT_FALSE(multiSimController->IsDataShareReady());
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_SetDataShareReady_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    // Test setting to true
    multiSimController->SetDataShareReady(true);
    EXPECT_TRUE(multiSimController->IsDataShareReady());
    
    // Test setting to false
    multiSimController->SetDataShareReady(false);
    EXPECT_FALSE(multiSimController->IsDataShareReady());
    
    // Test setting to true again
    multiSimController->SetDataShareReady(true);
    EXPECT_TRUE(multiSimController->IsDataShareReady());
}

HWTEST_F(MultiSimControllerTest, MultiSimController_MarkCacheModified_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    std::string iccId = "12345123451234512345";
    std::string fieldName = "showName";
    
    multiSimController->MarkCacheModified(iccId, fieldName);
    
    auto modifiedRecords = multiSimController->GetModifiedRecords();
    EXPECT_EQ(modifiedRecords.size(), 1);
    EXPECT_TRUE(modifiedRecords.find(iccId) != modifiedRecords.end());
    EXPECT_TRUE(modifiedRecords[iccId].find(fieldName) != modifiedRecords[iccId].end());
}

HWTEST_F(MultiSimControllerTest, MultiSimController_MarkCacheModified_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    std::string iccId = "12345123451234512345";
    
    multiSimController->MarkCacheModified(iccId, "showName");
    multiSimController->MarkCacheModified(iccId, "phoneNumber");
    multiSimController->MarkCacheModified(iccId, "simLabelIndex");
    
    auto modifiedRecords = multiSimController->GetModifiedRecords();
    EXPECT_EQ(modifiedRecords.size(), 1);
    EXPECT_TRUE(modifiedRecords.find(iccId) != modifiedRecords.end());
    EXPECT_EQ(modifiedRecords[iccId].size(), 3);
}

HWTEST_F(MultiSimControllerTest, MultiSimController_GetModifiedRecords_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    std::string iccId1 = "12345123451234512345";
    std::string iccId2 = "54321543215432154321";
    
    multiSimController->MarkCacheModified(iccId1, "showName");
    multiSimController->MarkCacheModified(iccId2, "simLabelIndex");
    
    auto modifiedRecords = multiSimController->GetModifiedRecords();
    EXPECT_EQ(modifiedRecords.size(), 2);
    EXPECT_TRUE(modifiedRecords.find(iccId1) != modifiedRecords.end());
    EXPECT_TRUE(modifiedRecords.find(iccId2) != modifiedRecords.end());
}

HWTEST_F(MultiSimControllerTest, MultiSimController_ClearModifiedRecords_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    std::string iccId = "12345123451234512345";
    multiSimController->MarkCacheModified(iccId, "showName");
    
    EXPECT_TRUE(multiSimController->HasModifiedRecords());
    
    multiSimController->ClearModifiedRecords();
    
    EXPECT_FALSE(multiSimController->HasModifiedRecords());
    auto modifiedRecords = multiSimController->GetModifiedRecords();
    EXPECT_EQ(modifiedRecords.size(), 0);
}

HWTEST_F(MultiSimControllerTest, MultiSimController_HasModifiedRecords_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    EXPECT_FALSE(multiSimController->HasModifiedRecords());

    std::string iccId = "12345123451234512345";
    multiSimController->MarkCacheModified(iccId, "showName");
    
    EXPECT_TRUE(multiSimController->HasModifiedRecords());
}
} // namespace Telephony
} // namespace OHOS