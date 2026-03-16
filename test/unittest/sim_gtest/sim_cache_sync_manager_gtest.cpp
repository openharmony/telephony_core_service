/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "telephony_ext_wrapper.h"
#include "mock_sim_manager.h"
#include "multi_sim_helper.h"
#include "sim_cache_sync_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;
static const std::string ESIM_SUPPORT_PARAM = "const.ril.esim_type";
const std::string LAST_DEACTIVE_PROFILE_SLOT0 = "persist.telephony.last_deactive_profile0";
const std::string LAST_DEACTIVE_PROFILE_SLOT1 = "persist.telephony.last_deactive_profile1";
const std::string SUPPORT_ESIM_MEP = "const.ril.sim.esim_support_mep";
class SimCacheSyncManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SimCacheSyncManagerTest::SetUpTestCase() {}

void SimCacheSyncManagerTest::TearDownTestCase() {}

void SimCacheSyncManagerTest::SetUp() {}

void SimCacheSyncManagerTest::TearDown() {}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_001, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_002, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_003, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_004, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_005, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_006, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_IsFieldEmptyOrDefault_001, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_007, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    // Set database not ready
    multiSimController->SetDataShareReady(false);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_008, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    // Set database ready
    multiSimController->SetDataShareReady(true);
    
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncSingleRecord_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.slotIndex = 0;
    record.cardId = "card001";
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    
    int32_t result = cacheSyncManager->SyncSingleRecord(record);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncSingleRecord_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "98765987659876598765";
    record.slotIndex = 1;
    record.cardId = "card002";
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    
    int32_t result = cacheSyncManager->SyncSingleRecord(record);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncToDatabase_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    std::vector<SimRdbInfo> data;
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.slotIndex = 0;
    record.cardId = "card001";
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    data.push_back(record);
    
    int32_t result = cacheSyncManager->SyncToDatabase(data);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncToDatabase_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    std::vector<SimRdbInfo> data;
    SimRdbInfo record1;
    record1.iccId = "12345123451234512345";
    record1.slotIndex = 0;
    record1.cardId = "card001";
    record1.isActive = 1;
    record1.isEsim = 0;
    record1.simLabelIndex = 1;
    record1.isMainCard = 1;
    record1.isVoiceCard = 1;
    record1.isMessageCard = 1;
    record1.isCellularDataCard = 1;
    data.push_back(record1);
    
    SimRdbInfo record2;
    record2.iccId = "98765987659876598765";
    record2.slotIndex = 1;
    record2.cardId = "card002";
    record2.isActive = 1;
    record2.isEsim = 0;
    record2.simLabelIndex = 1;
    record2.isMainCard = 1;
    record2.isVoiceCard = 1;
    record2.isMessageCard = 1;
    record2.isCellularDataCard = 1;
    data.push_back(record2);
    
    int32_t result = cacheSyncManager->SyncToDatabase(data);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_009, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    // Set database ready
    multiSimController->SetDataShareReady(true);
    
    // Test switching from 100 to 101 (isSwitching100To101 = true)
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(PRIVATE_USER_ID, ACTIVE_USER_ID);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_010, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    // Set database ready
    multiSimController->SetDataShareReady(true);
    
    // Test switching from 101 to 100 (isSwitching100To101 = false)
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(ACTIVE_USER_ID, PRIVATE_USER_ID);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_011, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    // Set database ready
    multiSimController->SetDataShareReady(true);
    
    // Test switching from 100 to 101 with cache modified
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
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(PRIVATE_USER_ID, ACTIVE_USER_ID);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}
HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_012, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_013, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController = nullptr;
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_014, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    multiSimController->SetDataShareReady(true);
    multiSimController->cacheModified_ = true;
    
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_DATABASE_READ_FAIL));
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_ERR_DATABASE_READ_FAIL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_015, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    auto multiSimControllerMock = std::make_shared<MultiSimControllerMock>(telRilManager,
        simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimControllerMock, simRdbHelper);
    
    multiSimControllerMock->SetDataShareReady(true);
    multiSimControllerMock->cacheModified_ = true;
    
    std::vector<SimRdbInfo> targetData;
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(targetData), testing::Return(TELEPHONY_SUCCESS)));
    
    EXPECT_CALL(*multiSimControllerMock, GetLocalCache(testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_LOCAL_PTR_NULL));
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_016, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    auto multiSimControllerMock = std::make_shared<MultiSimControllerMock>(telRilManager,
        simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimControllerMock, simRdbHelper);
    
    multiSimControllerMock->SetDataShareReady(true);
    multiSimControllerMock->cacheModified_ = true;
    
    std::vector<SimRdbInfo> targetData;
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(targetData), testing::Return(TELEPHONY_SUCCESS)));
    
    std::vector<SimRdbInfo> localCache;
    EXPECT_CALL(*multiSimControllerMock, GetLocalCache(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(localCache), testing::Return(TELEPHONY_SUCCESS)));
    
    EXPECT_CALL(*simRdbHelper, QueryDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_DATABASE_WRITE_FAIL));
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_ERR_DATABASE_WRITE_FAIL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_017, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    multiSimController->SetDataShareReady(true);
    multiSimController->cacheModified_ = true;
    
    cacheSyncManager->isSyncing_ = true;
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
    
    cacheSyncManager->isSyncing_ = false;
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_018, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    auto multiSimControllerMock = std::make_shared<MultiSimControllerMock>(telRilManager,
        simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimControllerMock, simRdbHelper);
    
    multiSimControllerMock->SetDataShareReady(true);
    multiSimControllerMock->cacheModified_ = true;
    
    cacheSyncManager->lastSyncFailed_ = true;
    
    std::vector<SimRdbInfo> targetData;
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(targetData), testing::Return(TELEPHONY_SUCCESS)));
    
    std::vector<SimRdbInfo> localCache;
    EXPECT_CALL(*multiSimControllerMock, GetLocalCache(testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(localCache), testing::Return(TELEPHONY_SUCCESS)));
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_019, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_020, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_021, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncSingleRecord_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.showName = "测试卡";
    record.phoneNumber = "13800138000";
    record.slotIndex = 0;
    record.cardType = 1;
    record.imsSwitch = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    
    SimRdbInfo targetRecord;
    targetRecord.iccId = "12345123451234512345";
    targetRecord.showName = "旧卡名";
    targetRecord.phoneNumber = "13900139000";
    targetRecord.slotIndex = 0;
    targetRecord.cardType = 1;
    targetRecord.imsSwitch = 0;
    targetRecord.isMainCard = 0;
    targetRecord.isVoiceCard = 0;
    targetRecord.isMessageCard = 0;
    targetRecord.isCellularDataCard = 0;
    targetRecord.isActive = 1;
    targetRecord.isEsim = 0;
    targetRecord.simLabelIndex = 0;
    
    EXPECT_CALL(*simRdbHelper, QueryDataByIccId(testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(targetRecord), testing::Return(TELEPHONY_SUCCESS)));
    
    EXPECT_CALL(*simRdbHelper, UpdateDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_DATABASE_WRITE_FAIL));
    
    int32_t result = cacheSyncManager->SyncSingleRecord(record);
    EXPECT_EQ(result, TELEPHONY_ERR_DATABASE_WRITE_FAIL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncSingleRecord_004, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.showName = "测试卡";
    record.phoneNumber = "13800138000";
    record.slotIndex = 0;
    record.cardType = 1;
    record.imsSwitch = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    
    EXPECT_CALL(*simRdbHelper, QueryDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_DATABASE_READ_FAIL));
    
    EXPECT_CALL(*simRdbHelper, InsertData(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_DATABASE_WRITE_FAIL));
    
    int32_t result = cacheSyncManager->SyncSingleRecord(record);
    EXPECT_EQ(result, TELEPHONY_ERR_DATABASE_WRITE_FAIL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncSingleRecord_005, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.showName = "测试卡";
    record.phoneNumber = "13800138000";
    record.slotIndex = 0;
    record.cardType = 1;
    record.imsSwitch = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    
    EXPECT_CALL(*simRdbHelper, QueryDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_DATABASE_READ_FAIL));
    
    int64_t id = 1;
    EXPECT_CALL(*simRdbHelper, InsertData(testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(id), testing::Return(TELEPHONY_SUCCESS)));
    
    int32_t result = cacheSyncManager->SyncSingleRecord(record);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_IncrementalSync_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    std::vector<SimRdbInfo> localCache;
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.showName = "测试卡";
    record.phoneNumber = "13800138000";
    record.slotIndex = 0;
    record.cardType = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    localCache.push_back(record);
    
    std::unordered_map<std::string, std::set<std::string>> modifiedRecords;
    modifiedRecords["12345123451234512345"].insert("showName");
    
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    EXPECT_CALL(*simRdbHelper, UpdateDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    int32_t result = cacheSyncManager->SyncModifiedRecordsToDatabase(modifiedRecords);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_IncrementalSync_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    std::set<std::string> modifiedFields;
    
    std::vector<SimRdbInfo> localCache;
    
    SimRdbInfo record2;
    record2.iccId = "54321543215432154321";
    record2.showName = "测试卡2";
    record2.phoneNumber = "13900139000";
    record2.slotIndex = 1;
    record2.cardType = 1;
    record2.isMainCard = 0;
    record2.isVoiceCard = 1;
    record2.isMessageCard = 1;
    record2.isCellularDataCard = 0;
    record2.isActive = 1;
    record2.isEsim = 0;
    record2.simLabelIndex = 2;
    localCache.push_back(record2);

    modifiedFields.insert("showName");
    DataShare::DataShareValuesBucket values;
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);
    
    modifiedFields.insert("phoneNumber");
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);

    modifiedFields.insert("simLabelIndex");
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);

    modifiedFields.insert("operatorName");
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);

    modifiedFields.insert("isMainCard");
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);
    
    std::unordered_map<std::string, std::set<std::string>> modifiedRecords;
    modifiedRecords["12345123451234512345"].insert("showName");
    modifiedRecords["12345123451234512345"].insert("phoneNumber");
    modifiedRecords["54321543215432154321"].insert("simLabelIndex");
    
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    EXPECT_CALL(*simRdbHelper, UpdateDataByIccId(testing::_, testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(TELEPHONY_SUCCESS));
    
    int32_t result = cacheSyncManager->SyncModifiedRecordsToDatabase(modifiedRecords);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_IncrementalSync_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    std::set<std::string> modifiedFields;
    
    std::vector<SimRdbInfo> localCache;
    
    SimRdbInfo record2;
    record2.iccId = "54321543215432154321";
    record2.showName = "测试卡2";
    record2.phoneNumber = "13900139000";
    record2.slotIndex = 1;
    record2.cardType = 1;
    record2.isMainCard = 0;
    record2.isVoiceCard = 1;
    record2.isMessageCard = 1;
    record2.isCellularDataCard = 0;
    record2.isActive = 1;
    record2.isEsim = 0;
    record2.simLabelIndex = 2;
    localCache.push_back(record2);

    modifiedFields.insert("isVoiceCard");
    DataShare::DataShareValuesBucket values;
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);
    
    modifiedFields.insert("isMessageCard");
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);

    modifiedFields.insert("isCellularDataCard");
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);

    modifiedFields.insert("isActive");
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);

    modifiedFields.insert("isEsim");
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);
    
    std::unordered_map<std::string, std::set<std::string>> modifiedRecords;
    modifiedRecords["12345123451234512345"].insert("showName");
    modifiedRecords["12345123451234512345"].insert("phoneNumber");
    modifiedRecords["54321543215432154321"].insert("simLabelIndex");
    
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    EXPECT_CALL(*simRdbHelper, UpdateDataByIccId(testing::_, testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(TELEPHONY_SUCCESS));
    
    int32_t result = cacheSyncManager->SyncModifiedRecordsToDatabase(modifiedRecords);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_IncrementalSync_004, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    std::set<std::string> modifiedFields;
    
    std::vector<SimRdbInfo> localCache;
    
    SimRdbInfo record2;
    record2.iccId = "54321543215432154321";
    record2.showName = "测试卡2";
    record2.phoneNumber = "13900139000";
    record2.slotIndex = 1;
    record2.cardType = 1;
    record2.isMainCard = 0;
    record2.isVoiceCard = 1;
    record2.isMessageCard = 1;
    record2.isCellularDataCard = 0;
    record2.isActive = 1;
    record2.isEsim = 0;
    record2.simLabelIndex = 2;
    localCache.push_back(record2);

    modifiedFields.insert("all_fields");
    DataShare::DataShareValuesBucket values;
    cacheSyncManager->BuildPartialDataShareValues(record2, modifiedFields, values);
    
    std::unordered_map<std::string, std::set<std::string>> modifiedRecords;
    modifiedRecords["12345123451234512345"].insert("showName");
    modifiedRecords["12345123451234512345"].insert("phoneNumber");
    modifiedRecords["54321543215432154321"].insert("simLabelIndex");
    
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    EXPECT_CALL(*simRdbHelper, UpdateDataByIccId(testing::_, testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(TELEPHONY_SUCCESS));
    
    int32_t result = cacheSyncManager->SyncModifiedRecordsToDatabase(modifiedRecords);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_IncrementalSync_005, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
        auto simRdbHelper = std::make_shared<MockSimRdbHelper>();

    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    cacheSyncManager->simRdbHelper_  = nullptr;
    std::set<std::string> modifiedFields;
    std::unordered_map<std::string, std::set<std::string>> modifiedRecords;
    modifiedRecords["12345123451234512345"].insert("showName");
    modifiedRecords["12345123451234512345"].insert("phoneNumber");
    modifiedRecords["54321543215432154321"].insert("simLabelIndex");
    
    int32_t result = cacheSyncManager->SyncModifiedRecordsToDatabase(modifiedRecords);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_022, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_023, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_024, Function | MediumTest | Level1)
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

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_025, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, nullptr);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_026, Function | MediumTest | Level1)
{
    std::weak_ptr<MultiSimController> emptyController;
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(emptyController, simRdbHelper);
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_027, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    auto multiSimController = std::make_shared<MultiSimControllerMock>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    EXPECT_CALL(*multiSimController, IsDataShareReady())
        .WillOnce(testing::Return(false));
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_028, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    auto multiSimController = std::make_shared<MultiSimControllerMock>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    EXPECT_CALL(*multiSimController, IsDataShareReady())
        .WillOnce(testing::Return(true));
    EXPECT_CALL(*multiSimController, HasModifiedRecords())
        .WillOnce(testing::Return(false));
    
    int32_t result = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncCacheOnUserSwitch_029, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    auto multiSimController = std::make_shared<MultiSimControllerMock>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    EXPECT_CALL(*multiSimController, IsDataShareReady())
        .WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*multiSimController, HasModifiedRecords())
        .WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*multiSimController, GetModifiedRecords())
        .WillRepeatedly(testing::Return(std::unordered_map<std::string, std::set<std::string>>()));
    EXPECT_CALL(*multiSimController, ClearModifiedRecords())
        .Times(1);
    
    int32_t result1 = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result1, TELEPHONY_SUCCESS);
    
    int32_t result2 = cacheSyncManager->SyncCacheOnUserSwitch(101, 100);
    EXPECT_EQ(result2, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_GetLocalCache_001, Function | MediumTest | Level1)
{
    std::weak_ptr<MultiSimController> emptyController;
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(emptyController, simRdbHelper);
    
    std::vector<SimRdbInfo> localCache;
    int32_t result = cacheSyncManager->GetLocalCache(localCache);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncToDatabase_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, nullptr);
    
    std::vector<SimRdbInfo> data;
    int32_t result = cacheSyncManager->SyncToDatabase(data);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncToDatabase_004, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    std::vector<SimRdbInfo> data;
    
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    int32_t result = cacheSyncManager->SyncToDatabase(data);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncToDatabase_005, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.showName = "测试卡";
    record.phoneNumber = "13800138000";
    record.slotIndex = 0;
    record.cardType = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    
    std::vector<SimRdbInfo> data;
    data.push_back(record);
    
    EXPECT_CALL(*simRdbHelper, QueryDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    EXPECT_CALL(*simRdbHelper, UpdateDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(INVALID_VALUE));
    EXPECT_CALL(*simRdbHelper, QueryAllData(testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    int32_t result = cacheSyncManager->SyncToDatabase(data);
    EXPECT_EQ(result, TELEPHONY_ERR_DATABASE_WRITE_FAIL);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncSingleRecord_006, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.showName = "测试卡";
    record.phoneNumber = "13800138000";
    record.slotIndex = 0;
    record.cardType = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    
    SimRdbInfo existingRecord;
    existingRecord.iccId = "12345123451234512345";
    
    EXPECT_CALL(*simRdbHelper, QueryDataByIccId(testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(existingRecord), testing::Return(TELEPHONY_SUCCESS)));
    EXPECT_CALL(*simRdbHelper, UpdateDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    int32_t result = cacheSyncManager->SyncSingleRecord(record);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncSingleRecord_007, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.showName = "测试卡";
    record.phoneNumber = "13800138000";
    record.slotIndex = 0;
    record.cardType = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    
    EXPECT_CALL(*simRdbHelper, QueryDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_DATABASE_READ_FAIL));
    EXPECT_CALL(*simRdbHelper, InsertData(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_SUCCESS));
    
    int32_t result = cacheSyncManager->SyncSingleRecord(record);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimCacheSyncManagerTest, SimCacheSyncManager_SyncSingleRecord_008, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    
    auto simRdbHelper = std::make_shared<MockSimRdbHelper>();
    auto cacheSyncManager = std::make_unique<SimCacheSyncManager>(multiSimController, simRdbHelper);
    
    SimRdbInfo record;
    record.iccId = "12345123451234512345";
    record.showName = "测试卡";
    record.phoneNumber = "13800138000";
    record.slotIndex = 0;
    record.cardType = 1;
    record.isMainCard = 1;
    record.isVoiceCard = 1;
    record.isMessageCard = 1;
    record.isCellularDataCard = 1;
    record.isActive = 1;
    record.isEsim = 0;
    record.simLabelIndex = 1;
    
    EXPECT_CALL(*simRdbHelper, QueryDataByIccId(testing::_, testing::_))
        .WillOnce(testing::Return(TELEPHONY_ERR_DATABASE_READ_FAIL));
    EXPECT_CALL(*simRdbHelper, InsertData(testing::_, testing::_))
        .WillOnce(testing::Return(INVALID_VALUE));
    
    int32_t result = cacheSyncManager->SyncSingleRecord(record);
    EXPECT_EQ(result, TELEPHONY_ERR_DATABASE_WRITE_FAIL);
}
} // namespace Telephony
} // namespace OHOS