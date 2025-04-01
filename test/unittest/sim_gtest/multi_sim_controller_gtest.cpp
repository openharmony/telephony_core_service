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

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;

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
    multiSimController->radioProtocolController_ = nullptr;
    multiSimController->Init();
    multiSimController->radioProtocolController_ = radioProtocolController;
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
    EXPECT_TRUE(ret);
}

HWTEST_F(MultiSimControllerTest, MultiSimControllerTest_InitIccId_001, Function | MediumTest | Level1)
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
    EXPECT_TRUE(ret);
}

}
}
