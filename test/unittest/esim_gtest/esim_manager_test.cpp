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
#include <unistd.h>

#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "gtest/gtest.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_manager.h"
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimManagerTest::TearDownTestCase() {}

void EsimManagerTest::SetUp() {}

void EsimManagerTest::TearDown() {}

void EsimManagerTest::SetUpTestCase() {}

HWTEST_F(EsimManagerTest, DeleteProfile, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    ResultState DeleteProfileResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->DeleteProfile(slotId, iccId, DeleteProfileResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->DeleteProfile(slotId, iccId, DeleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->DeleteProfile(slotId, iccId, DeleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, SwitchToProfile, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDeactivateSim = true;
    ResultState SwitchProfileResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->SwitchToProfile(slotId, portIndex, iccId, forceDeactivateSim, SwitchProfileResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->SwitchToProfile(slotId, portIndex, iccId, forceDeactivateSim, SwitchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->SwitchToProfile(slotId, portIndex, iccId, forceDeactivateSim, SwitchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, SetProfileNickname, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    ResultState UpdateResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->SetProfileNickname(slotId, iccId, nickname, UpdateResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->SetProfileNickname(slotId, iccId, nickname, UpdateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->SetProfileNickname(slotId, iccId, nickname, UpdateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS
