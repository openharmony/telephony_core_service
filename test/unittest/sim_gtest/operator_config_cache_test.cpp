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
#include "operator_config_cache.h"
#include "mock_datashare_helper.h"
#include "observer_handler.h"
#include "tel_ril_manager.h"
#include "common_event_support.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>
 
namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;
 
class OperatorConfigCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
 
void OperatorConfigCacheTest::SetUpTestCase() {}
 
void OperatorConfigCacheTest::TearDownTestCase() {}
 
void OperatorConfigCacheTest::SetUp() {}
 
void OperatorConfigCacheTest::TearDown() {}

class IOperatorConfigHisyseventImpl : public IOperatorConfigHisysevent {
public:
    IOperatorConfigHisyseventImpl() = default;
    ~IOperatorConfigHisyseventImpl() = default;
    void InitOperatorConfigHisysevent(int32_t slotId, int32_t simState) override
    {
    }
    void SetMatchSimResult(int32_t slotId, const char* opkey, const char* opname, int32_t matchSimState) override
    {
    }
    void SetMatchSimFile(int32_t slotId, MatchSimFileType simFileType, const std::string &simFile) override
    {
    }
    void SetMatchSimReason(int32_t slotId, MatchSimReason matchSimReason) override
    {
    }
    void SetMatchSimStateTracker(MatchSimState matchSimStateTracker, int32_t slotId = -1) override
    {
    }
    void SetMatchSimStateTracker(int8_t matchSimStateTracker, int32_t slotId) override
    {
    }
    void ReportMatchSimChr(int32_t slotId) override
    {
    }
};

HWTEST_F(OperatorConfigCacheTest, NotifyInitApnConfigsTest001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    auto dataShareHelper = std::make_shared<MockDataShareHelper>();
    EXPECT_CALL(*dataShareHelper, Creator(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::DoAll(testing::Return(nullptr)));
    operatorConfigCache->notifyInitApnConfigs(0);
    operatorConfigCache->batchInsertApnRetryTask_();
    EXPECT_NE(operatorConfigCache->retryBatchInsertApnTimes_, 0);
}
 
HWTEST_F(OperatorConfigCacheTest, NotifyInitApnConfigsTest002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    auto dataShareHelper = std::make_shared<MockDataShareHelper>();
    EXPECT_CALL(*dataShareHelper, Creator(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::DoAll(testing::Return(nullptr)));
    operatorConfigCache->notifyInitApnConfigs(0);
    operatorConfigCache->batchInsertApnRetryHandler_ = nullptr;
    operatorConfigCache->batchInsertApnRetryTask_();
    EXPECT_NE(operatorConfigCache->retryBatchInsertApnTimes_, 0);
}
 
HWTEST_F(OperatorConfigCacheTest, NotifyInitApnConfigsTest003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    auto dataShareHelper = std::make_shared<MockDataShareHelper>();
    EXPECT_CALL(*dataShareHelper, Creator(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::DoAll(testing::Return(nullptr)));
    operatorConfigCache->retryBatchInsertApnTimes_ = 5;
    operatorConfigCache->notifyInitApnConfigs(0);
    operatorConfigCache->batchInsertApnRetryTask_();
    EXPECT_NE(operatorConfigCache->retryBatchInsertApnTimes_, 0);
}

HWTEST_F(OperatorConfigCacheTest, ProcessEvent, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager);
    simStateHandle->slotId_ = 0;
    simStateHandle->externalState_ = SimState::SIM_STATE_LOCKED;
    simStateManager->simStateHandle_  = simStateHandle;
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    simFileManager->SetOpKey("46001");
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    operatorConfigCache->ProcessEvent(AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE));
    EXPECT_NE(simFileManager->opKey_, "46001");
}

HWTEST_F(OperatorConfigCacheTest, RegisterForIccChange, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simStateHandle = std::make_shared<SimStateHandle>(simStateManager);
    simStateHandle->slotId_ = 0;
    simStateHandle->externalState_ = SimState::SIM_STATE_LOCKED;
    simStateHandle->observerHandler_ = std::make_unique<ObserverHandler>();
    simStateManager->simStateHandle_  = simStateHandle;
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    bool result = operatorConfigCache->RegisterForIccChange();
    EXPECT_TRUE(result);
}

HWTEST_F(OperatorConfigCacheTest, OperatorConfigCache_Expand001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);

    operatorConfigCache->ClearAllCache(0);
    operatorConfigCache->ClearMemoryAndOpkey(0);

    OperatorConfig poc;
    operatorConfigCache->simFileManager_.reset();
    operatorConfigCache->ClearOperatorValue(0);
    EXPECT_TRUE(operatorConfigCache->LoadOperatorConfigFile(0, poc) == TELEPHONY_ERR_LOCAL_PTR_NULL);
    operatorConfigCache->simFileManager_ = simFileManager;

    simStateManager->simStateHandle_.reset();
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE);
    operatorConfigCache->ProcessEvent(event);
    event = nullptr;
    operatorConfigCache->ProcessEvent(event);
    operatorConfigCache->AnnounceOperatorConfigChanged(0, 1);

    simStateManager->simStateHandle_ = std::make_shared<SimStateHandle>(simStateManager);
    simStateManager->simStateHandle_->iccid_ = "1234";
    operatorConfigCache->iccidCache_ = "";
    poc.configValue.clear();
    operatorConfigCache->LoadOperatorConfigFile(0, poc);

    poc.configValue = {
        {u"key1", u"value1"},
        {u"key2", u"value2"}
    };
    operatorConfigCache->GetOperatorConfigs(0, poc);

    auto Impl = std::make_shared<IOperatorConfigHisyseventImpl>();
    operatorConfigCache->operatorConfigHisysevent_ = Impl;
    operatorConfigCache->UpdateOperatorConfigs(0);

    operatorConfigCache->simFileManager_.reset();
    operatorConfigCache->LoadOperatorConfig(0, poc, 0);
    operatorConfigCache->RegisterForIccChange();
    operatorConfigCache->UnRegisterForIccChange();
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 0);
    operatorConfigCache->simFileManager_ = simFileManager;

    simFileManager->opKey_ = "1234";
    operatorConfigCache->modemSimMatchedOpNameCache_ = "";
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 0);
    operatorConfigCache->modemSimMatchedOpNameCache_ = "123";
    operatorConfigCache->iccidCache_ = "1234";
    operatorConfigCache->slotId_ = 1;
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 0);
    operatorConfigCache->slotId_ = 0;
    operatorConfigCache->simStateManager_.reset();
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 0);
    operatorConfigCache->simStateManager_ = simStateManager;
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 0);

    operatorConfigCache->isLoadingConfig_ = true;
    operatorConfigCache->IsNeedOperatorLoad(0);
    operatorConfigCache->isLoadingConfig_ = false;
    operatorConfigCache->simFileManager_.reset();
    operatorConfigCache->IsNeedOperatorLoad(0);
    operatorConfigCache->simFileManager_ = simFileManager;
    operatorConfigCache->IsNeedOperatorLoad(0);

    operatorConfigCache->iccidCache_ = "";
    operatorConfigCache->simFileManager_.reset();
    operatorConfigCache->UpdateIccidCache(0);
    operatorConfigCache->simFileManager_ = simFileManager;

    operatorConfigCache->simStateManager_.reset();
    operatorConfigCache->slotId_ = 1;
    SimState state;
    operatorConfigCache->GetSimState(0, state);
    operatorConfigCache->GetSimState(1, state);
    operatorConfigCache->simStateManager_ = simStateManager;
}
}
}