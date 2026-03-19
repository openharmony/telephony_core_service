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
#include "telephony_ext_wrapper.h"
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

    auto Impl = std::make_shared<IOperatorConfigHisyseventImpl>();
    operatorConfigCache->operatorConfigHisysevent_ = Impl;

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

    operatorConfigCache->UpdateOperatorConfigs(0);

    operatorConfigCache->simFileManager_.reset();
    operatorConfigCache->LoadOperatorConfig(0, poc, 0);
    operatorConfigCache->RegisterForIccChange();
    operatorConfigCache->UnRegisterForIccChange();
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 0);
    operatorConfigCache->simFileManager_ = simFileManager;
}

HWTEST_F(OperatorConfigCacheTest, OperatorConfigCache_Expand002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);

    auto Impl = std::make_shared<IOperatorConfigHisyseventImpl>();
    operatorConfigCache->operatorConfigHisysevent_ = Impl;
    simStateManager->simStateHandle_ = std::make_shared<SimStateHandle>(simStateManager);
    simStateManager->simStateHandle_->iccid_ = "1234";
    operatorConfigCache->iccidCache_ = "";
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
    operatorConfigCache->IsNeedOperatorLoad(0);
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
    EXPECT_TRUE(operatorConfigCache->simStateManager_ != nullptr);
}

HWTEST_F(OperatorConfigCacheTest, OperatorConfigCache_Expand003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);

    OperatorConfig from;
    OperatorConfig to;
    from.longValue["1234"] = 0;
    std::vector<int64_t> vec = {0, 1, 2, 3};
    from.longArrayValue["1234"] = vec;
    std::vector<std::string> strVec= {"1234", "1345"};
    from.stringArrayValue["1234"] = strVec;

    operatorConfigCache->CopyOperatorConfig(from, to);
    operatorConfigCache->opc_.configValue.clear();
    operatorConfigCache->GetOperatorConfigs(0, from);
    EXPECT_TRUE(to.longValue.size() > 0);
}

HWTEST_F(OperatorConfigCacheTest, SimFileManager_Expand001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<SimStateManager> simStateManagerNullptr = nullptr;
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManagerNullptr);

    simFileManager->simStateManager_ = simStateManager;
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    simFileManager->stateRecord_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager->stateHandler_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager->Init(0);
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();

    simFileManager->stateRecord_ = SimFileManager::HandleRunningState::STATE_RUNNING;
    simFileManager->Init(0);
    simFileManager->stateRecord_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager->stateHandler_ = SimFileManager::HandleRunningState::STATE_RUNNING;
    simFileManager->Init(0);
    simFileManager->stateHandler_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager->simStateManager_.reset();
    simFileManager->Init(0);
    simFileManager->telRilManager_.reset();
    simFileManager->Init(0);
    EXPECT_TRUE(simFileManager->simStateManager_.lock() == nullptr);
}

HWTEST_F(OperatorConfigCacheTest, SimFileManager_Expand002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);

    simFileManager->GetMCC();
    simFileManager->GetMNC();
    simFileManager->GetISOCountryCodeForSim();
    simFileManager->GetSimSpn();
    simFileManager->GetSimDecIccId();
    simFileManager->GetIMSI();
    simFileManager->GetEhPlmns();
    simFileManager->GetSpdiPlmns();
    simFileManager->GetLocaleFromDefaultSim();
    simFileManager->GetSimGid1();
    simFileManager->GetSimGid2();
    simFileManager->GetSimTeleNumberIdentifier();
    simFileManager->GetVoiceMailIdentifier();

    simFileManager->stateRecord_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager->stateHandler_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager->Init(0);

    SimFileManager::IccType iccType = SimFileManager::IccType::ICC_TYPE_IMS;
    simFileManager->InitIccFileController(iccType);

    simFileManager->GetSimOperatorNumeric();
    simFileManager->GetMCC();
    simFileManager->GetMNC();
    simFileManager->GetISOCountryCodeForSim();
    simFileManager->GetSimSpn();
    simFileManager->GetSimDecIccId();
    simFileManager->GetIMSI();
    simFileManager->GetEhPlmns();
    simFileManager->GetSpdiPlmns();
    simFileManager->GetLocaleFromDefaultSim();
    simFileManager->GetSimGid1();
    simFileManager->GetSimGid2();
    simFileManager->SetSimTelephoneNumber(u"", u"");
    simFileManager->GetSimTeleNumberIdentifier();
    simFileManager->GetVoiceMailIdentifier();

    simFileManager->simStateManager_.reset();
    simFileManager->GetSimIccId();
    simFileManager->simStateManager_ = simStateManager;
    EXPECT_TRUE(simFileManager->simStateManager_.lock() != nullptr);
}

HWTEST_F(OperatorConfigCacheTest, SimFileManager_Expand003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);

    simFileManager->GetVoiceMailNumber();
    simFileManager->GetVoiceMailCount();
    simFileManager->SetVoiceMailCount(0);
    simFileManager->SetVoiceCallForwarding(true, "");
    simFileManager->ObtainSpnCondition(true, "");
    simFileManager->RegisterCoreNotify(std::make_shared<AppExecFwk::EventHandler>(), RadioEvent::RADIO_ICC_REFRESH);
    simFileManager->UnRegisterCoreNotify(std::make_shared<AppExecFwk::EventHandler>(), RadioEvent::RADIO_ICC_REFRESH);
    simFileManager->SetImsi("");

    simFileManager->Init(0);

    simFileManager->simFile_->voiceMailNum_ = "1234";
    simFileManager->GetVoiceMailNumberKey();
    simFileManager->simFile_->voiceMailNum_ = "";
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    simFileManager->GetVoiceMailNumberKey();
    std::u16string mailNumber = u"1234";
    simFileManager->SetVoiceMailParamGsm(mailNumber, true);
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    simFileManager->GetVoiceMailNumberKey();

    simFileManager->GetVoiceMailNumber();
    simFileManager->GetVoiceMailCount();
    simFileManager->SetVoiceMailCount(0);
    simFileManager->SetVoiceCallForwarding(true, "");
    simFileManager->SetImsi("");
    simFileManager->StoreVoiceMailNumber(mailNumber, true);
    simFileManager->SetVoiceMailInfo(u"", u"");

    simFileManager->GetVoiceMailNumberFromParam();
    simFileManager->GetOpKeyExt();

    simFileManager->simStateManager_.reset();
    EXPECT_TRUE(simFileManager->HasSimCard() == false);
}

HWTEST_F(OperatorConfigCacheTest, SimFileManager_Expand004, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);

    simFileManager->InitDiallingNumberHandler();
    simFileManager->fileController_ = std::make_shared<RuimFileController>(0);
    simFileManager->InitDiallingNumberHandler();
    simFileManager->InitDiallingNumberHandler();

    simFileManager->IsCTSimCard();
    simFileManager->HandleOperatorConfigChanged();
    simFileManager->HandleSimRecordsLoaded();

    simFileManager->Init(0);
    simFileManager->UpdateOpkeyConfig();

    simFileManager->IsCTSimCard();
    simFileManager->HandleOperatorConfigChanged();
    simFileManager->HandleSimRecordsLoaded();

    simFileManager->simStateManager_.reset();
    simFileManager->IsCTSimCard();
    simFileManager->IsCTIccId("8986567");
    EXPECT_TRUE(simFileManager->simStateManager_.lock() == nullptr);
}

HWTEST_F(OperatorConfigCacheTest, SimFileManager_Expand005, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    simFileManager->Init(0);

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_VOICE_TECH_CHANGED, 0);
    simFileManager->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_CARD_TYPE_CHANGE, 0);
    simFileManager->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_RECORDS_LOADED, 0);
    simFileManager->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_ICC_REFRESH, 0);
    simFileManager->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_ICCID_LOADED, 0);
    simFileManager->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR_CONFIG_CHANGED, 0);
    simFileManager->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_GET_PRIMARY_SLOT, 0);
    simFileManager->ProcessEvent(event);
    simFileManager->simStateManager_.reset();
    simFileManager->ProcessEvent(event);
    event.reset();
    simFileManager->ProcessEvent(event);

    simStateManager.reset();
    simFileManager->CreateInstance(telRilManager, simStateManager);
    telRilManager.reset();
    EXPECT_TRUE(simFileManager->CreateInstance(telRilManager, simStateManager) == nullptr);
}

}
}