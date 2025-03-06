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

#include "common_event_manager.h"
#include "common_event_support.h"
#include "gtest/gtest.h"
#include "tel_ril_manager.h"
#include "sim_file_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class SimFileManagerBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SimFileManagerBranchTest::TearDownTestCase() {}

void SimFileManagerBranchTest::SetUp() {}

void SimFileManagerBranchTest::TearDown() {}

void SimFileManagerBranchTest::SetUpTestCase() {}

HWTEST_F(SimFileManagerBranchTest, Telephony_SimFileManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    int slotId = 1;
    simFileManager.stateRecord_ = SimFileManager::HandleRunningState::STATE_RUNNING;
    simFileManager.Init(slotId);
    EXPECT_EQ(simFileManager.iccType_, SimFileManager::IccType::ICC_TYPE_USIM);

    simFileManager.stateRecord_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager.stateRecord_ = SimFileManager::HandleRunningState::STATE_RUNNING;
    simFileManager.Init(slotId);
    EXPECT_EQ(simFileManager.iccType_, SimFileManager::IccType::ICC_TYPE_USIM);

    simFileManager.stateRecord_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager.stateRecord_ = SimFileManager::HandleRunningState::STATE_NOT_START;
    simFileManager.telRilManager_ = std::weak_ptr<TelRilManager>();
    simFileManager.Init(slotId);
    EXPECT_EQ(simFileManager.iccType_, SimFileManager::IccType::ICC_TYPE_USIM);

    simFileManager.telRilManager_ = std::weak_ptr<ITelRilManager>(telRilManager);
    simFileManager.simStateManager_ = std::weak_ptr<SimStateManager>();
    simFileManager.Init(slotId);
    EXPECT_EQ(simFileManager.iccType_, SimFileManager::IccType::ICC_TYPE_USIM);
}

HWTEST_F(SimFileManagerBranchTest, Telephony_SimFileManager_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };

    simFileManager.fileController_ = nullptr;
    EXPECT_FALSE(simFileManager.InitSimFile(SimFileManager::IccType::ICC_TYPE_CDMA));

    int slotId = 1;
    simFileManager.fileController_ = std::make_shared<RuimFileController>(slotId);
    simFileManager.diallingNumberHandler_ = nullptr;
    EXPECT_FALSE(simFileManager.InitSimFile(SimFileManager::IccType::ICC_TYPE_CDMA));

    simFileManager.fileController_ = nullptr;
    simFileManager.iccFileControllerCache_.insert(std::make_pair(SimFileManager::IccType::ICC_TYPE_CDMA, nullptr));
    EXPECT_FALSE(simFileManager.InitIccFileController(SimFileManager::IccType::ICC_TYPE_CDMA));

    simFileManager.iccFileControllerCache_.clear();
    EXPECT_TRUE(simFileManager.InitIccFileController(SimFileManager::IccType::ICC_TYPE_CDMA));
    EXPECT_EQ(simFileManager.iccFileControllerCache_.size(), 1);

    simFileManager.iccFileControllerCache_.clear();
    EXPECT_TRUE(simFileManager.InitIccFileController(SimFileManager::IccType::ICC_TYPE_IMS));
    EXPECT_EQ(simFileManager.iccFileControllerCache_.size(), 1);

    simFileManager.iccFileControllerCache_.clear();
    EXPECT_TRUE(simFileManager.InitIccFileController(SimFileManager::IccType::ICC_TYPE_GSM));
    EXPECT_EQ(simFileManager.iccFileControllerCache_.size(), 1);

    simFileManager.iccFileControllerCache_.clear();
    EXPECT_TRUE(simFileManager.InitIccFileController(SimFileManager::IccType::ICC_TYPE_USIM));
    EXPECT_EQ(simFileManager.iccFileControllerCache_.size(), 1);
}

HWTEST_F(SimFileManagerBranchTest, Telephony_SimFileManager_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };

    simFileManager.simFile_ = nullptr;
    std::string number = "";
    EXPECT_EQ(simFileManager.GetMCC(), u"");
    EXPECT_EQ(simFileManager.GetMNC(), u"");
    EXPECT_EQ(simFileManager.GetSimDecIccId(), u"");
    EXPECT_EQ(simFileManager.GetVoiceMailCount(), UNKNOWN_VOICE_MAIL_COUNT);
    EXPECT_FALSE(simFileManager.SetVoiceMailCount(0));
    EXPECT_FALSE(simFileManager.SetVoiceCallForwarding(0, number));

    simFileManager.simFile_ = std::make_shared<RuimFile>(simStateManager);
    EXPECT_EQ(simFileManager.GetISOCountryCodeForSim(), u"");
    EXPECT_EQ(simFileManager.GetSimSpn(), u"");
    EXPECT_EQ(simFileManager.GetSimDecIccId(), u"");
    EXPECT_EQ(simFileManager.GetSimGid1(), u"");
    EXPECT_EQ(simFileManager.GetVoiceMailIdentifier(), u"");
    EXPECT_EQ(simFileManager.GetVoiceMailCount(), DEFAULT_VOICE_MAIL_COUNT);
    EXPECT_FALSE(simFileManager.SetVoiceMailCount(0));
    EXPECT_FALSE(simFileManager.SetVoiceCallForwarding(0, number));
    simFileManager.UnRegisterCoreNotify(nullptr, RadioEvent::RADIO_STK_SESSION_END);
    simFileManager.SetImsi("testImsi");

    std::u16string testU16Str = u"";
    EXPECT_FALSE(simFileManager.SetSimTelephoneNumber(testU16Str, testU16Str));

    simFileManager.simStateManager_ = std::weak_ptr<SimStateManager>();
    EXPECT_EQ(simFileManager.GetSimIccId(), u"");

    simFileManager.simFile_->SetVoiceMailNumber("testNum");
    EXPECT_STREQ((simFileManager.simFile_->voiceMailNum_).c_str(), "testNum");
    EXPECT_STREQ((simFileManager.GetVoiceMailNumberKey()).c_str(), "testNum");
}

HWTEST_F(SimFileManagerBranchTest, Telephony_SimFileManager_004, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };

    EXPECT_STREQ((simFileManager.EncryptImsi("")).c_str(), "");
    EXPECT_STRNE((simFileManager.EncryptImsi("460001234567890")).c_str(), "");

    simFileManager.simStateManager_ = std::weak_ptr<SimStateManager>();
    EXPECT_FALSE(simFileManager.HasSimCard());
    EXPECT_FALSE(simFileManager.IsCTSimCard());

    simFileManager.fileController_ = nullptr;
    EXPECT_FALSE(simFileManager.InitDiallingNumberHandler());

    int slotId = 1;
    simFileManager.fileController_ = std::make_shared<RuimFileController>(slotId);
    simFileManager.diallingNumberHandler_ = std::make_shared<IccDiallingNumbersHandler>(simFileManager.fileController_);
    EXPECT_TRUE(simFileManager.InitDiallingNumberHandler());

    simFileManager.simFile_ = nullptr;
    simFileManager.HandleSimRecordsLoaded();
    simFileManager.HandleSimIccidLoaded("testIccid");

    auto ril = std::weak_ptr<ITelRilManager>();
    auto simState = std::weak_ptr<SimStateManager>();
    EXPECT_EQ(ril.lock(), nullptr);
    EXPECT_EQ(simFileManager.CreateInstance(ril, simState), nullptr);

    ril = std::weak_ptr<ITelRilManager>(telRilManager);
    EXPECT_NE(ril.lock(), nullptr);
    EXPECT_EQ(simState.lock(), nullptr);
    EXPECT_EQ(simFileManager.CreateInstance(ril, simState), nullptr);

    EXPECT_EQ(simFileManager.GetIccTypeByCardType(CardType::SINGLE_MODE_ISIM_CARD),
        SimFileManager::IccType::ICC_TYPE_IMS);

    simFileManager.simFile_ = std::make_shared<IsimFile>(simStateManager);
    EXPECT_EQ(simFileManager.GetSimIst(), u"");
}

HWTEST_F(SimFileManagerBranchTest, Telephony_SimFileManager_005, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<SimFileManager> simFileManager = SimFileManager::CreateInstance(
        std::weak_ptr<ITelRilManager>(telRilManager), std::weak_ptr<SimStateManager>(simStateManager));
    EXPECT_NE(simFileManager, nullptr);
    if (simFileManager != nullptr) {
        AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_VOICE_TECH_CHANGED);
        simFileManager->ProcessEvent(event);
        std::shared_ptr<VoiceRadioTechnology> voiceRadioTechnology = std::make_shared<VoiceRadioTechnology>();
        event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_VOICE_TECH_CHANGED, voiceRadioTechnology);
        simFileManager->ProcessEvent(event);
        event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_ICC_REFRESH);
        simFileManager->ProcessEvent(event);
        event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR_CONFIG_CHANGED);
        simFileManager->ProcessEvent(event);
        int slotId = 1;
        simFileManager->Init(slotId);
        EXPECT_NE(simFileManager->simFile_, nullptr);
        event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_ICC_REFRESH);
        simFileManager->ProcessEvent(event);
        event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR_CONFIG_CHANGED);
        simFileManager->ProcessEvent(event);
        EXPECT_EQ(simFileManager->GetVoiceMailCount(), DEFAULT_VOICE_MAIL_COUNT);
    }
}
} // namespace Telephony
} // namespace OHOS
