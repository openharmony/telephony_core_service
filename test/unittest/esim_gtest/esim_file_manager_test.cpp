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
#include "sim_file_manager.h"
#include "tel_ril_manager.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class EsimFileManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimFileManagerTest::TearDownTestCase() {}

void EsimFileManagerTest::SetUp() {}

void EsimFileManagerTest::TearDown() {}

void EsimFileManagerTest::SetUpTestCase() {}

HWTEST_F(EsimFileManagerTest, GetEid_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    EXPECT_EQ(simFileManager.GetEid(), Str8ToStr16(expectedEid));
    simFileManager.eSimFile_ = nullptr;
    EXPECT_EQ(simFileManager.GetEid(), u"");
}

HWTEST_F(EsimFileManagerTest, GetEuiccProfileInfoList_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    GetEuiccProfileInfoListInnerResult eUiccRes = simFileManager.GetEuiccProfileInfoList();
    EXPECT_NE(eUiccRes.result_, static_cast<int32_t>(ResultCode::RESULT_OK));
    simFileManager.eSimFile_ = nullptr;
    eUiccRes = simFileManager.GetEuiccProfileInfoList();
    EXPECT_EQ(eUiccRes.result_, static_cast<int32_t>(ResultCode::RESULT_OK));
}

HWTEST_F(EsimFileManagerTest, GetEuiccInfo_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    EuiccInfo eUiccInfo = simFileManager.GetEuiccInfo();
    EXPECT_EQ(eUiccInfo.osVersion_, u"");
    simFileManager.eSimFile_ = nullptr;
    eUiccInfo = simFileManager.GetEuiccInfo();
    EXPECT_EQ(eUiccInfo.osVersion_, u"");
}

HWTEST_F(EsimFileManagerTest, DisableProfile_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string iccId = u"";
    int32_t res = simFileManager.DisableProfile(portIndex, iccId);
    EXPECT_NE(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.DisableProfile(portIndex, iccId);
    EXPECT_EQ(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
}

HWTEST_F(EsimFileManagerTest, GetSmdsAddress_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string resStr = simFileManager.GetSmdsAddress(portIndex);
    EXPECT_EQ(resStr, u"");
    simFileManager.eSimFile_ = nullptr;
    resStr = simFileManager.GetSmdsAddress(portIndex);
    EXPECT_EQ(resStr, u"");
}

HWTEST_F(EsimFileManagerTest, GetRulesAuthTable_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    EuiccRulesAuthTable res = simFileManager.GetRulesAuthTable(portIndex);
    EXPECT_EQ(res.position_, 0);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.GetRulesAuthTable(portIndex);
    EXPECT_EQ(res.position_, 0);
}

HWTEST_F(EsimFileManagerTest, GetEuiccChallenge_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    ResponseEsimInnerResult res = simFileManager.GetEuiccChallenge(portIndex);
    EXPECT_NE(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.GetEuiccChallenge(portIndex);
    EXPECT_EQ(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
}

HWTEST_F(EsimFileManagerTest, RequestDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    std::u16string resStr = simFileManager.GetDefaultSmdpAddress();
    EXPECT_EQ(resStr, u"");
    simFileManager.eSimFile_ = nullptr;
    resStr = simFileManager.GetDefaultSmdpAddress();
    EXPECT_EQ(resStr, u"");
}

HWTEST_F(EsimFileManagerTest, CancelSession_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    std::u16string transactionId = u"";
    CancelReason cancelReason = CancelReason::CANCEL_REASON_END_USER_REJECTION;
    ResponseEsimInnerResult res = simFileManager.CancelSession(transactionId, cancelReason);
    EXPECT_NE(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.CancelSession(transactionId, cancelReason);
    EXPECT_EQ(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
}

HWTEST_F(EsimFileManagerTest, GetProfile_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string iccId = u"";
    EuiccProfile res = simFileManager.GetProfile(portIndex, iccId);
    EXPECT_NE(res.state_, ProfileState::PROFILE_STATE_DISABLED);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.GetProfile(portIndex, iccId);
    EXPECT_NE(res.state_, ProfileState::PROFILE_STATE_DISABLED);
}

HWTEST_F(EsimFileManagerTest, ResetMemory_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    int32_t res = simFileManager.ResetMemory(resetOption);
    EXPECT_NE(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.ResetMemory(resetOption);
    EXPECT_EQ(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
}

HWTEST_F(EsimFileManagerTest, SetDefaultSmdpAddress_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    std::u16string defaultSmdpAddress = u"";
    int32_t res = simFileManager.SetDefaultSmdpAddress(defaultSmdpAddress);
    EXPECT_NE(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.SetDefaultSmdpAddress(defaultSmdpAddress);
    EXPECT_EQ(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
}

HWTEST_F(EsimFileManagerTest, IsSupported_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    bool res = simFileManager.IsSupported();
    EXPECT_EQ(res, false);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.IsSupported();
    EXPECT_EQ(res, false);
}

HWTEST_F(EsimFileManagerTest, SendApduData_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    std::u16string aid = u"";
    EsimApduData apduData;
    ResponseEsimInnerResult res = simFileManager.SendApduData(aid, apduData);
    EXPECT_NE(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.SendApduData(aid, apduData);
    EXPECT_EQ(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
}

HWTEST_F(EsimFileManagerTest, PrepareDownload_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex_ = 0;
    downLoadConfigInfo.hashCc_ = u"";
    ResponseEsimInnerResult res = simFileManager.PrepareDownload(downLoadConfigInfo);
    EXPECT_NE(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
    
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.PrepareDownload(downLoadConfigInfo);
    EXPECT_EQ(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
}

HWTEST_F(EsimFileManagerTest, LoadBoundProfilePackage_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string boundProfilePackage = u"";
    ResponseEsimBppResult res = simFileManager.LoadBoundProfilePackage(portIndex, boundProfilePackage);
    EXPECT_NE(res.resultCode_, 0);
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.LoadBoundProfilePackage(portIndex, boundProfilePackage);
    EXPECT_EQ(res.resultCode_, 0);
}

HWTEST_F(EsimFileManagerTest, ListNotifications_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    Event events = Event::EVENT_DONOTHING;
    EuiccNotificationList lst = simFileManager.ListNotifications(portIndex, events);
    EXPECT_EQ(lst.euiccNotification_.empty(), true);
    simFileManager.eSimFile_ = nullptr;
    lst = simFileManager.ListNotifications(portIndex, events);
    EXPECT_EQ(lst.euiccNotification_.empty(), true);
}

HWTEST_F(EsimFileManagerTest, RetrieveNotificationList_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    Event events = Event::EVENT_DONOTHING;
    EuiccNotificationList lst = simFileManager.RetrieveNotificationList(portIndex, events);
    EXPECT_EQ(lst.euiccNotification_.empty(), true);
    simFileManager.eSimFile_ = nullptr;
    lst = simFileManager.RetrieveNotificationList(portIndex, events);
    EXPECT_EQ(lst.euiccNotification_.empty(), true);
}

HWTEST_F(EsimFileManagerTest, RetrieveNotification_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    int32_t seqNumber = 0;
    EuiccNotification res = simFileManager.RetrieveNotification(portIndex, seqNumber);
    EXPECT_EQ(res.data_, u"");
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.RetrieveNotification(portIndex, seqNumber);
    EXPECT_EQ(res.data_, u"");
}

HWTEST_F(EsimFileManagerTest, RemoveNotificationFromList_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    int32_t seqNumber = 0;
    int32_t res = simFileManager.RemoveNotificationFromList(portIndex, seqNumber);
    EXPECT_NE(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.RemoveNotificationFromList(portIndex, seqNumber);
    EXPECT_EQ(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
}

HWTEST_F(EsimFileManagerTest, DeleteProfile_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    std::u16string iccId = u"";
    int32_t res = simFileManager.DeleteProfile(iccId);
    EXPECT_NE(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.DeleteProfile(iccId);
    EXPECT_EQ(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
}

HWTEST_F(EsimFileManagerTest, SwitchToProfile_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    std::u16string iccId = u"";
    bool forceDisableProfile = false;
    int32_t res = simFileManager.SwitchToProfile(portIndex, iccId, forceDisableProfile);
    EXPECT_NE(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.SwitchToProfile(portIndex, iccId, forceDisableProfile);
    EXPECT_EQ(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
}

HWTEST_F(EsimFileManagerTest, SetProfileNickname_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    std::u16string iccId = u"";
    std::u16string nickname = u"";
    int32_t res = simFileManager.SetProfileNickname(iccId, nickname);
    EXPECT_NE(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.SetProfileNickname(iccId, nickname);
    EXPECT_EQ(res, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER));
}

HWTEST_F(EsimFileManagerTest, GetEuiccInfo2_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    int32_t portIndex = 0;
    EuiccInfo2 res = simFileManager.GetEuiccInfo2(portIndex);
    EXPECT_TRUE(res.svn_.empty());
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.GetEuiccInfo2(portIndex);
    EXPECT_TRUE(res.svn_.empty());
}

HWTEST_F(EsimFileManagerTest, AuthenticateServer_001, Function | MediumTest | Level2)
{
    std::string expectedEid = "12345";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    SimFileManager simFileManager { subcribeInfo, std::weak_ptr<ITelRilManager>(telRilManager),
        std::weak_ptr<SimStateManager>(simStateManager) };
    simFileManager.eSimFile_ = std::make_shared<EsimFile>(simStateManager);
    AuthenticateConfigInfo authenticateConfigInfo;
    ResponseEsimInnerResult res = simFileManager.AuthenticateServer(authenticateConfigInfo);
    EXPECT_NE(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
    simFileManager.eSimFile_ = nullptr;
    res = simFileManager.AuthenticateServer(authenticateConfigInfo);
    EXPECT_EQ(res.resultCode_, static_cast<int32_t>(ResultCode::RESULT_OK));
}
} // namespace Telephony
} // namespace OHOS
