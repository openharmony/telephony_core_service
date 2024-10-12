/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <string_ex.h>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_service.h"
#include "core_service_client.h"
#include "core_service_dump_helper.h"
#include "core_service_hisysevent.h"
#include "network_search_manager.h"
#include "operator_name.h"
#include "operator_name_utils.h"
#include "security_token.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
std::shared_ptr<SimManager> g_simManagerPtr = nullptr;

namespace {
constexpr int32_t SLEEP_TIME_SECONDS = 3;
constexpr int32_t SLOT_ID = 0;
const int32_t INVALID_SLOTID = -1;
constexpr int32_t NR_NSA_OPTION_ONLY = 1;
constexpr int32_t SIGNAL_STRENGTH_GOOD = 3;
const std::string NITZ_STR = "23/10/16,09:10:33+32,00";
const std::string NITZ_STR_INVALID = "202312102359";
constexpr int32_t LTE_RSSI_GOOD = -80;
} // namespace

class CoreServiceBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void CoreServiceBranchTest::SetUpTestCase()
{
    DelayedSingleton<CoreService>::GetInstance()->Init();
    auto iSimManager = DelayedSingleton<CoreService>::GetInstance()->simManager_;
    if (iSimManager == nullptr) {
        return;
    }
    g_simManagerPtr = std::static_pointer_cast<SimManager>(iSimManager);
}

void CoreServiceBranchTest::TearDownTestCase()
{
    if (g_simManagerPtr != nullptr && g_simManagerPtr->multiSimMonitor_ != nullptr) {
        g_simManagerPtr->multiSimMonitor_->remainCount_ = 0;
        sleep(SLEEP_TIME_SECONDS);
    }
    auto telRilManager = DelayedSingleton<CoreService>::GetInstance()->telRilManager_;
    if (telRilManager == nullptr) {
        return;
    }
    auto handler = telRilManager->handler_;
    if (handler != nullptr) {
        handler->RemoveAllEvents();
        handler->SendEvent(0, 0, AppExecFwk::EventQueue::Priority::HIGH);
        sleep(SLEEP_TIME_SECONDS);
    }
    telRilManager->DisConnectRilInterface();
    telRilManager->DeInit();
    DelayedSingleton<CoreService>::GetInstance()->Stop();
    DelayedSingleton<CoreService>::DestroyInstance();
    sleep(SLEEP_TIME_SECONDS);
}

void CoreServiceBranchTest::SetUp() {}

void CoreServiceBranchTest::TearDown() {}

/**
 * @tc.number   Telephony_CoreService_NetWork_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_NetWork_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t psRadioTech;
    EXPECT_GE(
        DelayedSingleton<CoreService>::GetInstance()->GetPsRadioTech(SLOT_ID, psRadioTech), TELEPHONY_ERR_SUCCESS);
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    int32_t result = DelayedSingleton<CoreService>::GetInstance()->SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, nullptr);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    std::vector<sptr<SignalInformation>> signals;
    result = DelayedSingleton<CoreService>::GetInstance()->GetSignalInfoList(SLOT_ID, signals);
    DelayedSingleton<CoreService>::GetInstance()->GetOperatorNumeric(SLOT_ID);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    std::u16string u16OperatorName = u"";
    result = DelayedSingleton<CoreService>::GetInstance()->GetOperatorName(SLOT_ID, u16OperatorName);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    sptr<NetworkState> networkState = nullptr;
    DelayedSingleton<CoreService>::GetInstance()->GetNetworkState(SLOT_ID, networkState);
    DelayedSingleton<CoreService>::GetInstance()->SetRadioState(SLOT_ID, false, nullptr);
    DelayedSingleton<CoreService>::GetInstance()->SetRadioState(SLOT_ID, false, nullptr);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreService_NetWork_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_NetWork_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    DelayedSingleton<CoreService>::GetInstance()->GetPreferredNetwork(SLOT_ID, nullptr);
    DelayedSingleton<CoreService>::GetInstance()->SetPreferredNetwork(SLOT_ID, 1, nullptr);
    int32_t networkCapabilityType = 1;
    int32_t networkCapabilityState = 1;
    DelayedSingleton<CoreService>::GetInstance()->GetNetworkCapability(
        SLOT_ID, networkCapabilityType, networkCapabilityState);
    DelayedSingleton<CoreService>::GetInstance()->SetNetworkCapability(
        SLOT_ID, networkCapabilityType, networkCapabilityState);
    std::vector<sptr<CellInformation>> cellList;
    int32_t result = DelayedSingleton<CoreService>::GetInstance()->GetCellInfoList(SLOT_ID, cellList);
    DelayedSingleton<CoreService>::GetInstance()->SendUpdateCellLocationRequest(SLOT_ID);
    DelayedSingleton<CoreService>::GetInstance()->FactoryReset(SLOT_ID);
    std::u16string u16Ret = u"";
    DelayedSingleton<CoreService>::GetInstance()->GetIsoCountryCodeForNetwork(SLOT_ID, u16Ret);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    result = DelayedSingleton<CoreService>::GetInstance()->GetImei(SLOT_ID, u16Ret);
    DelayedSingleton<CoreService>::GetInstance()->GetImeiSv(SLOT_ID, u16Ret);
    DelayedSingleton<CoreService>::GetInstance()->GetMeid(SLOT_ID, u16Ret);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    result = DelayedSingleton<CoreService>::GetInstance()->GetUniqueDeviceId(SLOT_ID, u16Ret);
    DelayedSingleton<CoreService>::GetInstance()->IsNrSupported(SLOT_ID);
    DelayedSingleton<CoreService>::GetInstance()->GetPreferredNetwork(SLOT_ID, nullptr);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    result = DelayedSingleton<CoreService>::GetInstance()->SetNrOptionMode(SLOT_ID, NR_NSA_OPTION_ONLY, nullptr);
    DelayedSingleton<CoreService>::GetInstance()->GetNetworkSearchInformation(SLOT_ID, nullptr);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    DelayedSingleton<CoreService>::GetInstance()->GetNrOptionMode(SLOT_ID, nullptr);
    DelayedSingleton<CoreService>::GetInstance()->GetNetworkSelectionMode(SLOT_ID, nullptr);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreService_Sim_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_Sim_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    bool hasSimCard = false;
    DelayedSingleton<CoreService>::GetInstance()->HasSimCard(SLOT_ID, hasSimCard);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    DelayedSingleton<CoreService>::GetInstance()->GetSimState(SLOT_ID, simState);
    CardType cardType = CardType::UNKNOWN_CARD;
    int32_t result = DelayedSingleton<CoreService>::GetInstance()->GetCardType(SLOT_ID, cardType);
    std::u16string countryCode;
    DelayedSingleton<CoreService>::GetInstance()->GetISOCountryCodeForSim(SLOT_ID, countryCode);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    std::u16string testU16Str = u"";
    result = DelayedSingleton<CoreService>::GetInstance()->GetSimSpn(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetSimIccId(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetSimOperatorNumeric(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetIMSI(SLOT_ID, testU16Str);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    DelayedSingleton<CoreService>::GetInstance()->IsSimActive(SLOT_ID);
    int32_t simId = 1;
    result = DelayedSingleton<CoreService>::GetInstance()->GetSlotId(simId);
    DelayedSingleton<CoreService>::GetInstance()->GetLocaleFromDefaultSim();
    DelayedSingleton<CoreService>::GetInstance()->GetSimGid1(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetSimGid2(SLOT_ID);
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    int32_t lac = 1;
    bool longNameRequired = true;
    std::string plmn = "46001";
    DelayedSingleton<CoreService>::GetInstance()->GetSimEons(SLOT_ID, plmn, lac, longNameRequired);
    IccAccountInfo info;
    result = DelayedSingleton<CoreService>::GetInstance()->GetSimAccountInfo(SLOT_ID, info);
    DelayedSingleton<CoreService>::GetInstance()->SetDefaultVoiceSlotId(SLOT_ID);
    DelayedSingleton<CoreService>::GetInstance()->GetDefaultVoiceSlotId();
    DelayedSingleton<CoreService>::GetInstance()->GetDefaultVoiceSimId(simId);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    int32_t dsdsMode = 0;
    DelayedSingleton<CoreService>::GetInstance()->GetDsdsMode(dsdsMode);
    DelayedSingleton<CoreService>::GetInstance()->GetPrimarySlotId(result);
    const std::u16string cardNumber = Str8ToStr16("SimNumber12345678901");
    result = DelayedSingleton<CoreService>::GetInstance()->SetShowNumber(SLOT_ID, cardNumber);
    DelayedSingleton<CoreService>::GetInstance()->GetShowNumber(SLOT_ID, testU16Str);
    const std::u16string cardName = Str8ToStr16("SimNameZhang");
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    DelayedSingleton<CoreService>::GetInstance()->SetShowName(SLOT_ID, cardName);
    DelayedSingleton<CoreService>::GetInstance()->GetShowName(SLOT_ID, testU16Str);
    std::vector<IccAccountInfo> iccAccountInfoList = {};
    DelayedSingleton<CoreService>::GetInstance()->GetActiveSimAccountInfoList(iccAccountInfoList);
    EXPECT_GE(DelayedSingleton<CoreService>::GetInstance()->GetShowName(SLOT_ID, testU16Str), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreService_Sim_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_Sim_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    DelayedSingleton<CoreService>::GetInstance()->RefreshSimState(SLOT_ID);
    std::u16string testU16Str = u"";
    int32_t result = DelayedSingleton<CoreService>::GetInstance()->GetSimTelephoneNumber(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetSimTeleNumberIdentifier(SLOT_ID);
    std::string number = "01234567890123456789";
    DelayedSingleton<CoreService>::GetInstance()->SetVoiceCallForwarding(SLOT_ID, true, number);
    DelayedSingleton<CoreService>::GetInstance()->GetOpKey(SLOT_ID, testU16Str);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    result = DelayedSingleton<CoreService>::GetInstance()->GetOpKeyExt(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetOpKeyExt(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetOpName(SLOT_ID, testU16Str);
    ImsRegInfo mImsRegInfo;
    DelayedSingleton<CoreService>::GetInstance()->GetImsRegStatus(SLOT_ID, ImsServiceType::TYPE_VOICE, mImsRegInfo);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
    SimAuthenticationResponse response = { 0 };
    AuthType authType = AuthType::SIM_AUTH_EAP_SIM_TYPE;
    std::string authData = "1234";
    DelayedSingleton<CoreService>::GetInstance()->SimAuthentication(SLOT_ID, authType, authData, response);
    bool isCTSimCard = false;
    DelayedSingleton<CoreService>::GetInstance()->IsCTSimCard(SLOT_ID, isCTSimCard);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreService_Stub_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_Stub_001, Function | MediumTest | Level1)
{
    uint32_t maxCode = static_cast<uint32_t>(CoreServiceInterfaceCode::GET_SIM_IO_DONE);
    int32_t result = 0;
    for (uint32_t code = 0; code <= maxCode; code++) {
        if (code == static_cast<uint32_t>(CoreServiceInterfaceCode::HAS_OPERATOR_PRIVILEGES)) {
            continue;
        }
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(CoreServiceStub::GetDescriptor());
        result = DelayedSingleton<CoreService>::GetInstance()->OnRemoteRequest(code, data, reply, option);
        EXPECT_GE(result, NO_ERROR);
    }
    std::string version;
    EXPECT_GE(
        DelayedSingleton<CoreService>::GetInstance()->GetBasebandVersion(SLOT_ID, version), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreService_Stub_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_Stub_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t slotId = SLOT_ID;
    uint32_t maxCode = static_cast<uint32_t>(CoreServiceInterfaceCode::GET_SIM_IO_DONE);
    for (uint32_t code = 0; code <= maxCode; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(CoreServiceStub::GetDescriptor());
        data.WriteInt32(slotId);
        DelayedSingleton<CoreService>::GetInstance()->OnRemoteRequest(code, data, reply, option);
    }
    std::string version;
    EXPECT_GE(
        DelayedSingleton<CoreService>::GetInstance()->GetBasebandVersion(SLOT_ID, version), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreService_Stub_003
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_Stub_003, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t slotId = SLOT_ID;
    uint32_t maxCode = static_cast<uint32_t>(CoreServiceInterfaceCode::GET_SIM_IO_DONE);
    for (uint32_t code = 0; code <= maxCode; code++) {
        if (code == static_cast<uint32_t>(CoreServiceInterfaceCode::HAS_OPERATOR_PRIVILEGES)) {
            continue;
        }
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(CoreServiceStub::GetDescriptor());
        data.WriteInt32(slotId);
        data.WriteRemoteObject(nullptr);
        DelayedSingleton<CoreService>::GetInstance()->OnRemoteRequest(code, data, reply, option);
    }
    std::string version;
    EXPECT_GE(
        DelayedSingleton<CoreService>::GetInstance()->GetBasebandVersion(SLOT_ID, version), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreService_Stub_004
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_Stub_004, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t slotId = SLOT_ID;
    DelayedSingleton<CoreService>::GetInstance()->GetRadioState(slotId, nullptr);
    auto simManager = DelayedSingleton<CoreService>::GetInstance()->simManager_;
    auto networkSearchManager_ = DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_;
    auto telRilManager_ = DelayedSingleton<CoreService>::GetInstance()->telRilManager_;
    DelayedSingleton<CoreService>::GetInstance()->simManager_ = nullptr;
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = nullptr;
    DelayedSingleton<CoreService>::GetInstance()->telRilManager_ = nullptr;
    DelayedSingleton<CoreService>::GetInstance()->GetRadioState(slotId, nullptr);
    uint32_t maxCode = static_cast<uint32_t>(CoreServiceInterfaceCode::GET_SIM_IO_DONE);
    for (uint32_t code = 0; code <= maxCode; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(CoreServiceStub::GetDescriptor());
        data.WriteInt32(slotId);
        data.WriteRemoteObject(nullptr);
        DelayedSingleton<CoreService>::GetInstance()->OnRemoteRequest(code, data, reply, option);
    }
    DelayedSingleton<CoreService>::GetInstance()->simManager_ = simManager;
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = networkSearchManager_;
    DelayedSingleton<CoreService>::GetInstance()->telRilManager_ = telRilManager_;
    std::vector<std::u16string> args = { u"test", u"test1" };
    DelayedSingleton<CoreService>::GetInstance()->Dump(slotId, args);
    slotId--;
    DelayedSingleton<CoreService>::GetInstance()->Dump(slotId, args);
    DelayedSingleton<CoreService>::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    DelayedSingleton<CoreService>::GetInstance()->OnStart();
    DelayedSingleton<CoreService>::GetInstance()->OnStop();
    EXPECT_EQ(DelayedSingleton<CoreService>::GetInstance()->GetServiceRunningState(),
        static_cast<int32_t>(ServiceRunningState::STATE_NOT_START));
}

/**
 * @tc.number   Telephony_CoreService_DumpHelper_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_DumpHelper_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    if (telRilManager == nullptr) {
        return;
    }
    telRilManager->OnInit();
    DelayedSingleton<CoreService>::GetInstance()->telRilManager_ = telRilManager;
    int32_t slotCount = DelayedSingleton<CoreService>::GetInstance()->GetMaxSimCount();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    if (simManager == nullptr) {
        return;
    }
    simManager->OnInit(slotCount);
    DelayedSingleton<CoreService>::GetInstance()->simManager_ = simManager;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    if (networkSearchManager == nullptr) {
        return;
    }
    networkSearchManager->OnInit();
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = networkSearchManager;

    auto coreServiceDumpHelper = std::make_shared<CoreServiceDumpHelper>();
    std::vector<std::string> argsInStr;
    std::string result;
    coreServiceDumpHelper->ShowHelp(result);
    coreServiceDumpHelper->ShowCoreServiceTimeInfo(result);
    coreServiceDumpHelper->ShowCoreServiceInfo(result);
    coreServiceDumpHelper->ShowCoreServiceInfo(result);
    coreServiceDumpHelper->Dump(argsInStr, result);
    EXPECT_FALSE(result.empty());
    if (simManager->multiSimMonitor_ != nullptr) {
        simManager->multiSimMonitor_->remainCount_ = 0;
        sleep(SLEEP_TIME_SECONDS);
    }
}

/**
 * @tc.number   Telephony_CoreService_HiSysEvent_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_HiSysEvent_001, Function | MediumTest | Level1)
{
    auto coreServiceHiSysEvent = std::make_shared<CoreServiceHiSysEvent>();
    int32_t slotId = SLOT_ID;
    int32_t argInt = SLOT_ID;
    std::string argStr = "";
    coreServiceHiSysEvent->WriteSignalLevelBehaviorEvent(slotId, argInt);
    coreServiceHiSysEvent->WriteNetworkStateBehaviorEvent(slotId, argInt, argInt, argInt);
    coreServiceHiSysEvent->WriteRadioStateBehaviorEvent(slotId, argInt);
    coreServiceHiSysEvent->WriteDefaultDataSlotIdBehaviorEvent(slotId);
    coreServiceHiSysEvent->WriteSimStateBehaviorEvent(slotId, argInt);
    coreServiceHiSysEvent->WriteDialCallFaultEvent(slotId, argInt, argStr);
    coreServiceHiSysEvent->WriteAnswerCallFaultEvent(slotId, argInt, argStr);
    coreServiceHiSysEvent->WriteHangUpFaultEvent(slotId, argInt, argStr);
    coreServiceHiSysEvent->WriteSmsSendFaultEvent(
        slotId, SmsMmsMessageType::SMS_SHORT_MESSAGE, SmsMmsErrorCode::SMS_ERROR_NULL_POINTER, argStr);
    coreServiceHiSysEvent->WriteSmsReceiveFaultEvent(
        slotId, SmsMmsMessageType::SMS_SHORT_MESSAGE, SmsMmsErrorCode::SMS_ERROR_NULL_POINTER, argStr);
    coreServiceHiSysEvent->WriteDataActivateFaultEvent(
        slotId, argInt, CellularDataErrorCode::DATA_ERROR_PS_NOT_ATTACH, argStr);
    coreServiceHiSysEvent->WriteAirplaneModeChangeEvent(argInt);
    ASSERT_NE(argStr, "Event");
}

/**
 * @tc.number   Telephony_MultiSimController_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_MultiSimController_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    std::shared_ptr<RadioProtocolController> radioProtocolController = nullptr;
    multiSimController->PublishSetPrimaryEvent(true);
    multiSimController->EncryptIccId("");
    multiSimController->getDefaultMainSlotByIccId();
    multiSimController->CheckIfNeedSwitchMainSlotId();
    multiSimController->IsAllModemInitDone();
    multiSimController->ReCheckPrimary();
    int simId = 0;
    multiSimController->GetTargetDefaultSimId(INVALID_SLOTID, simId);
    multiSimController->GetTargetSimId(INVALID_SLOTID, simId);
    std::string iccId = "";
    multiSimController->GetTargetIccId(INVALID_SLOTID, iccId);

    EXPECT_FALSE(multiSimController->IsValidSlotId(INVALID_SLOTID));
    multiSimController->maxCount_ = 1;
    EXPECT_FALSE(multiSimController->InitPrimary());
    multiSimController->maxCount_ = 2;
    EXPECT_FALSE(multiSimController->InitPrimary());
    EXPECT_TRUE(multiSimController->IsAllCardsReady());
    EXPECT_FALSE(multiSimController->IsAllCardsLoaded());
}

/**
 * @tc.number   Telephony_OperatorName_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_OperatorName_002, Function | MediumTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto operatorName = std::make_shared<OperatorName>(
        subscriberInfo, networkSearchState, simManager, networkSearchManager, INVALID_SLOTID);
    std::string numeric = "";
    EXPECT_FALSE(operatorName->isCMCard(numeric));
    EXPECT_FALSE(operatorName->isCUCard(numeric));
    EXPECT_FALSE(operatorName->isCTCard(numeric));
    EXPECT_FALSE(operatorName->isCBCard(numeric));
    EXPECT_FALSE(operatorName->isCMDomestic(numeric));
    EXPECT_FALSE(operatorName->isCUDomestic(numeric));
    EXPECT_FALSE(operatorName->isCTDomestic(numeric));
    EXPECT_FALSE(operatorName->isCBDomestic(numeric));
}

/**
 * @tc.number   Telephony_OperatorNameCMCC_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_OperatorNameCMCC_001, Function | MediumTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto operatorName = std::make_shared<OperatorName>(
        subscriberInfo, networkSearchState, simManager, networkSearchManager, INVALID_SLOTID);
    std::string simPlmn = "46000";
    std::string netPlmn = "46031";
    EXPECT_TRUE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46001";
    netPlmn = "46031";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46003";
    netPlmn = "46031";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46015";
    netPlmn = "46031";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46018";
    netPlmn = "46031";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46000";
    netPlmn = "46050";
    EXPECT_TRUE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46001";
    netPlmn = "46050";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46003";
    netPlmn = "46050";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46015";
    netPlmn = "46050";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46018";
    netPlmn = "46050";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
}

/**
 * @tc.number   Telephony_OperatorNameCUCC_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_OperatorCUCC_001, Function | MediumTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto operatorName = std::make_shared<OperatorName>(
        subscriberInfo, networkSearchState, simManager, networkSearchManager, INVALID_SLOTID);
    std::string simPlmn = "46001";
    std::string netPlmn = "46022";
    EXPECT_TRUE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46000";
    netPlmn = "46022";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46003";
    netPlmn = "46022";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46015";
    netPlmn = "46022";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46018";
    netPlmn = "46022";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46001";
    netPlmn = "46061";
    EXPECT_TRUE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46000";
    netPlmn = "46061";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46003";
    netPlmn = "46061";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46015";
    netPlmn = "46061";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46018";
    netPlmn = "46061";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
}

/**
 * @tc.number   Telephony_OperatorNameCTCC_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_OperatorNameCTCC_001, Function | MediumTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto operatorName = std::make_shared<OperatorName>(
        subscriberInfo, networkSearchState, simManager, networkSearchManager, INVALID_SLOTID);
    std::string simPlmn = "46003";
    std::string netPlmn = "46021";
    EXPECT_TRUE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46000";
    netPlmn = "46021";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46001";
    netPlmn = "46021";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46015";
    netPlmn = "46021";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46018";
    netPlmn = "46021";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46003";
    netPlmn = "46060";
    EXPECT_TRUE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46000";
    netPlmn = "46060";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46001";
    netPlmn = "46060";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46015";
    netPlmn = "46060";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46018";
    netPlmn = "46060";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
}

/**
 * @tc.number   Telephony_OperatorNameCBCC_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_OperatorNameCBCC_001, Function | MediumTest | Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto operatorName = std::make_shared<OperatorName>(
        subscriberInfo, networkSearchState, simManager, networkSearchManager, INVALID_SLOTID);
    std::string simPlmn = "46015";
    std::string netPlmn = "46032";
    EXPECT_TRUE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46000";
    netPlmn = "46032";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46001";
    netPlmn = "46032";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46003";
    netPlmn = "46032";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46018";
    netPlmn = "46032";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46015";
    netPlmn = "46051";
    EXPECT_TRUE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46000";
    netPlmn = "46051";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46001";
    netPlmn = "46051";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46003";
    netPlmn = "46051";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
    simPlmn = "46018";
    netPlmn = "46051";
    EXPECT_FALSE(operatorName->isDomesticRoaming(simPlmn, netPlmn));
}

/**
 * @tc.number   Telephony_OperatorNameUtils_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_OperatorNameUtils_001, Function | MediumTest | Level1)
{
    OperatorNameUtils::GetInstance().Init();
    char *content = nullptr;
    const char *path = "etc/telephony/a.json";
    EXPECT_GT(OperatorNameUtils::GetInstance().LoaderJsonFile(content, path), TELEPHONY_ERR_SUCCESS);
    std::string numeric = "46000";
    EXPECT_NE(OperatorNameUtils::GetInstance().GetCustomName(numeric), "");
}

/**
 * @tc.number   Telephony_TelRilManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_TelRilManager_001, Function | MediumTest | Level1)
{
    OHOS::HDI::ServiceManager::V1_0::ServiceStatus status = { "test", 0, SERVIE_STATUS_STOP, "test" };
    auto telRilManager = std::make_shared<TelRilManager>();
    telRilManager->HandleRilInterfaceStatusCallback(status);
    status.serviceName = "ril_service";
    telRilManager->HandleRilInterfaceStatusCallback(status);
    status.deviceClass = DEVICE_CLASS_DEFAULT;
    telRilManager->rilInterface_ = nullptr;
    telRilManager->HandleRilInterfaceStatusCallback(status);
    EXPECT_TRUE(status.status == SERVIE_STATUS_STOP);
}

/**
 * @tc.number   Telephony_NitzUpdate_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_NitzUpdate_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto nitzUpdate = std::make_shared<NitzUpdate>(networkSearchManager, SLOT_ID);
    auto event = AppExecFwk::InnerEvent::Get(0);
    nitzUpdate->ProcessNitzUpdate(event);
    nitzUpdate->ProcessTimeZone();
    std::string countryCode = "";
    nitzUpdate->UpdateCountryCode(countryCode);
    countryCode = "cn";
    nitzUpdate->UpdateCountryCode(countryCode);
    nitzUpdate->AutoTimeChange();
    NitzUpdate::NetworkTime networkTime;
    std::string nitzStr = NITZ_STR;
    EXPECT_TRUE(nitzUpdate->NitzParse(nitzStr, networkTime));
    nitzUpdate->ProcessTime(networkTime);
    int64_t networkTimeSec = nitzUpdate->lastNetworkTime_;
    nitzUpdate->IsValidTime(networkTimeSec);
    nitzUpdate->SaveTime(networkTimeSec);
    nitzUpdate->IsAutoTime();
    nitzStr = NITZ_STR_INVALID;
    EXPECT_FALSE(nitzUpdate->NitzParse(nitzStr, networkTime));
}

/**
 * @tc.number   Telephony_IsAllowedInsertApn_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_IsAllowedInsertApn_001, Function | MediumTest | Level1)
{
    std::string jsonValue = "";
    auto coreServiceClient = std::make_shared<CoreServiceClient>();
    coreServiceClient->OnRemoteDied(nullptr);
    auto recipient = std::make_shared<CoreServiceClient::CoreServiceDeathRecipient>(CoreServiceClient::GetInstance());
    recipient->OnRemoteDied(nullptr);
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    if (TELEPHONY_EXT_WRAPPER.telephonyExtWrapperHandle_ != nullptr) {
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.isAllowedInsertApn_ != nullptr, true);
    }
    EXPECT_TRUE(coreServiceClient->IsAllowedInsertApn(jsonValue));
}

/**
 * @tc.number   Telephony_GetTargetOpkey_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_GetTargetOpkey_001, Function | MediumTest | Level1)
{
    std::u16string opkey;
    auto coreServiceClient = std::make_shared<CoreServiceClient>();
    coreServiceClient->OnRemoteDied(nullptr);
    auto recipient = std::make_shared<CoreServiceClient::CoreServiceDeathRecipient>(CoreServiceClient::GetInstance());
    recipient->OnRemoteDied(nullptr);
    int32_t result = coreServiceClient->GetTargetOpkey(SLOT_ID, opkey);
    EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_SignalInformationExt_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_SignalInformation_001, Function | MediumTest | Level1)
{
    std::shared_ptr<SignalInformation> gsm = std::make_shared<GsmSignalInformation>();
    std::shared_ptr<SignalInformation> cdma = std::make_shared<CdmaSignalInformation>();
    std::shared_ptr<SignalInformation> wcdma = std::make_shared<WcdmaSignalInformation>();
    std::shared_ptr<SignalInformation> lte = std::make_shared<LteSignalInformation>();
    std::shared_ptr<SignalInformation> nr = std::make_shared<NrSignalInformation>();
    std::shared_ptr<SignalInformation> tdScdma = std::make_shared<TdScdmaSignalInformation>();
    if (gsm == nullptr || cdma == nullptr || wcdma == nullptr || lte == nullptr || nr == nullptr ||
        tdScdma == nullptr) {
        return;
    }
    gsm->GetSignalLevel();
    gsm->SetSignalLevel(SIGNAL_STRENGTH_GOOD);
    EXPECT_EQ(gsm->GetSignalLevel(), SIGNAL_STRENGTH_GOOD);
    cdma->GetSignalLevel();
    cdma->SetSignalLevel(SIGNAL_STRENGTH_GOOD);
    EXPECT_EQ(cdma->GetSignalLevel(), SIGNAL_STRENGTH_GOOD);
    wcdma->GetSignalLevel();
    wcdma->SetSignalLevel(SIGNAL_STRENGTH_GOOD);
    EXPECT_EQ(wcdma->GetSignalLevel(), SIGNAL_STRENGTH_GOOD);
    lte->GetSignalLevel();
    lte->SetSignalLevel(SIGNAL_STRENGTH_GOOD);
    EXPECT_EQ(lte->GetSignalLevel(), SIGNAL_STRENGTH_GOOD);
    nr->GetSignalLevel();
    nr->SetSignalLevel(SIGNAL_STRENGTH_GOOD);
    EXPECT_EQ(nr->GetSignalLevel(), SIGNAL_STRENGTH_GOOD);
    tdScdma->GetSignalLevel();
    tdScdma->SetSignalLevel(SIGNAL_STRENGTH_GOOD);
    EXPECT_EQ(tdScdma->GetSignalLevel(), SIGNAL_STRENGTH_GOOD);
}

/**
 * @tc.number   Telephony_SignalInfo_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_SignalInfo_001, Function | MediumTest | Level1)
{
    auto signalInfo = std::make_shared<SignalInfo>();
    Rssi signalIntensity;
    signalIntensity.lte.rsrp = LTE_RSSI_GOOD;
    signalInfo->ProcessSignalIntensity(SLOT_ID, &signalIntensity);
    EXPECT_TRUE(signalInfo->ProcessLte(signalIntensity.lte));
}
} // namespace Telephony
} // namespace OHOS
