/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "network_search_manager.h"
#include "network_search_test_callback_stub.h"
#include "operator_name.h"
#include "operator_name_utils.h"
#include "runner_pool.h"
#include "security_token.h"
#include "sim_manager.h"
#include "telephony_log_wrapper.h"
#include "time_zone_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
constexpr int32_t SLOT_ID = 0;
const int32_t INVALID_SLOTID = 2;
constexpr int32_t NR_NSA_OPTION_ONLY = 1;
} // namespace

class DemoHandler : public AppExecFwk::EventHandler {
public:
    explicit DemoHandler(std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner) {}
    virtual ~DemoHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}
};

class CoreServiceBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void CoreServiceBranchTest::SetUpTestCase()
{
    RunnerPool::GetInstance().Init();
    DelayedSingleton<CoreService>::GetInstance()->Init();
}

void CoreServiceBranchTest::TearDownTestCase() {}

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
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    int32_t result = DelayedSingleton<CoreService>::GetInstance()->SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
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
    DelayedSingleton<CoreService>::GetInstance()->SetRadioState(SLOT_ID, false, callback);
    DelayedSingleton<CoreService>::GetInstance()->SetRadioState(SLOT_ID, false, callback);
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
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    DelayedSingleton<CoreService>::GetInstance()->GetPreferredNetwork(SLOT_ID, callback);
    DelayedSingleton<CoreService>::GetInstance()->SetPreferredNetwork(SLOT_ID, 1, callback);
    int32_t networkCapabilityType = 1;
    int32_t networkCapabilityState = 1;
    DelayedSingleton<CoreService>::GetInstance()->GetNetworkCapability(
        SLOT_ID, networkCapabilityType, networkCapabilityState);
    DelayedSingleton<CoreService>::GetInstance()->SetNetworkCapability(
        SLOT_ID, networkCapabilityType, networkCapabilityState);
    std::vector<sptr<CellInformation>> cellList;
    int32_t result = DelayedSingleton<CoreService>::GetInstance()->GetCellInfoList(SLOT_ID, cellList);
    DelayedSingleton<CoreService>::GetInstance()->SendUpdateCellLocationRequest(SLOT_ID);
    std::u16string u16Ret = u"";
    DelayedSingleton<CoreService>::GetInstance()->GetIsoCountryCodeForNetwork(SLOT_ID, u16Ret);
    DelayedSingleton<CoreService>::GetInstance()->GetImei(SLOT_ID, u16Ret);
    DelayedSingleton<CoreService>::GetInstance()->GetMeid(SLOT_ID, u16Ret);
    DelayedSingleton<CoreService>::GetInstance()->GetUniqueDeviceId(SLOT_ID, u16Ret);
    DelayedSingleton<CoreService>::GetInstance()->IsNrSupported(SLOT_ID);
    DelayedSingleton<CoreService>::GetInstance()->GetPreferredNetwork(SLOT_ID, callback);
    DelayedSingleton<CoreService>::GetInstance()->SetNrOptionMode(SLOT_ID, NR_NSA_OPTION_ONLY, callback);
    DelayedSingleton<CoreService>::GetInstance()->GetNetworkSearchInformation(SLOT_ID, callback);
    DelayedSingleton<CoreService>::GetInstance()->GetNrOptionMode(SLOT_ID, callback);
    DelayedSingleton<CoreService>::GetInstance()->GetNetworkSelectionMode(SLOT_ID, callback);
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
    std::u16string testU16Str = u"";
    DelayedSingleton<CoreService>::GetInstance()->GetSimSpn(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetSimIccId(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetSimOperatorNumeric(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetIMSI(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->IsSimActive(SLOT_ID);
    int32_t simId = 1;
    DelayedSingleton<CoreService>::GetInstance()->GetSlotId(simId);
    DelayedSingleton<CoreService>::GetInstance()->GetLocaleFromDefaultSim();
    DelayedSingleton<CoreService>::GetInstance()->GetSimGid1(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetSimGid2(SLOT_ID);
    int32_t lac = 1;
    bool longNameRequired = true;
    std::string plmn = "46001";
    DelayedSingleton<CoreService>::GetInstance()->GetSimEons(SLOT_ID, plmn, lac, longNameRequired);
    IccAccountInfo info;
    DelayedSingleton<CoreService>::GetInstance()->GetSimAccountInfo(SLOT_ID, info);
    DelayedSingleton<CoreService>::GetInstance()->SetDefaultVoiceSlotId(SLOT_ID);
    DelayedSingleton<CoreService>::GetInstance()->GetDefaultVoiceSlotId();
    DelayedSingleton<CoreService>::GetInstance()->GetDefaultVoiceSimId(simId);
    int32_t dsdsMode = 0;
    DelayedSingleton<CoreService>::GetInstance()->GetDsdsMode(dsdsMode);
    DelayedSingleton<CoreService>::GetInstance()->SetPrimarySlotId(SLOT_ID);
    DelayedSingleton<CoreService>::GetInstance()->GetPrimarySlotId(result);
    const std::u16string cardNumber = Str8ToStr16("SimNumber12345678901");
    DelayedSingleton<CoreService>::GetInstance()->SetShowNumber(SLOT_ID, cardNumber);
    DelayedSingleton<CoreService>::GetInstance()->GetShowNumber(SLOT_ID, testU16Str);
    const std::u16string cardName = Str8ToStr16("SimNameZhang");
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
    DelayedSingleton<CoreService>::GetInstance()->GetOpKeyExt(SLOT_ID, testU16Str);
    DelayedSingleton<CoreService>::GetInstance()->GetOpName(SLOT_ID, testU16Str);
    ImsRegInfo mImsRegInfo;
    DelayedSingleton<CoreService>::GetInstance()->GetImsRegStatus(SLOT_ID, ImsServiceType::TYPE_VOICE, mImsRegInfo);
    SimAuthenticationResponse response = { 0 };
    AuthType authType = AuthType::SIM_AUTH_EAP_SIM_TYPE;
    std::string authData = "1234";
    DelayedSingleton<CoreService>::GetInstance()->SimAuthentication(SLOT_ID, authType, authData, response);
    EXPECT_GE(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreService_Stub_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_CoreService_Stub_001, Function | MediumTest | Level1)
{
    uint32_t maxCode = static_cast<uint32_t>(CoreServiceInterfaceCode::GET_BASEBAND_VERSION);
    for (uint32_t code = 0; code < maxCode; code++) {
        if (code == static_cast<uint32_t>(CoreServiceInterfaceCode::HAS_OPERATOR_PRIVILEGES)) {
            continue;
        }
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(CoreServiceStub::GetDescriptor());
        DelayedSingleton<CoreService>::GetInstance()->OnRemoteRequest(code, data, reply, option);
    }
    std::string version;
    EXPECT_GE(
        DelayedSingleton<CoreService>::GetInstance()->GetBasebandVersion(SLOT_ID, version), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_TimeZoneManager_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_TimeZoneManager_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    DelayedSingleton<TimeZoneManager>::GetInstance()->Init(networkSearchManager);
    std::string countryCode = "cn";
    DelayedSingleton<TimeZoneManager>::GetInstance()->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    int32_t offset = 0;
    DelayedSingleton<TimeZoneManager>::GetInstance()->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    std::string timeZone = "Asia/Singapore";
    EXPECT_FALSE(DelayedSingleton<TimeZoneManager>::GetInstance()->UpdateLocationTimeZone(timeZone));
    DelayedSingleton<TimeZoneManager>::GetInstance()->SendUpdateLocationRequest();
    DelayedSingleton<TimeZoneManager>::GetInstance()->SendUpdateLocationCountryCodeRequest();
    DelayedSingleton<TimeZoneManager>::GetInstance()->IsRoaming();
    DelayedSingleton<TimeZoneManager>::GetInstance()->HasSimCard();
    DelayedSingleton<TimeZoneManager>::GetInstance()->GetCurrentLac();

    auto inner = std::make_shared<NetworkSearchManagerInner>();
    networkSearchManager->AddManagerInner(DEFAULT_SIM_SLOT_ID, inner);
    DelayedSingleton<TimeZoneManager>::GetInstance()->Init(networkSearchManager);
    inner->eventLoop_ = AppExecFwk::EventRunner::Create("test");
    DelayedSingleton<TimeZoneManager>::GetInstance()->Init(networkSearchManager);
    DelayedSingleton<TimeZoneManager>::GetInstance()->Init(networkSearchManager);
    DelayedSingleton<TimeZoneManager>::GetInstance()->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    DelayedSingleton<TimeZoneManager>::GetInstance()->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    DelayedSingleton<TimeZoneManager>::GetInstance()->SendUpdateLocationRequest();
    DelayedSingleton<TimeZoneManager>::GetInstance()->SendUpdateLocationCountryCodeRequest();
    DelayedSingleton<TimeZoneManager>::GetInstance()->IsRoaming();
    DelayedSingleton<TimeZoneManager>::GetInstance()->HasSimCard();
    DelayedSingleton<TimeZoneManager>::GetInstance()->GetCurrentLac();
    EXPECT_FALSE(DelayedSingleton<TimeZoneManager>::GetInstance()->UpdateLocationTimeZone(timeZone));
}

/**
 * @tc.number   Telephony_TimeZoneUpdater_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_TimeZoneUpdater_001, Function | MediumTest | Level1)
{
    auto eventLoop = AppExecFwk::EventRunner::Create("test");
    auto timeZoneUpdater = std::make_shared<TimeZoneUpdater>(eventLoop);
    timeZoneUpdater->Init();
    auto event = AppExecFwk::InnerEvent::Get(0);
    timeZoneUpdater->ProcessEvent(event);
    std::string countryCode = "cn";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    int32_t offset = 0;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    std::string timeZone = "Asia/Shanghai";
    timeZoneUpdater->UpdateLocationTimeZone(timeZone);
    timeZoneUpdater->SendUpdateLocationRequest();
    timeZoneUpdater->SendUpdateLocationCountryCodeRequest();
    timeZoneUpdater->RegisterSetting();
    Uri uri("datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=auto_timezone_test");
    std::string key = "settings.telephony.autotimezonetest";
    std::string value;
    timeZoneUpdater->QuerySetting(uri, key, value);
    timeZoneUpdater->StartEventSubscriber();
    timeZoneUpdater->RequestLocationUpdate();
    timeZoneUpdater->IsAutoTimeZone();
    timeZoneUpdater->IsAirplaneMode();
    timeZoneUpdater->IsScreenOn();
    timeZoneUpdater->IsLocationTimeZoneEnabled();
    timeZoneUpdater->UpdateTelephonyTimeZone();
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    timeZoneUpdater->NeedUpdateLocationTimeZone(timeZone);
    timeZoneUpdater->SaveTimeZone(timeZone);
    timeZoneUpdater->HandleAutoTimeZoneChange(event);
    timeZoneUpdater->HandleAirplaneModeChange(event);
    timeZoneUpdater->HandleLocationTimeOut(event);
    timeZoneUpdater->HandleScreenOnEvent(event);
    timeZoneUpdater->HandleCountryCodeChange(event);
    timeZoneUpdater->HandleNetworkConnected(event);
    timeZoneUpdater->HandleRequestLocationUpdate(event);
    timeZoneUpdater->HandleRequestLocationCountryCode(event);
    timeZoneUpdater->StopEventSubscriber();
    timeZoneUpdater->UnRegisterSetting();
    timeZoneUpdater->UnInit();
    countryCode = "CN";
    EXPECT_EQ(timeZoneUpdater->StringToLower(countryCode), "cn");
    EXPECT_TRUE(timeZoneUpdater->IsTimeZoneMatchCountryCode(timeZone));
    EXPECT_FALSE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
}

/**
 * @tc.number   Telephony_TimeZoneUpdater_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_TimeZoneUpdater_002, Function | MediumTest | Level1)
{
    auto eventLoop = AppExecFwk::EventRunner::Create("test");
    auto timeZoneUpdater = std::make_shared<TimeZoneUpdater>(eventLoop);
    auto event = AppExecFwk::InnerEvent::Get(0);
    timeZoneUpdater->ProcessEvent(event);
    std::string countryCode = "cn";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    int32_t offset = 0;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    std::string timeZone = "Asia/Shanghai";
    timeZoneUpdater->UpdateLocationTimeZone(timeZone);
    timeZoneUpdater->SendUpdateLocationRequest();
    timeZoneUpdater->SendUpdateLocationCountryCodeRequest();
    timeZoneUpdater->StartEventSubscriber();
    timeZoneUpdater->StartEventSubscriber();
    timeZoneUpdater->RequestLocationUpdate();
    timeZoneUpdater->IsLocationTimeZoneEnabled();
    timeZoneUpdater->HandleCountryCodeChange(event);
    timeZoneUpdater->HandleNetworkConnected(event);
    timeZoneUpdater->HandleRequestLocationUpdate(event);
    timeZoneUpdater->HandleRequestLocationCountryCode(event);
    timeZoneUpdater->HandleAutoTimeZoneChange(event);
    timeZoneUpdater->HandleAirplaneModeChange(event);
    timeZoneUpdater->HandleLocationTimeOut(event);
    timeZoneUpdater->HandleScreenOnEvent(event);
    timeZoneUpdater->StopEventSubscriber();
    timeZoneUpdater->StopEventSubscriber();
    timeZoneUpdater->UnRegisterSetting();
    EXPECT_FALSE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
}

/**
 * @tc.number   Telephony_TimeZoneLocationSuggester_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_TimeZoneLocationSuggester_001, Function | MediumTest | Level1)
{
    auto eventLoop = AppExecFwk::EventRunner::Create("test");
    auto suggester = std::make_shared<TimeZoneLocationSuggester>(eventLoop);
    suggester->Init();
    suggester->NitzUpdate();
#ifdef ABILITY_LOCATION_SUPPORT
    Parcel parcel;
    std::unique_ptr<Location::Location> location = Location::Location::Unmarshalling(parcel);
    suggester->LocationUpdate(location);
    suggester->GetLocationExpirationTime();
    suggester->IsLocationExpired();
#endif
    suggester->ClearLocation();
    EXPECT_FALSE(suggester->HasLocation());
}

/**
 * @tc.number   Telephony_TimeZoneLocationUpdate_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceBranchTest, Telephony_TimeZoneLocationUpdate_001, Function | MediumTest | Level1)
{
    auto eventLoop = AppExecFwk::EventRunner::Create("test");
    auto suggester = std::make_shared<TimeZoneLocationSuggester>(eventLoop);
    auto update = std::make_shared<TimeZoneLocationUpdate>(suggester);
    update->StartPassiveUpdate();
    update->StopPassiveUpdate();
    update->RequestUpdate();
    update->CancelUpdate();
#ifdef ABILITY_LOCATION_SUPPORT
    update->LocationSwitchChange();
    Parcel parcel;
    std::unique_ptr<Location::Location> location = Location::Location::Unmarshalling(parcel);
    update->LocationReport(location);
    update->RegisterLocationChange();
    update->UnregisterLocationChange();
    update->RegisterSwitchCallback();
    update->UnregisterSwitchCallback();
#endif
    update->IsLocationEnabled();
    update->GetIsoCountryCode();
    EXPECT_NE(update->GetIsoCountryCode(), "test");
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
} // namespace Telephony
} // namespace OHOS
