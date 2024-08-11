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

#include "gtest/gtest.h"
#include "device_state_observer.h"
#include "network_search_manager.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
constexpr int32_t INVALID_SLOTID = -1;
constexpr int32_t INVALID_YEAR = 1800;
constexpr int32_t TEST_YEAR = 2000;
constexpr int32_t TEST_MONTH = 2;
} // namespace

class NetworkSearchBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetworkSearchBranchTest::TearDownTestCase() {}

void NetworkSearchBranchTest::SetUp() {}

void NetworkSearchBranchTest::TearDown() {}

void NetworkSearchBranchTest::SetUpTestCase() {}

HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkType, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkType = std::make_unique<NetworkType>(networkSearchManager, INVALID_SLOTID);

    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    networkType->ProcessSetPreferredNetwork(event);

    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE);
    networkType->networkSearchManager_ = std::weak_ptr<NetworkSearchManager>();
    ASSERT_TRUE(networkType->networkSearchManager_.expired());
    networkType->ProcessSetPreferredNetwork(event);

    std::shared_ptr<PreferredNetworkTypeInfo> preferredTypeInfo = std::make_shared<PreferredNetworkTypeInfo>();
    std::shared_ptr<RadioResponseInfo> responseInfo = std::make_shared<RadioResponseInfo>();
    MessageParcel data;
    int64_t index = 0;
    EXPECT_FALSE(networkType->WriteGetPreferredNetworkInfo(preferredTypeInfo, responseInfo, data, index));
}

HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSelection, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSelection = std::make_unique<NetworkSelection>(networkSearchManager, INVALID_SLOTID);

    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    networkSelection->ProcessNetworkSearchResult(event);
    networkSelection->ProcessGetNetworkSelectionMode(event);
    networkSelection->ProcessSetNetworkSelectionMode(event);

    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_NETWORK_SEARCH_RESULT);
    networkSelection->networkSearchManager_ = std::weak_ptr<NetworkSearchManager>();
    ASSERT_TRUE(networkSelection->networkSearchManager_.expired());
    networkSelection->ProcessNetworkSearchResult(event);
    networkSelection->ProcessGetNetworkSelectionMode(event);
    networkSelection->ProcessSetNetworkSelectionMode(event);

    std::shared_ptr<AvailableNetworkList> availNetworkResult = std::make_shared<AvailableNetworkList>();
    MessageParcel data;
    int64_t index = 0;
    EXPECT_FALSE(networkSelection->AvailNetworkResult(availNetworkResult, data, index));

    std::shared_ptr<SetNetworkModeInfo> selectModeResult = std::make_shared<SetNetworkModeInfo>();
    EXPECT_FALSE(networkSelection->SelectModeResult(selectModeResult, data, index));

    networkSelection->networkSearchManager_ = networkSearchManager;
    std::shared_ptr<NetworkSearchManager> nsm = networkSelection->networkSearchManager_.lock();
    ASSERT_NE(nsm, nullptr);
    EXPECT_TRUE(networkSelection->AvailNetworkResult(nullptr, data, index));
    EXPECT_EQ(index, -1);

    index = 0;
    EXPECT_FALSE(networkSelection->SelectModeResult(nullptr, data, index));
    EXPECT_EQ(index, 0);

    EXPECT_TRUE(networkSelection->ResponseInfoOfResult(nullptr, data, index));
    EXPECT_TRUE(networkSelection->ResponseInfoOfGet(nullptr, data, index));

    MessageParcel data1;
    std::shared_ptr<RadioResponseInfo> responseInfo = std::make_shared<RadioResponseInfo>();
    responseInfo->error = ErrType::NONE;
    EXPECT_TRUE(networkSelection->ResponseInfoOfSet(responseInfo, data1, index));
    EXPECT_TRUE(data1.ReadBool());
    EXPECT_EQ(data1.ReadInt32(), TELEPHONY_SUCCESS);
    MessageParcel data2;
    responseInfo->error = ErrType::ERR_INVALID_PARAMETER;
    EXPECT_TRUE(networkSelection->ResponseInfoOfSet(responseInfo, data2, index));
    EXPECT_FALSE(data2.ReadBool());
    EXPECT_EQ(data2.ReadInt32(), static_cast<int32_t>(ErrType::ERR_INVALID_PARAMETER));
}

HWTEST_F(NetworkSearchBranchTest, Telephony_DeviceStateObserver, Function | MediumTest | Level1)
{
    auto deviceStateObserver = std::make_shared<DeviceStateObserver>();

    deviceStateObserver->subscriber_ = nullptr;
    deviceStateObserver->sharingEventCallback_ = nullptr;
    deviceStateObserver->StopEventSubscriber();

    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_POWER_SAVE_MODE_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_CHARGING);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISCHARGING);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    deviceStateObserver->subscriber_ = std::make_shared<DeviceStateEventSubscriber>(subscriberInfo);
    deviceStateObserver->subscriber_->deviceStateHandler_ = nullptr;
    CommonEventData data;
    deviceStateObserver->subscriber_->OnReceiveEvent(data);
    deviceStateObserver->subscriber_->ProcessWifiState(data);

    deviceStateObserver->subscriber_->InitEventMap();
    std::string event = "testEvent";
    EXPECT_EQ(deviceStateObserver->subscriber_->GetDeviceStateEventIntValue(event),
        DeviceStateEventIntValue::COMMON_EVENT_UNKNOWN);

    event = CommonEventSupport::COMMON_EVENT_CHARGING;
    EXPECT_EQ(deviceStateObserver->subscriber_->GetDeviceStateEventIntValue(event),
        DeviceStateEventIntValue::COMMON_EVENT_CHARGING);
}

HWTEST_F(NetworkSearchBranchTest, Telephony_NitzUpdate_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto nitzUpdate = std::make_unique<NitzUpdate>(networkSearchManager, INVALID_SLOTID);

    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    nitzUpdate->ProcessNitzUpdate(event);

    NitzUpdate::NetworkTime networkTime;
    std::string nitzStr = "2023/01/01";
    EXPECT_FALSE(nitzUpdate->NitzParse(nitzStr, networkTime));
    nitzStr = "2023/01,12:00:00";
    EXPECT_FALSE(nitzUpdate->NitzParse(nitzStr, networkTime));
    nitzStr = "202/01/01,12:00:00";
    EXPECT_FALSE(nitzUpdate->NitzParse(nitzStr, networkTime));
}

HWTEST_F(NetworkSearchBranchTest, Telephony_NitzUpdate_002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto nitzUpdate = std::make_unique<NitzUpdate>(networkSearchManager, INVALID_SLOTID);

    NitzUpdate::NetworkTime networkTime;
    std::string strTimeSubs = "-12:00:00-05-00-00";
    EXPECT_FALSE(nitzUpdate->NitzTimeParse(strTimeSubs, networkTime));
    strTimeSubs = "12:00:00";
    EXPECT_FALSE(nitzUpdate->NitzTimeParse(strTimeSubs, networkTime));
    strTimeSubs = "+12";
    EXPECT_FALSE(nitzUpdate->NitzTimeParse(strTimeSubs, networkTime));
    strTimeSubs = "+12:00:00:00";
    EXPECT_FALSE(nitzUpdate->NitzTimeParse(strTimeSubs, networkTime));
}

HWTEST_F(NetworkSearchBranchTest, Telephony_NitzUpdate_003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto nitzUpdate = std::make_unique<NitzUpdate>(networkSearchManager, INVALID_SLOTID);

    NitzUpdate::NetworkTime networkTime;
    networkTime.year = INVALID_YEAR;
    networkTime.month = 0;
    nitzUpdate->ProcessTime(networkTime);

    networkTime.month = TEST_MONTH;
    nitzUpdate->ProcessTime(networkTime);

    networkTime.year = TEST_YEAR;
    networkTime.month = 0;
    nitzUpdate->ProcessTime(networkTime);

    nitzUpdate->networkSearchManager_ = std::weak_ptr<NetworkSearchManager>();
    ASSERT_TRUE(nitzUpdate->networkSearchManager_.expired());
    nitzUpdate->ProcessTimeZone();
}

HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkRegister_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, INVALID_SLOTID);

    networkRegister->networkSearchManager_ = std::weak_ptr<NetworkSearchManager>();
    ASSERT_TRUE(networkRegister->networkSearchManager_.expired());
    auto psRegInfo = std::make_shared<PsRegStatusResultInfo>();
    auto csRegInfo = std::make_shared<CsRegStatusInfo>();
    networkRegister->ProcessPsRegister(psRegInfo);
    networkRegister->ProcessCsRegister(csRegInfo);
    networkRegister->NotifyNrFrequencyChanged();
    EXPECT_EQ(networkRegister->UpdateNsaState(static_cast<int32_t>(NrState::NR_STATE_NOT_SUPPORT)),
        static_cast<int32_t>(NrState::NR_STATE_NOT_SUPPORT));

    RegServiceState regStatus = RegServiceState::REG_STATE_IN_SERVICE;
    networkRegister->UpdateCellularCall(regStatus, 0);

    networkRegister->networkSearchManager_ = networkSearchManager;
    networkRegister->networkSearchState_ = nullptr;

    networkRegister->ProcessPsRegister(psRegInfo);
    networkRegister->ProcessCsRegister(csRegInfo);
    EXPECT_EQ(networkRegister->RevertLastTechnology(), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(networkRegister->NotifyStateChange(), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(networkRegister->UpdateNsaState(static_cast<int32_t>(NrState::NR_STATE_NOT_SUPPORT)),
        static_cast<int32_t>(NrState::NR_STATE_NOT_SUPPORT));

    auto netManager = networkRegister->networkSearchManager_.lock();
    ASSERT_NE(netManager, nullptr);
    netManager->cellularCallCallBack_ = nullptr;
    networkRegister->UpdateCellularCall(regStatus, 0);

    regStatus = RegServiceState::REG_STATE_EMERGENCY_ONLY;
    networkRegister->UpdateCellularCall(regStatus, 0);

    networkRegister->networkSearchState_ = networkSearchState;
    networkRegister->networkSearchState_->networkState_ = nullptr;
    EXPECT_EQ(networkRegister->RevertLastTechnology(), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkRegister->NotifyStateChange(), TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkRegister_002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, INVALID_SLOTID);

    networkRegister->networkSearchManager_ = std::weak_ptr<NetworkSearchManager>();
    ASSERT_TRUE(networkRegister->networkSearchManager_.expired());
    int32_t rrcState = 0;
    EXPECT_EQ(networkRegister->GetRrcConnectionState(rrcState), TELEPHONY_ERR_LOCAL_PTR_NULL);

    networkRegister->networkSearchState_ = nullptr;

    networkRegister->systemPropertiesConfig_ = "ConfigAD";
    int32_t status = 1;
    EXPECT_EQ(networkRegister->HandleRrcStateChanged(status), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkRegister->currentNrConfig_, "ConfigA");

    status = 0;
    EXPECT_EQ(networkRegister->HandleRrcStateChanged(status), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkRegister->currentNrConfig_, "ConfigD");

    networkRegister->nrState_ = NrState::NR_NSA_STATE_NO_DETECT;
    EXPECT_EQ(networkRegister->GetTechnologyByNrConfig(RadioTech::RADIO_TECHNOLOGY_LTE_CA),
        RadioTech::RADIO_TECHNOLOGY_NR);

    networkRegister->nrState_ = NrState::NR_NSA_STATE_CONNECTED_DETECT;
    EXPECT_EQ(networkRegister->GetTechnologyByNrConfig(RadioTech::RADIO_TECHNOLOGY_LTE_CA),
        RadioTech::RADIO_TECHNOLOGY_NR);

    networkRegister->nrState_ = NrState::NR_NSA_STATE_IDLE_DETECT;
    EXPECT_EQ(networkRegister->GetTechnologyByNrConfig(RadioTech::RADIO_TECHNOLOGY_LTE_CA),
        RadioTech::RADIO_TECHNOLOGY_NR);

    networkRegister->nrState_ = NrState::NR_NSA_STATE_DUAL_CONNECTED;
    EXPECT_EQ(networkRegister->GetTechnologyByNrConfig(RadioTech::RADIO_TECHNOLOGY_LTE_CA),
        RadioTech::RADIO_TECHNOLOGY_NR);

    networkRegister->nrState_ = NrState::NR_NSA_STATE_SA_ATTACHED;
    EXPECT_EQ(networkRegister->GetTechnologyByNrConfig(RadioTech::RADIO_TECHNOLOGY_LTE_CA),
        RadioTech::RADIO_TECHNOLOGY_LTE_CA);
}

HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchState_001, Function | MediumTest | Level1)
{
    NetworkSearchNotify networkSearchNotify;
    sptr<NetworkState> networkState = nullptr;
    networkSearchNotify.NotifyNetworkStateUpdated(0, networkState);

    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);

    networkSearchState->networkState_ = nullptr;
    EXPECT_FALSE(networkSearchState->IsEmergency());

    networkSearchState->imsRegStatus_ = false;
    networkSearchState->SetImsStatus(false);

    networkSearchState->imsRegStatus_ = true;
    networkSearchState->imsServiceStatus_ = std::make_unique<ImsServiceStatus>();
    ASSERT_NE(networkSearchState->imsServiceStatus_, nullptr);
    networkSearchState->imsServiceStatus_->supportImsVoice = true;
    EXPECT_EQ(networkSearchState->GetImsRegState(ImsServiceType::TYPE_VOICE), ImsRegState::IMS_REGISTERED);

    networkSearchState->imsServiceStatus_->supportImsVideo = true;
    EXPECT_EQ(networkSearchState->GetImsRegState(ImsServiceType::TYPE_VIDEO), ImsRegState::IMS_REGISTERED);

    networkSearchState->imsServiceStatus_->supportImsUt = true;
    EXPECT_EQ(networkSearchState->GetImsRegState(ImsServiceType::TYPE_UT), ImsRegState::IMS_REGISTERED);

    networkSearchState->imsServiceStatus_->supportImsSms = true;
    EXPECT_EQ(networkSearchState->GetImsRegState(ImsServiceType::TYPE_SMS), ImsRegState::IMS_REGISTERED);
}

HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchState_002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);

    networkSearchState->networkState_ = std::make_unique<NetworkState>();
    networkSearchState->networkState_->lastCfgTech_ = RadioTech::RADIO_TECHNOLOGY_LTE_CA;
    RadioTech tech = RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    EXPECT_EQ(networkSearchState->GetLastCfgTech(tech), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(tech, RadioTech::RADIO_TECHNOLOGY_LTE_CA);

    networkSearchState->networkState_->lastPsRadioTech_ = RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    EXPECT_EQ(networkSearchState->GetLastPsRadioTech(tech), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(tech, RadioTech::RADIO_TECHNOLOGY_UNKNOWN);

    networkSearchState->networkSearchManager_ = std::weak_ptr<NetworkSearchManager>();
    ASSERT_TRUE(networkSearchState->networkSearchManager_.expired());

    ImsRegInfo info;
    networkSearchState->NotifyPsRegStatusChange();
    networkSearchState->NotifyPsRoamingStatusChange();
    networkSearchState->NotifyPsRadioTechChange();
    networkSearchState->NotifyEmergencyChange();
    networkSearchState->NotifyNrStateChange();
    networkSearchState->NotifyImsStateChange(ImsServiceType::TYPE_VOICE, info);
    networkSearchState->CsRadioTechChange();
    EXPECT_TRUE(networkSearchState->networkSearchManager_.expired());
}
} // namespace Telephony
} // namespace OHOS