/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
 
#include "cell_info.h"
#include "cell_location.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "core_service_client.h"
#include "tel_ril_base_parcel.h"
#include "network_register.h"
#include "network_search_manager.h"
#include "network_search_state.h"
#include "operator_matching_rule.h"
#include "operator_name.h"
#include "radio_protocol_controller.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_data_helper.h"
#include "nativetoken_kit.h"
#include "telephony_ext_wrapper.h"
#include "network_utils.h"
#include "mock_sim_manager.h"
 
namespace OHOS {
namespace Telephony {
using namespace testing::ext;
 
namespace {
const int32_t SLOT_ID_0 = 0;
const int32_t INVALID_SLOTID = -1;
const int32_t CORE_NETWORK_MODE_NR = 31;
const CellInformation::CellType NONE = CellInformation::CellType::CELL_TYPE_NONE;
const CellInformation::CellType GSM = CellInformation::CellType::CELL_TYPE_GSM;
const CellInformation::CellType CDMA = CellInformation::CellType::CELL_TYPE_CDMA;
const CellInformation::CellType WCDMA = CellInformation::CellType::CELL_TYPE_WCDMA;
const CellInformation::CellType TDSCDMA = CellInformation::CellType::CELL_TYPE_TDSCDMA;
const CellInformation::CellType LTE = CellInformation::CellType::CELL_TYPE_LTE;
const CellInformation::CellType NR = CellInformation::CellType::CELL_TYPE_NR;
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
 
 
static void UpdateOperatorNameParamsTest(
    std::shared_ptr<OperatorName> &operatorName, sptr<NetworkState> &networkState, OperatorNameParams &params)
{
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_IN_SERVICE, networkState, params);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_NO_SERVICE, networkState, params);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_EMERGENCY_ONLY, networkState, params);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_SEARCH, networkState, params);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_UNKNOWN, networkState, params);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_POWER_OFF, networkState, params);
    params.spn = params.plmn;
    params.showSpn = params.showPlmn;
    operatorName->UpdateSpn(RegServiceState::REG_STATE_IN_SERVICE, networkState, params);
}
 
static void MockSimManagerFucTest(std::shared_ptr<MockSimManager> simManager)
{
    using ::testing::_;
    EXPECT_CALL(*simManager, GetSimOperatorNumeric(_, _))
        .WillOnce([=](int32_t arg1, std::u16string &outParam) { return -1; })
        .WillOnce([=](int32_t arg1, std::u16string &outParam) { return -1; })
        .WillOnce([=](int32_t arg1, std::u16string &outParam) {
            outParam = Str8ToStr16("46000");
            return 0;
        })
        .WillRepeatedly([=](int32_t arg1, std::u16string &outParam) {
            outParam = Str8ToStr16("46001");
            return 0;
        });
    EXPECT_CALL(*simManager, GetEhPlmns(_, _))
        .WillOnce([=](int32_t arg1, std::set<std::string> &outParam) {
            outParam = {"46000"};
            return 0;
        })
        .WillRepeatedly([=](int32_t arg1, std::set<std::string> &outParam) {
            outParam = {"46001"};
            return 0;
        });
    EXPECT_CALL(*simManager, GetSpdiPlmns(_, _))
        .WillOnce([=](int32_t arg1, std::set<std::string> &outParam) {
            outParam = {"46000"};
            return 0;
        })
        .WillRepeatedly([=](int32_t arg1, std::set<std::string> &outParam) {
            outParam = {"46001"};
            return 0;
        });
    EXPECT_CALL(*simManager, GetSimEons(_, _, _, _))
        .WillRepeatedly([=](int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) {
            return std::u16string(u"46000");
        });
    EXPECT_CALL(*simManager, GetSimSpn(_, _)).WillRepeatedly([=](int32_t arg1, std::u16string &outParam) {
        outParam = u"46001";
        return 0;
    });
}
 
/**
 * @tc.number   Telephony_CellInfo_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_CellInfo_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager_ = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto cellInfo = std::make_shared<CellInfo>(networkSearchManager_, INVALID_SLOTID);
    std::vector<sptr<CellInformation>> cellInfoList;
    auto event = AppExecFwk::InnerEvent::Get(0);
    sptr<CellInformation> gsmCellInformation = new GsmCellInformation();
    sptr<CellInformation> lteCellInformation = new LteCellInformation();
    sptr<CellInformation> wcdmaCellInformation = new WcdmaCellInformation();
    sptr<CellInformation> tdscdmaCellInformation = new TdscdmaCellInformation();
    sptr<CellInformation> nrCellInformation = new NrCellInformation();
    sptr<CellInformation> cdmaCellInformation = new CdmaCellInformation();
    sptr<CellInformation> cdmaCellInformationTwo;
    cdmaCellInformationTwo = cdmaCellInformation;
    Parcel parcel;
    gsmCellInformation->CellInformation::Unmarshalling(parcel);
    std::vector<sptr<CellInformation>> cellInfos;
    cellInfo->GetCellInfoList(cellInfoList);
    cellInfo->ProcessNeighboringCellInfo(event);
    cellInfo->ProcessCurrentCellInfo(event);
    event = nullptr;
    cellInfo->ProcessNeighboringCellInfo(event);
    cellInfo->ProcessCurrentCellInfo(event);
    cellInfo->UpdateCellLocation(0, 1, 1);
    cellInfo->UpdateCellLocation(1, 1, 1);
    cellInfo->GetCellLocation();
    cellInfo->NotifyCellInfoUpdated();
    cellInfo->ProcessCellLocation(gsmCellInformation, CellInformation::CellType::CELL_TYPE_NONE, 1, 0);
    cellInfo->UpdateSignalLevel(gsmCellInformation, CellInformation::CellType::CELL_TYPE_TDSCDMA);
    cellInfo->UpdateSignalLevel(gsmCellInformation, CellInformation::CellType::CELL_TYPE_NONE);
    cellInfo->AddCellInformation(gsmCellInformation, cellInfos);
    cellInfo->AddCellInformation(lteCellInformation, cellInfos);
    cellInfo->AddCellInformation(wcdmaCellInformation, cellInfos);
    cellInfo->AddCellInformation(tdscdmaCellInformation, cellInfos);
    cellInfo->AddCellInformation(nrCellInformation, cellInfos);
    cellInfo->AddCellInformation(cdmaCellInformation, cellInfos);
    EXPECT_TRUE(cellInfo->ProcessCellLocation(gsmCellInformation, CellInformation::CellType::CELL_TYPE_GSM, 1, 0));
    EXPECT_TRUE(cellInfo->ProcessCellLocation(lteCellInformation, CellInformation::CellType::CELL_TYPE_LTE, 1, 0));
    EXPECT_TRUE(cellInfo->ProcessCellLocation(wcdmaCellInformation, CellInformation::CellType::CELL_TYPE_WCDMA, 1, 0));
    EXPECT_TRUE(
        cellInfo->ProcessCellLocation(tdscdmaCellInformation, CellInformation::CellType::CELL_TYPE_TDSCDMA, 1, 0));
    EXPECT_TRUE(cellInfo->ProcessCellLocation(nrCellInformation, CellInformation::CellType::CELL_TYPE_NR, 1, 0));
    EXPECT_GE(cdmaCellInformation->GetSignalIntensity(), 0);
}
 
/**
 * @tc.number   Telephony_CellInfo_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_CellInfo_002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager_ = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto cellInfo = std::make_shared<CellInfo>(networkSearchManager_, INVALID_SLOTID);
    CellNearbyInfo cellNearbyInfo;
    cellNearbyInfo.ServiceCellParas.gsm.arfcn = 1;
    cellNearbyInfo.ServiceCellParas.gsm.cellId = 1;
    cellNearbyInfo.ServiceCellParas.gsm.bsic = 1;
    cellNearbyInfo.ServiceCellParas.gsm.lac = 0;
    cellNearbyInfo.ServiceCellParas.lte.pci = 1;
    cellNearbyInfo.ServiceCellParas.lte.arfcn = 1;
    cellNearbyInfo.ServiceCellParas.wcdma.arfcn = 1;
    cellNearbyInfo.ServiceCellParas.wcdma.psc = 1;
    cellNearbyInfo.ServiceCellParas.cdma.baseId = 1;
    cellNearbyInfo.ServiceCellParas.tdscdma.arfcn = 1;
    cellNearbyInfo.ServiceCellParas.nr.nci = 1;
    CurrentCellInformation current;
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellGsm(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellLte(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellWcdma(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellCdma(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellTdscdma(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellNr(&cellNearbyInfo));
    current.ratType = TelRilRatType::NETWORK_TYPE_GSM;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = TelRilRatType::NETWORK_TYPE_LTE;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = TelRilRatType::NETWORK_TYPE_WCDMA;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = TelRilRatType::NETWORK_TYPE_TDSCDMA;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = TelRilRatType::NETWORK_TYPE_CDMA;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = TelRilRatType::NETWORK_TYPE_NR;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = TelRilRatType::NETWORK_TYPE_UNKNOWN;
    EXPECT_FALSE(cellInfo->ProcessCurrentCell(&current));
}
 
/**
 * @tc.number   Telephony_CellInfo_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_CellInfo_003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager_ = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto cellInfo = std::make_shared<CellInfo>(networkSearchManager_, INVALID_SLOTID);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::UNKNOWN), NONE);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::GSM), GSM);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::WCDMA), WCDMA);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::LTE), LTE);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::CDMA), CDMA);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::TDSCDMA), TDSCDMA);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::NR), NR);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_GSM), GSM);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_WCDMA), WCDMA);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_HSPAP), WCDMA);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_HSPA), WCDMA);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_LTE), LTE);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_LTE_CA), LTE);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_TD_SCDMA), TDSCDMA);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_1XRTT), CDMA);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_EVDO), CDMA);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_EHRPD), CDMA);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_NR), NR);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_UNKNOWN), NONE);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(TelRilRatType::NETWORK_TYPE_GSM), GSM);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(TelRilRatType::NETWORK_TYPE_WCDMA), WCDMA);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(TelRilRatType::NETWORK_TYPE_LTE), LTE);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(TelRilRatType::NETWORK_TYPE_CDMA), CDMA);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(TelRilRatType::NETWORK_TYPE_TDSCDMA), TDSCDMA);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(TelRilRatType::NETWORK_TYPE_NR), NR);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(TelRilRatType::NETWORK_TYPE_UNKNOWN), NONE);
}
 
/**
 * @tc.number   Telephony_CellInfo_004
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_CellInfo_004, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager_ = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto cellInfo = std::make_shared<CellInfo>(networkSearchManager_, 1);
    int32_t SIGNAL_FOUR_BARS = 4;
    cellInfo->InitCellSignalBar(SIGNAL_FOUR_BARS);
    cellInfo->UpdateCellLocation(0, 10, 9);
    cellInfo->UpdateCellLocation(1, 11, 8);
    cellInfo->UpdateCellLocation(2, 12, 7);
    cellInfo->UpdateCellLocation(3, 13, 6);
    cellInfo->UpdateCellLocation(4, 14, 5);
    cellInfo->UpdateCellLocation(5, 15, 4);
    cellInfo->UpdateCellLocation(6, 16, 3);
    cellInfo->GetCurrentSignalLevelGsm(0);
    cellInfo->GetCurrentSignalLevelLte(0);
    cellInfo->GetCurrentSignalLevelCdma(0);
    cellInfo->GetCurrentSignalLevelTdscdma(0);
    cellInfo->GetCurrentSignalLevelNr(0);
    cellInfo->GetCellLocationExt(CellInformation::CellType::CELL_TYPE_NONE);
    cellInfo->GetCellLocationExt(CellInformation::CellType::CELL_TYPE_LTE);
    cellInfo->GetCellLocationExt(CellInformation::CellType::CELL_TYPE_NR);
    EXPECT_EQ(cellInfo->GetCurrentSignalLevelCdma(-40), SIGNAL_FOUR_BARS);
    EXPECT_EQ(cellInfo->GetCurrentSignalLevelWcdma(-40), SIGNAL_FOUR_BARS);
    EXPECT_EQ(cellInfo->GetCurrentSignalLevelLte(-40), SIGNAL_FOUR_BARS);
    EXPECT_EQ(cellInfo->GetCurrentSignalLevelGsm(-40), SIGNAL_FOUR_BARS);
    EXPECT_EQ(cellInfo->GetCurrentSignalLevelTdscdma(-40), SIGNAL_FOUR_BARS);
    EXPECT_EQ(cellInfo->GetCurrentSignalLevelNr(-40), SIGNAL_FOUR_BARS);
}
 
/**
 * @tc.number   Telephony_CellInfo_005
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_CellInfo_005, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto cellInfo = std::make_shared<CellInfo>(networkSearchManager, INVALID_SLOTID);
    auto event = AppExecFwk::InnerEvent::Get(0);
    cellInfo->ProcessNeighboringCellInfo(event);
    cellInfo->ProcessCurrentCellInfo(event);
    event = nullptr;
    cellInfo->ProcessNeighboringCellInfo(event);
    cellInfo->ProcessCurrentCellInfo(event);
    auto cellListNearbyInfo = std::make_shared<CellListNearbyInfo>();
    auto cellListCurrentInfo = std::make_shared<CellListCurrentInformation>();
    auto eventNearby = AppExecFwk::InnerEvent::Get(0, cellListNearbyInfo);
    auto eventCurrent = AppExecFwk::InnerEvent::Get(0, cellListCurrentInfo);
    cellInfo->ProcessNeighboringCellInfo(eventNearby);
    cellInfo->ProcessCurrentCellInfo(eventCurrent);
    CellNearbyInfo cellInfoNearby;
    cellInfoNearby.ratType = 1;
    cellListNearbyInfo->itemNum = 1;
    cellListNearbyInfo->cellNearbyInfo.push_back(cellInfoNearby);
    CurrentCellInformation cellInfoCurrent;
    cellInfoCurrent.ratType = 1;
    cellListCurrentInfo->itemNum = 1;
    cellListCurrentInfo->cellCurrentInfo.push_back(cellInfoCurrent);
    cellInfo->ProcessNeighboringCellInfo(eventNearby);
    cellInfo->ProcessCurrentCellInfo(eventCurrent);
 
    cellInfo = std::make_shared<CellInfo>(networkSearchManager, SLOT_ID_0);
    cellInfo->UpdateCellLocation(1, 1, 1);
    sptr<CellInformation> gsmCellInfo = new GsmCellInformation;
    EXPECT_TRUE(cellInfo->ProcessCellLocation(gsmCellInfo, GSM, 1, 1));
}
 
/**
 * @tc.number   Telephony_CellInfo_006
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_CellInfo_006, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto cellInfo = std::make_shared<CellInfo>(networkSearchManager, INVALID_SLOTID);
    sptr<CellInformation> nwCellInfo = new GsmCellInformation;
    EXPECT_FALSE(cellInfo->ProcessCellLocation(nwCellInfo, GSM, 0, 0));
    nwCellInfo = new LteCellInformation;
    EXPECT_FALSE(cellInfo->ProcessCellLocation(nwCellInfo, LTE, 0, 0));
    nwCellInfo = new WcdmaCellInformation;
    EXPECT_FALSE(cellInfo->ProcessCellLocation(nwCellInfo, WCDMA, 0, 0));
    nwCellInfo = new TdscdmaCellInformation;
    EXPECT_FALSE(cellInfo->ProcessCellLocation(nwCellInfo, TDSCDMA, 0, 0));
    nwCellInfo = new NrCellInformation;
    EXPECT_FALSE(cellInfo->ProcessCellLocation(nwCellInfo, NR, 0, 0));
}
 
/**
 * @tc.number   Telephony_NetworkType_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkType_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkType = std::make_unique<NetworkType>(networkSearchManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE);
    networkType->ProcessGetPreferredNetwork(event);
    event = nullptr;
    networkType->ProcessGetPreferredNetwork(event);
    EXPECT_TRUE(networkType != nullptr);
}
 
/**
 * @tc.number   Telephony_OperatorName_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_OperatorName_001, Function | MediumTest | Level1)
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
    auto operatorInfo = std::make_shared<OperatorInfoResult>();
    std::string numeric = "qwe";
    std::vector<std::string> pnnCust;
    sptr<NetworkState> networkState;
    system::SetParameter("persist.radio.cfg.display_rule_use_roaming_from_network_state", "true");
    operatorName->NotifyGsmSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState, "");
    operatorName->NotifyCdmaSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState, "");
    operatorName->UpdateOperatorConfig();
    operatorName->UpdatePnnCust(pnnCust);
    operatorName->UpdateOplCust(pnnCust);
    EXPECT_EQ(operatorName->GetPlmn(networkState, true), "");
    networkState = new NetworkState;
    OperatorNameParams params = {true, "", false, "", 1};
    UpdateOperatorNameParamsTest(operatorName, networkState, params);
    operatorName->NotifyGsmSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState, "");
    operatorName->NotifyCdmaSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState, "");
    operatorName->GsmOperatorInfo(operatorInfo);
    operatorName->HandleOperatorInfo(operatorInfo);
    operatorName->TrySetLongOperatorNameWithTranslation();
    operatorName->NotifySpnChanged();
    operatorName->CdmaOperatorInfo(operatorInfo);
    operatorInfo = nullptr;
    operatorName->GsmOperatorInfo(operatorInfo);
    operatorName->CdmaOperatorInfo(operatorInfo);
    EXPECT_EQ(operatorName->GetCurrentLac(), 0);
    EXPECT_TRUE(operatorName->GetNetworkStatus() == nullptr);
 
    std::string plmn = params.spn;
    EXPECT_EQ(operatorName->GetCustomName(plmn), "");
    EXPECT_EQ(operatorName->GetCustomName(numeric), "");
    EXPECT_EQ(operatorName->GetCustSpnRule(true), 0);
    operatorName->displayConditionCust_ = 1;
    EXPECT_NE(operatorName->GetCustSpnRule(true), 0);
    operatorName->simManager_ = nullptr;
    EXPECT_EQ(operatorName->GetEons(plmn, 1, true), "");
}
 
/**
 * @tc.number   Telephony_OperatorName_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_OperatorName_002, Function | MediumTest | Level1)
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
    operatorName->enableCust_ = true;
    std::string plmn = "46000";
    std::vector<std::string> pnnCust;
    pnnCust.push_back("CMCC,ChinaMobile");
    std::vector<std::string> oplCust;
    oplCust.push_back("0,0,0,46000");
    sptr<NetworkState> networkState;
    operatorName->csSpnFormat_ = "*";
    operatorName->UpdatePnnCust(pnnCust);
    operatorName->UpdateOplCust(oplCust);
    EXPECT_EQ(operatorName->GetCustEons(plmn, 1, false, false), "");
 
    OperatorNameParams params = {false, "", true, plmn, 1};
    operatorName->UpdateSpn(RegServiceState::REG_STATE_IN_SERVICE, networkState, params);
    operatorName->NotifyCdmaSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState, "ChinaMobile");
    std::shared_ptr<OperatorInfoResult> operatorResult = std::make_shared<OperatorInfoResult>();
    operatorResult->flag = NetworkSearchManagerInner::SERIAL_NUMBER_EXEMPT;
    operatorName->HandleOperatorInfo(operatorResult);
    operatorName->TrySetLongOperatorNameWithTranslation();
 
    if (!networkSearchState->Init() || operatorName->GetNetworkStatus() == nullptr) {
        return;
    }
    params = {false, "plmn", false, "spn", 1};
    operatorName->SetOperatorNameByParams(params);
    EXPECT_EQ(operatorName->GetNetworkStatus()->GetLongOperatorName(), "");
    params = {true, "plmn", false, "spn", 1};
    operatorName->SetOperatorNameByParams(params);
    EXPECT_EQ(operatorName->GetNetworkStatus()->GetLongOperatorName(), params.plmn);
    params = {false, "plmn", true, "spn", 1};
    operatorName->SetOperatorNameByParams(params);
    EXPECT_EQ(operatorName->GetNetworkStatus()->GetLongOperatorName(), params.spn);
}
 
 
/**
 * @tc.number   Telephony_OperatorName_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_OperatorName_003, Function | MediumTest | Level1)
{
    auto simManager = std::make_shared<MockSimManager>();
    MockSimManagerFucTest(simManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager1 = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager1);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto operatorName = std::make_shared<OperatorName>(
        subscriberInfo, networkSearchState, simManager, networkSearchManager, INVALID_SLOTID);
    operatorName->enableCust_ = true;
    std::string plmn = "46000";
    std::vector<std::string> pnnCust;
    pnnCust.push_back("CMCC,ChinaPhone");
    std::vector<std::string> oplCust;
    oplCust.push_back("0,0,0,46000");
    sptr<NetworkState> networkState = new NetworkState;
    operatorName->csSpnFormat_ = "*";
    operatorName->UpdatePnnCust(pnnCust);
    operatorName->UpdateOplCust(oplCust);
    EXPECT_EQ(operatorName->GetCustEons(plmn, 1, false, false), "");
    OperatorNameParams params = {false, "", true, plmn, 1};
    operatorName->UpdateSpn(RegServiceState::REG_STATE_IN_SERVICE, networkState, params);
    networkState->SetOperatorInfo("ChinaPhone", "ChinaPhone", "46000", DomainType::DOMAIN_TYPE_PS);
    system::SetParameter("persist.radio.cfg.display_rule_use_roaming_from_network_state", "false");
    EXPECT_EQ(operatorName->GetSpnRule(networkState), 0);
    EXPECT_EQ(operatorName->GetSpnRule(networkState), 2);
    EXPECT_EQ(operatorName->GetSpnRule(networkState), 2);
    EXPECT_EQ(operatorName->GetSpnRule(networkState), 2);
    EXPECT_EQ(operatorName->GetSpnRule(networkState), 0);
}
 
/**
 * @tc.number   Telephony_NetworkSearchState_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchState_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    const std::string longName = "";
    const std::string shortName = "";
    const std::string numeric = "";
    ImsServiceStatus imsServiceStatus;
    ImsRegInfo info;
    EXPECT_TRUE(networkSearchState->GetNetworkStatus() == nullptr);
    networkSearchState->NotifyStateChange();
    networkSearchState->CsRadioTechChange();
    networkSearchState->NotifyPsRegStatusChange();
    networkSearchState->NotifyPsRoamingStatusChange();
    networkSearchState->NotifyPsRadioTechChange();
    networkSearchState->NotifyEmergencyChange();
    networkSearchState->NotifyNrStateChange();
    networkSearchState->NotifyImsStateChange(ImsServiceType::TYPE_VOICE, info);
    networkSearchState->Init();
    networkSearchState->SetImsServiceStatus(imsServiceStatus);
    networkSearchState->NotifyStateChange();
    networkSearchState->CsRadioTechChange();
    imsServiceStatus.supportImsUt = true;
    networkSearchState->SetImsServiceStatus(imsServiceStatus);
    networkSearchState->SetOperatorInfo(longName, shortName, numeric, DomainType::DOMAIN_TYPE_PS);
    networkSearchState->SetEmergency(true);
    networkSearchState->IsEmergency();
    networkSearchState->SetNetworkType(RadioTech::RADIO_TECHNOLOGY_GSM, DomainType::DOMAIN_TYPE_PS);
    networkSearchState->SetNetworkState(RegServiceState::REG_STATE_IN_SERVICE, DomainType::DOMAIN_TYPE_PS);
    networkSearchState->SetNetworkStateToRoaming(RoamingType::ROAMING_STATE_UNSPEC, DomainType::DOMAIN_TYPE_PS);
    networkSearchState->SetInitial();
    networkSearchState->SetNrState(NrState::NR_STATE_NOT_SUPPORT);
    networkSearchState->SetCfgTech(RadioTech::RADIO_TECHNOLOGY_EVDO);
    networkSearchState->SetImsStatus(true);
    networkSearchState->SetImsStatus(false);
    networkSearchState->SetLongOperatorName(longName, DomainType::DOMAIN_TYPE_PS);
    networkSearchState->NotifyPsRegStatusChange();
    networkSearchState->NotifyPsRoamingStatusChange();
    networkSearchState->NotifyPsRadioTechChange();
    networkSearchState->NotifyEmergencyChange();
    networkSearchState->NotifyNrStateChange();
    EXPECT_EQ(networkSearchState->GetImsStatus(ImsServiceType::TYPE_VOICE, info), 0);
    EXPECT_EQ(networkSearchState->GetImsStatus(ImsServiceType::TYPE_VIDEO, info), 0);
    EXPECT_EQ(networkSearchState->GetImsStatus(ImsServiceType::TYPE_UT, info), 0);
    EXPECT_EQ(networkSearchState->GetImsStatus(ImsServiceType::TYPE_SMS, info), 0);
}
 
/**
 * @tc.number   Telephony_NetworkSearchManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    networkSearchManager->eventSender_ = std::make_unique<EventSender>(telRilManager, networkSearchManager);
    sptr<NetworkInformation> networkInfo = nullptr;
    ImsRegInfo info;
    std::u16string testStr = u"";
    sptr<INetworkSearchCallback> networkSearchCallback = nullptr;
    networkSearchManager->SetRadioState(INVALID_SLOTID, true, 1);
    networkSearchManager->SetRadioState(INVALID_SLOTID, true, 1, networkSearchCallback);
    EXPECT_EQ(networkSearchManager->GetRadioState(INVALID_SLOTID), ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE);
    EXPECT_NE(networkSearchManager->GetNetworkSearchInformation(INVALID_SLOTID, networkSearchCallback),
        TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(networkSearchManager->SetNetworkSelectionMode(INVALID_SLOTID, 1, networkInfo, true));
    int32_t slotId = 0;
    EXPECT_FALSE(networkSearchManager->SetNetworkSelectionMode(slotId, 1, networkInfo, true));
    EXPECT_NE(
        networkSearchManager->SetNetworkSelectionMode(INVALID_SLOTID, 1, networkInfo, true, networkSearchCallback),
        TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetPreferredNetwork(INVALID_SLOTID, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetPreferredNetwork(slotId, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    int32_t networkMode = 0;
    EXPECT_NE(networkSearchManager->SetCachePreferredNetworkValue(INVALID_SLOTID, networkMode), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetCachePreferredNetworkValue(INVALID_SLOTID, networkMode), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(
        networkSearchManager->SetPreferredNetwork(INVALID_SLOTID, 1, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    std::u16string result = u"";
    EXPECT_NE(networkSearchManager->GetIsoCountryCodeForNetwork(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    networkSearchManager->UpdateDeviceId(INVALID_SLOTID);
    EXPECT_NE(networkSearchManager->GetImei(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    EXPECT_NE(networkSearchManager->GetImeiSv(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    EXPECT_EQ(networkSearchManager->GetImsRegStatus(INVALID_SLOTID, ImsServiceType::TYPE_SMS, info),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(networkSearchManager->GetUniqueDeviceId(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    EXPECT_NE(networkSearchManager->GetMeid(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    EXPECT_EQ(networkSearchManager->GetResidentNetworkNumeric(INVALID_SLOTID), std::string());
    networkSearchManager->SetResidentNetworkNumeric(0, "");
}
 
/**
 * @tc.number   Telephony_NetworkSearchManager_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchManager_002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->networkSearchState_ = networkSearchState;
    inner->observerHandler_ = std::make_unique<ObserverHandler>();
    inner->networkSearchHandler_ = networkSearchHandler;
    int32_t tokenId = 123456789;
    std::u16string imei = u"";
    std::u16string imeiSv = u"";
    sptr<ImsRegInfoCallback> callback = nullptr;
    networkSearchManager->SetLocateUpdate(INVALID_SLOTID);
    networkSearchManager->GetVoiceTech(INVALID_SLOTID);
    networkSearchManager->AddManagerInner(INVALID_SLOTID, inner);
    networkSearchManager->DcPhysicalLinkActiveUpdate(INVALID_SLOTID, true);
    networkSearchManager->NotifyPsRoamingOpenChanged(INVALID_SLOTID);
    networkSearchManager->NotifyPsRoamingCloseChanged(INVALID_SLOTID);
    networkSearchManager->NotifyPsConnectionAttachedChanged(INVALID_SLOTID);
    networkSearchManager->NotifyPsConnectionDetachedChanged(INVALID_SLOTID);
    networkSearchManager->NotifyPsRatChanged(INVALID_SLOTID);
    networkSearchManager->NotifyEmergencyOpenChanged(INVALID_SLOTID);
    networkSearchManager->NotifyEmergencyCloseChanged(INVALID_SLOTID);
    networkSearchManager->NotifyNrStateChanged(INVALID_SLOTID);
    networkSearchManager->NotifyNrFrequencyChanged(INVALID_SLOTID);
    networkSearchManager->TriggerSimRefresh(INVALID_SLOTID);
    networkSearchManager->TriggerTimezoneRefresh(INVALID_SLOTID);
    networkSearchManager->SetRadioStateValue(INVALID_SLOTID, ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE);
    networkSearchManager->SetNetworkSelectionValue(INVALID_SLOTID, SelectionMode::MODE_TYPE_UNKNOWN);
    networkSearchManager->SetImei(INVALID_SLOTID, imei);
    networkSearchManager->SetImeiSv(INVALID_SLOTID, imeiSv);
    networkSearchManager->UpdateCellLocation(INVALID_SLOTID, 1, 1, 1);
    networkSearchManager->SetMeid(INVALID_SLOTID, imei);
    networkSearchManager->SetFrequencyType(INVALID_SLOTID, FrequencyType::FREQ_TYPE_MMWAVE);
    networkSearchManager->SetRadioFirstPowerOn(INVALID_SLOTID, true);
    networkSearchManager->SetLocalAirplaneMode(INVALID_SLOTID, true);
    bool state = false;
    networkSearchManager->GetLocalAirplaneMode(INVALID_SLOTID, state);
    EXPECT_TRUE(networkSearchManager->GetNetworkSearchInformationValue(INVALID_SLOTID) == nullptr);
    EXPECT_TRUE(networkSearchManager->GetNetworkSearchState(INVALID_SLOTID) != nullptr);
    EXPECT_TRUE(networkSearchManager->IsRadioFirstPowerOn(INVALID_SLOTID));
    EXPECT_EQ(networkSearchManager->RegisterImsRegInfoCallback(
                  INVALID_SLOTID, ImsServiceType::TYPE_SMS, tokenId, callback),
        TELEPHONY_ERR_ARGUMENT_NULL);
    EXPECT_EQ(networkSearchManager->UnregisterImsRegInfoCallback(INVALID_SLOTID, ImsServiceType::TYPE_SMS, tokenId),
        TELEPHONY_SUCCESS);
}
 
/**
 * @tc.number   Telephony_NetworkSearchManager_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchManager_003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    sptr<INetworkSearchCallback> networkSearchCallback = nullptr;
    networkSearchManager->TriggerSimRefresh(INVALID_SLOTID);
    networkSearchManager->RegisterCoreNotify(INVALID_SLOTID, networkSearchHandler, 1);
    networkSearchManager->UnRegisterCoreNotify(INVALID_SLOTID, networkSearchHandler, 1);
    int32_t radioTech;
    std::u16string testStr = u"";
    std::u16string result = u"";
    EXPECT_NE(networkSearchManager->GetPsRadioTech(INVALID_SLOTID, radioTech), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetCsRadioTech(INVALID_SLOTID, radioTech), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchManager->GetOperatorNumeric(INVALID_SLOTID), testStr);
    EXPECT_NE(networkSearchManager->GetOperatorName(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    std::vector<sptr<Telephony::SignalInformation>> signals;
    networkSearchManager->GetSignalInfoList(INVALID_SLOTID, signals);
    EXPECT_TRUE(signals.empty());
    std::vector<sptr<CellInformation>> cellInfo;
    networkSearchManager->GetCellInfoList(INVALID_SLOTID, cellInfo);
    EXPECT_TRUE(cellInfo.empty());
 
    EXPECT_NE(networkSearchManager->SendUpdateCellLocationRequest(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(networkSearchManager->GetCellLocation(INVALID_SLOTID) == nullptr);
    bool airplaneMode = false;
    EXPECT_NE(networkSearchManager->GetAirplaneMode(airplaneMode), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->UpdateRadioOn(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->UpdateNrOptionMode(INVALID_SLOTID, NrMode::NR_MODE_UNKNOWN), TELEPHONY_SUCCESS);
    int32_t status = 0;
    EXPECT_NE(networkSearchManager->UpdateRrcConnectionState(INVALID_SLOTID, status), TELEPHONY_SUCCESS);
    EXPECT_EQ(status, 0);
    NrMode mode = NrMode::NR_MODE_UNKNOWN;
    EXPECT_NE(networkSearchManager->GetNrOptionMode(INVALID_SLOTID, mode), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetNrOptionMode(INVALID_SLOTID, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mode, NrMode::NR_MODE_UNKNOWN);
    EXPECT_NE(networkSearchManager->SetNrOptionMode(INVALID_SLOTID, 1), TELEPHONY_SUCCESS);
    EXPECT_NE(networkSearchManager->SetNrOptionMode(INVALID_SLOTID, 1, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
}
 
/**
 * @tc.number   Telephony_NetworkSearchManager_004
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchManager_004, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->networkSearchState_ = networkSearchState;
    inner->observerHandler_ = std::make_unique<ObserverHandler>();
    inner->networkSearchHandler_ = networkSearchHandler;
    std::string version = "";
    EXPECT_NE(networkSearchManager->GetBasebandVersion(INVALID_SLOTID, version), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(version, "");
    EXPECT_FALSE(networkSearchManager->IsNrSupported(INVALID_SLOTID));
    sptr<NetworkState> networkState = nullptr;
    EXPECT_NE(networkSearchManager->GetNetworkStatus(INVALID_SLOTID, networkState), TELEPHONY_ERR_SUCCESS);
    EXPECT_TRUE(networkState == nullptr);
    NrMode mode = NrMode::NR_MODE_UNKNOWN;
    EXPECT_NE(networkSearchManager->GetNrOptionMode(INVALID_SLOTID, mode), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mode, NrMode::NR_MODE_UNKNOWN);
    EXPECT_NE(networkSearchManager->NotifyCallStatusToNetworkSearch(INVALID_SLOTID, 0), TELEPHONY_ERR_SUCCESS);
    networkSearchManager->AddManagerInner(INVALID_SLOTID, inner);
    EXPECT_EQ(networkSearchManager->GetFrequencyType(INVALID_SLOTID), FrequencyType::FREQ_TYPE_UNKNOWN);
    EXPECT_EQ(networkSearchManager->GetNrState(INVALID_SLOTID), NrState::NR_STATE_NOT_SUPPORT);
    EXPECT_EQ(networkSearchManager->GetPsRegState(INVALID_SLOTID), TELEPHONY_ERROR);
    EXPECT_EQ(networkSearchManager->GetCsRegState(INVALID_SLOTID), TELEPHONY_ERROR);
    EXPECT_EQ(networkSearchManager->GetPsRoamingState(INVALID_SLOTID), TELEPHONY_ERROR);
    std::int32_t networkAbilityType = 0;
    std::int32_t networkAbilityState = 0;
    EXPECT_EQ(networkSearchManager->GetNetworkCapability(INVALID_SLOTID, networkAbilityType, networkAbilityState),
        TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->SetNetworkCapability(INVALID_SLOTID, networkAbilityType, networkAbilityState),
        TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->FactoryReset(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
}
 
/**
 * @tc.number   Telephony_NetworkSearchManager_005
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchManager_005, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    networkSearchManager->OnInit();
    sptr<INetworkSearchCallback> networkSearchCallback = nullptr;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    int32_t status = 0;
    std::string version = "";
    std::u16string result = u"";
    std::vector<NetworkInformation> operatorInfo;
    networkSearchManager->GetRadioState(INVALID_SLOTID, networkSearchCallback);
    networkSearchManager->SetNetworkSearchResultValue(INVALID_SLOTID, 0, operatorInfo);
    EXPECT_NE(
        networkSearchManager->GetNetworkSelectionMode(INVALID_SLOTID, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    int32_t slotId = 0;
    EXPECT_NE(networkSearchManager->SetPreferredNetwork(slotId, 1, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetPreferredNetwork(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetPreferredNetwork(slotId), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetUniqueDeviceId(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->HandleRrcStateChanged(INVALID_SLOTID, status), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->HandleRrcStateChanged(slotId, status), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->RevertLastTechnology(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->RevertLastTechnology(slotId), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetRrcConnectionState(INVALID_SLOTID, status), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->UpdateRrcConnectionState(slotId, status), TELEPHONY_ERR_SUCCESS);
    NrMode mode = NrMode::NR_MODE_UNKNOWN;
    EXPECT_NE(networkSearchManager->GetNrOptionMode(slotId, mode), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->SetNrOptionMode(slotId, 1), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->SetNrOptionMode(slotId, 1, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchManager->GetNrState(slotId), NrState::NR_STATE_NOT_SUPPORT);
    EXPECT_NE(networkSearchManager->NotifyCallStatusToNetworkSearch(slotId, 0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->HandleNotifyStateChangeWithDelay(INVALID_SLOTID, false), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(networkSearchManager->IsNeedDelayNotify(INVALID_SLOTID));
    EXPECT_NE(networkSearchManager->ProcessNotifyStateChangeEvent(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(networkSearchManager->RemoveManagerInner(INVALID_SLOTID));
    networkSearchManager->UnRegisterCoreNotify(slotId, networkSearchHandler, 1);
    networkSearchManager->UnRegisterCellularDataObject(callback);
}
 
/**
 * @tc.number   Telephony_NetworkSearchManager_006
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchManager_006, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto nsm = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(nsm, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(nsm, telRilManager, simManager, INVALID_SLOTID);
    nsm->OnInit();
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->networkSearchState_ = networkSearchState;
    inner->observerHandler_ = std::make_unique<ObserverHandler>();
    inner->networkSearchHandler_ = networkSearchHandler;
    nsm->delayTime_ = 1;
    int32_t status = 0;
    int32_t tokenId = 123456789;
    ImsRegInfo info;
    sptr<INetworkSearchCallback> networkSearchCallback = nullptr;
    nsm->AddManagerInner(INVALID_SLOTID, inner);
    nsm->RevertLastTechnology(INVALID_SLOTID);
    nsm->IsNeedDelayNotify(INVALID_SLOTID);
    nsm->HandleNotifyStateChangeWithDelay(INVALID_SLOTID, true);
    nsm->HandleNotifyStateChangeWithDelay(INVALID_SLOTID, false);
    nsm->InitSimRadioProtocol(INVALID_SLOTID);
    nsm->UnregisterImsRegInfoCallback(INVALID_SLOTID, ImsServiceType::TYPE_SMS, tokenId);
    EXPECT_EQ(nsm->HandleRrcStateChanged(INVALID_SLOTID, 0), TELEPHONY_ERR_FAIL);
    EXPECT_EQ(nsm->HandleRrcStateChanged(INVALID_SLOTID, 1), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(nsm->UpdateRrcConnectionState(INVALID_SLOTID, status), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(nsm->SetNrOptionMode(INVALID_SLOTID, -1), TELEPHONY_SUCCESS);
    EXPECT_NE(nsm->SetNrOptionMode(INVALID_SLOTID, -1, networkSearchCallback), TELEPHONY_SUCCESS);
    EXPECT_EQ(nsm->NotifyCallStatusToNetworkSearch(INVALID_SLOTID, 0), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(nsm->NotifyCallStatusToNetworkSearch(INVALID_SLOTID, -1), TELEPHONY_ERR_SUCCESS);
    inner->networkSearchState_ = nullptr;
    EXPECT_EQ(nsm->GetImsRegStatus(0, ImsServiceType::TYPE_VOICE, info), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_FALSE(nsm->IsNeedDelayNotify(INVALID_SLOTID));
    inner->networkSearchHandler_ = nullptr;
    EXPECT_EQ(nsm->SendUpdateCellLocationRequest(INVALID_SLOTID), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_TRUE(nsm->RemoveManagerInner(INVALID_SLOTID));
    nsm->SetBasebandVersion(INVALID_SLOTID, "");
    nsm->ConvertNetworkModeToCapabilityType(CORE_NETWORK_MODE_NR);
    nsm->ConvertNetworkModeToCapabilityType(-1);
    EXPECT_EQ(nsm->GetFrequencyType(INVALID_SLOTID), FrequencyType::FREQ_TYPE_UNKNOWN);
    EXPECT_GT(nsm->UpdateOperatorName(SLOT_ID_0), TELEPHONY_ERR_SUCCESS);
}
 
 
/**
 * @tc.number   Telephony_NetworkSearchHandler_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchHandler_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);
    networkSearchHandler->GetRadioStateResponse(event);
    networkSearchHandler->SetRadioStateResponse(event);
    networkSearchHandler->GetNetworkSelectionModeResponse(event);
    networkSearchHandler->SetNetworkSelectionModeResponse(event);
    EXPECT_TRUE(networkSearchHandler->Init());
    networkSearchHandler->UnregisterEvents();
    networkSearchHandler->DcPhysicalLinkActiveUpdate(event);
    networkSearchHandler->ProcessEvent(event);
    networkSearchHandler->RadioStateChange(event);
    networkSearchHandler->RadioRestrictedState(event);
    networkSearchHandler->RadioRilDataRegState(event);
    networkSearchHandler->RadioRilVoiceRegState(event);
    networkSearchHandler->RadioSignalStrength(event);
    networkSearchHandler->RadioRilOperator(event);
    networkSearchHandler->GetPreferredNetworkResponse(event);
    networkSearchHandler->SetPreferredNetworkResponse(event);
    networkSearchHandler->RadioGetImei(event);
    networkSearchHandler->RadioGetImeiSv(event);
    networkSearchHandler->RadioGetMeid(event);
    event = nullptr;
    networkSearchHandler->ProcessEvent(event);
    networkSearchHandler->DcPhysicalLinkActiveUpdate(event);
    networkSearchHandler->UpdateImsServiceStatus(event);
    networkSearchHandler->UpdateImsRegisterState(event);
    networkSearchHandler->GetRadioStateResponse(event);
    networkSearchHandler->SetRadioStateResponse(event);
    networkSearchHandler->ImsiLoadedReady(event);
    networkSearchHandler->RadioStateChange(event);
    networkSearchHandler->RadioRestrictedState(event);
    networkSearchHandler->RadioRilDataRegState(event);
    networkSearchHandler->RadioRilVoiceRegState(event);
    networkSearchHandler->RadioSignalStrength(event);
    networkSearchHandler->RadioRilOperator(event);
    networkSearchHandler->GetNetworkSelectionModeResponse(event);
    networkSearchHandler->SetNetworkSelectionModeResponse(event);
    networkSearchHandler->GetPreferredNetworkResponse(event);
    networkSearchHandler->SetPreferredNetworkResponse(event);
    networkSearchHandler->RadioNitzUpdate(event);
    networkSearchHandler->RadioGetImei(event);
    networkSearchHandler->RadioGetMeid(event);
    EXPECT_TRUE(networkSearchHandler->GetCellLocation() == nullptr);
}
 
/**
 * @tc.number   Telephony_NetworkSearchHandler_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchHandler_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);
    std::vector<sptr<SignalInformation>> signals;
    std::vector<sptr<CellInformation>> cells;
    EXPECT_TRUE(networkSearchHandler->Init());
    NetworkSearchResult mResult;
    MessageParcel parcel;
    mResult.Marshalling(parcel);
    mResult.ReadFromParcel(parcel);
    mResult.Unmarshalling(parcel);
    networkSearchHandler->RadioGetCurrentCellInfo(event);
    networkSearchHandler->RadioCurrentCellInfoUpdate(event);
    networkSearchHandler->RadioChannelConfigInfo(event);
    networkSearchHandler->RadioVoiceTechChange(event);
    networkSearchHandler->SimStateChange(event);
    networkSearchHandler->SimRecordsLoaded(event);
    networkSearchHandler->AutoTimeChange(event);
    networkSearchHandler->AutoTimeZoneChange(event);
    networkSearchHandler->AirplaneModeChange(event);
    networkSearchHandler->RadioGetBasebandVersion(event);
    networkSearchHandler->SetNrOptionModeResponse(event);
    networkSearchHandler->GetNrOptionModeResponse(event);
    networkSearchHandler->RadioGetRrcConnectionState(event);
    networkSearchHandler->RadioResidentNetworkChange(event);
    event = nullptr;
    networkSearchHandler->RadioGetCurrentCellInfo(event);
    networkSearchHandler->RadioCurrentCellInfoUpdate(event);
    networkSearchHandler->RadioChannelConfigInfo(event);
    networkSearchHandler->RadioVoiceTechChange(event);
    networkSearchHandler->RadioOnState();
    networkSearchHandler->GetSignalInfo(signals);
    networkSearchHandler->GetCellInfoList(cells);
    networkSearchHandler->UpdateCellLocation(1, 1, 1);
    networkSearchHandler->TimezoneRefresh();
    networkSearchHandler->SetCellRequestMinInterval(1);
    networkSearchHandler->RadioOffOrUnavailableState(1);
    networkSearchHandler->RadioGetNeighboringCellInfo(event);
    networkSearchHandler->RadioGetBasebandVersion(event);
    networkSearchHandler->SetNrOptionModeResponse(event);
    networkSearchHandler->GetNrOptionModeResponse(event);
    networkSearchHandler->RadioGetRrcConnectionState(event);
    networkSearchHandler->RadioResidentNetworkChange(event);
    EXPECT_EQ(networkSearchHandler->GetPhoneType(), PhoneType::PHONE_TYPE_IS_NONE);
}
 
/**
 * @tc.number   Telephony_NetworkSearchHandler_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchHandler_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::DELAY_NOTIFY_STATE_CHANGE);
    event = nullptr;
    int32_t status = RRC_IDLE_STATUS;
    networkSearchHandler->HandleDelayNotifyEvent(event);
    networkSearchHandler->NetworkSearchResult(event);
    networkSearchHandler->RadioGetNeighboringCellInfo(event);
    networkSearchHandler->RadioGetImeiSv(event);
    EXPECT_EQ(networkSearchHandler->HandleRrcStateChanged(status), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(networkSearchHandler->RevertLastTechnology(), TELEPHONY_ERR_LOCAL_PTR_NULL);
 
    EXPECT_TRUE(networkSearchHandler->Init());
    event = AppExecFwk::InnerEvent::Get(RadioEvent::DELAY_NOTIFY_STATE_CHANGE);
    networkSearchHandler->HandleDelayNotifyEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_NETWORK_SEARCH_RESULT);
    networkSearchHandler->NetworkSearchResult(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_NEIGHBORING_CELL_INFO);
    networkSearchHandler->RadioGetNeighboringCellInfo(event);
    networkSearchHandler->SetRadioOffWhenSimDeactive();
    EXPECT_EQ(networkSearchHandler->HandleRrcStateChanged(status), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchHandler->RevertLastTechnology(), TELEPHONY_ERR_SUCCESS);
    networkSearchHandler->IsPowerOnPrimaryRadioWhenNoSim();
    networkSearchHandler->UpdateOperatorName();
}
 
 
/**
 * @tc.number   Telephony_NetworkRegister_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkRegister_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0, 1);
    auto psRegInfo = std::make_shared<PsRegStatusResultInfo>();
    auto csRegInfo = std::make_shared<CsRegStatusInfo>();
    networkRegister->ProcessPsRegister(psRegInfo);
    networkRegister->ProcessCsRegister(csRegInfo);
    networkRegister->ProcessChannelConfigInfo(event);
    networkRegister->NotifyNrFrequencyChanged();
    psRegInfo = nullptr;
    csRegInfo = nullptr;
    networkRegister->ProcessPsRegister(psRegInfo);
    networkRegister->ProcessCsRegister(csRegInfo);
    EXPECT_EQ(networkRegister->ConvertRegFromRil(NetworkRegister::NetworkRegister::RilRegister::REG_STATE_SEARCH),
        RegServiceState::REG_STATE_SEARCH);
    EXPECT_EQ(networkRegister->ConvertRegFromRil(NetworkRegister::RilRegister::REG_STATE_NOT_REG),
        RegServiceState::REG_STATE_NO_SERVICE);
    EXPECT_EQ(networkRegister->ConvertRegFromRil(NetworkRegister::RilRegister::REG_STATE_NO_SERVICE),
        RegServiceState::REG_STATE_NO_SERVICE);
    EXPECT_EQ(networkRegister->ConvertRegFromRil(NetworkRegister::RilRegister::REG_STATE_INVALID),
        RegServiceState::REG_STATE_UNKNOWN);
    EXPECT_EQ(networkRegister->ConvertRegFromRil(NetworkRegister::RilRegister::REG_STATE_ROAMING),
        RegServiceState::REG_STATE_IN_SERVICE);
    EXPECT_EQ(networkRegister->ConvertRegFromRil(NetworkRegister::RilRegister::REG_STATE_HOME_ONLY),
        RegServiceState::REG_STATE_IN_SERVICE);
    EXPECT_EQ(networkRegister->ConvertRegFromRil(NetworkRegister::RilRegister::REG_STATE_EMERGENCY_ONLY),
        RegServiceState::REG_STATE_EMERGENCY_ONLY);
}
 
/**
 * @tc.number   Telephony_NetworkRegister_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkRegister_002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, INVALID_SLOTID);
    networkRegister->InitNrConversionConfig();
    std::string config = "";
    EXPECT_FALSE(networkRegister->IsValidConfig(config));
    config = "ConfigD";
    EXPECT_TRUE(networkRegister->IsValidConfig(config));
    int32_t rrcState = 1;
    EXPECT_NE(networkRegister->GetRrcConnectionState(rrcState), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkRegister->HandleRrcStateChanged(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkRegister->HandleRrcStateChanged(1), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(
        networkRegister->GetTechnologyByNrConfig(RadioTech::RADIO_TECHNOLOGY_NR), RadioTech::RADIO_TECHNOLOGY_INVALID);
    EXPECT_GT(
        networkRegister->GetTechnologyByNrConfig(RadioTech::RADIO_TECHNOLOGY_LTE), RadioTech::RADIO_TECHNOLOGY_INVALID);
    EXPECT_EQ(networkRegister->NotifyStateChange(), TELEPHONY_ERR_SUCCESS);
    EXPECT_GE(networkRegister->RevertLastTechnology(), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkRegister->GetSystemPropertiesConfig(config), TELEPHONY_ERR_SUCCESS);
    int32_t nsaState = 1;
    EXPECT_EQ(networkRegister->UpdateNsaState(nsaState), nsaState);
}
 
/**
 * @tc.number   Telephony_NetworkRegister_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkRegister_003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, INVALID_SLOTID);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_GSM), RadioTech::RADIO_TECHNOLOGY_GSM);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_1XRTT),
        RadioTech::RADIO_TECHNOLOGY_1XRTT);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_HSPA), RadioTech::RADIO_TECHNOLOGY_HSPA);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_HSPAP),
        RadioTech::RADIO_TECHNOLOGY_HSPAP);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_NR),
        RadioTech::RADIO_TECHNOLOGY_NR);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_WCDMA),
        RadioTech::RADIO_TECHNOLOGY_WCDMA);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_LTE), RadioTech::RADIO_TECHNOLOGY_LTE);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_EVDO), RadioTech::RADIO_TECHNOLOGY_EVDO);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_EHRPD),
        RadioTech::RADIO_TECHNOLOGY_EHRPD);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_TD_SCDMA),
        RadioTech::RADIO_TECHNOLOGY_TD_SCDMA);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_LTE_CA),
        RadioTech::RADIO_TECHNOLOGY_LTE_CA);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(TelRilRadioTech::RADIO_TECHNOLOGY_INVALID),
        RadioTech::RADIO_TECHNOLOGY_UNKNOWN);
}
 
HWTEST_F(NetworkSearchBranchTest, Telephony_NrSsbInfo, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto nrSsbInfo = std::make_shared<NrSsbInfo>(networkSearchManager, INVALID_SLOTID);
 
    EXPECT_FALSE(nrSsbInfo->FillNrSsbIdInformation(nullptr));
 
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo = std::make_shared<NrSsbInformation>();
    EXPECT_TRUE(nrSsbInfo->FillNrSsbIdInformation(nrCellSsbIdsInfo));
 
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    EXPECT_FALSE(nrSsbInfo->ProcessGetNrSsbId(event));
 
    EXPECT_FALSE(nrSsbInfo->UpdateNrSsbIdInfo(SLOT_ID_0, nullptr));
 
    std::shared_ptr<NrCellSsbIds> nrCellSsbIds = std::make_shared<NrCellSsbIds>();
    nrSsbInfo->nrCellSsbIdsInfo_ = nullptr;
    EXPECT_FALSE(nrSsbInfo->UpdateNrSsbIdInfo(SLOT_ID_0, nrCellSsbIds));
 
    nrSsbInfo->nrCellSsbIdsInfo_ = std::make_shared<NrCellSsbInfo>();
    EXPECT_TRUE(nrSsbInfo->UpdateNrSsbIdInfo(SLOT_ID_0, nrCellSsbIds));
 
    nrCellSsbIds->nbCellCount = 5;
    EXPECT_FALSE(nrSsbInfo->UpdateNrSsbIdInfo(SLOT_ID_0, nrCellSsbIds));
}
 
 
HWTEST_F(NetworkSearchBranchTest, Telephony_RadioInfo, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto radioInfo = std::make_shared<RadioInfo>(networkSearchManager, INVALID_SLOTID);
 
    AppExecFwk::InnerEvent::Pointer event(nullptr, nullptr);
    radioInfo->ProcessGetRadioState(event);
    radioInfo->ProcessSetRadioState(event);
 
    std::shared_ptr<NetworkSearchManager> nsm = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    radioInfo->RadioFirstPowerOn(nsm, ModemPowerState::CORE_SERVICE_POWER_OFF);
    radioInfo->ProcessGetImei(event);
    radioInfo->ProcessGetImeiSv(event);
    radioInfo->ProcessGetMeid(event);
    radioInfo->ProcessVoiceTechChange(event);
    radioInfo->ProcessGetBasebandVersion(event);
    radioInfo->ProcessGetRrcConnectionState(event);
    radioInfo->ProcessSetNrOptionMode(event);
    radioInfo->ProcessGetNrOptionMode(event);
    EXPECT_EQ(radioInfo->RadioTechToPhoneType(RadioTech::RADIO_TECHNOLOGY_1XRTT, RadioTech::RADIO_TECHNOLOGY_LTE),
        PhoneType::PHONE_TYPE_IS_CDMA);
    EXPECT_EQ(radioInfo->RadioTechToPhoneType(RadioTech::RADIO_TECHNOLOGY_EVDO, RadioTech::RADIO_TECHNOLOGY_LTE),
        PhoneType::PHONE_TYPE_IS_CDMA);
    EXPECT_EQ(radioInfo->RadioTechToPhoneType(RadioTech::RADIO_TECHNOLOGY_EHRPD, RadioTech::RADIO_TECHNOLOGY_LTE),
        PhoneType::PHONE_TYPE_IS_CDMA);
 
    EXPECT_EQ(radioInfo->RadioTechToPhoneType(RadioTech::RADIO_TECHNOLOGY_UNKNOWN, RadioTech::RADIO_TECHNOLOGY_LTE),
        PhoneType::PHONE_TYPE_IS_GSM);
    EXPECT_EQ(radioInfo->RadioTechToPhoneType(RadioTech::RADIO_TECHNOLOGY_UNKNOWN, RadioTech::RADIO_TECHNOLOGY_LTE_CA),
        PhoneType::PHONE_TYPE_IS_GSM);
    EXPECT_EQ(radioInfo->RadioTechToPhoneType(RadioTech::RADIO_TECHNOLOGY_UNKNOWN, RadioTech::RADIO_TECHNOLOGY_NR),
        PhoneType::PHONE_TYPE_IS_GSM);
    radioInfo->SetRadioOnIfNeeded();
    radioInfo->slotId_ = SLOT_ID_0;
    radioInfo->SetRadioOnIfNeeded();
    nsm->simManager_ = nullptr;
    radioInfo->SetRadioOnIfNeeded();
    nsm.reset();
    radioInfo->SetRadioOnIfNeeded();
}
 
} // namespace Telephony
} // namespace OHOS