/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "cell_info.h"
#include "cell_location.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "core_service_client.h"
#include "csim_file_controller.h"
#include "gtest/gtest.h"
#include "icc_file.h"
#include "icc_file_controller.h"
#include "icc_operator_rule.h"
#include "ims_core_service_callback_proxy.h"
#include "ims_core_service_callback_stub.h"
#include "ims_core_service_proxy.h"
#include "isim_file_controller.h"
#include "multi_sim_controller.h"
#include "multi_sim_monitor.h"
#include "network_register.h"
#include "network_search_manager.h"
#include "network_search_state.h"
#include "operator_matching_rule.h"
#include "operator_name.h"
#include "radio_protocol_controller.h"
#include "ruim_file_controller.h"
#include "sim_file_controller.h"
#include "sim_file_manager.h"
#include "sim_manager.h"
#include "sim_number_decode.h"
#include "sim_rdb_helper.h"
#include "sim_sms_controller.h"
#include "sim_state_manager.h"
#include "sim_utils.h"
#include "stk_controller.h"
#include "stk_manager.h"
#include "tag_service.h"
#include "tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_hisysevent.h"
#include "telephony_log_wrapper.h"
#include "usim_file_controller.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
const int32_t INVALID_SLOTID = 2;
const int32_t OBTAIN_SPN_NONE = 0;
const int32_t OBTAIN_SPN_START = 1;
const int32_t OBTAIN_SPN_GENERAL = 2;
const int32_t OBTAIN_OPERATOR_NAMESTRING = 3;
const int32_t OBTAIN_OPERATOR_NAME_SHORTFORM = 4;
const int32_t BYTES_LENGTH = 3;
const int32_t LO_FOUR_LENGTH = 15;
const int32_t VALUE_LENGTH = 128;
} // namespace

class DemoHandler : public AppExecFwk::EventHandler {
public:
    explicit DemoHandler(std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner) {}
    virtual ~DemoHandler() {}
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) {}
};

class BranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void BranchTest::SetUpTestCase() {}

void BranchTest::TearDownTestCase() {}

void BranchTest::SetUp() {}

void BranchTest::TearDown() {}

/**
 * @tc.number   Telephony_CellInfo_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellInfo_001, Function | MediumTest | Level1)
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
HWTEST_F(BranchTest, Telephony_CellInfo_002, Function | MediumTest | Level1)
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
    CurrentCellInfo current;
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellGsm(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellLte(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellWcdma(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellCdma(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellTdscdma(&cellNearbyInfo));
    EXPECT_TRUE(cellInfo->ProcessNeighboringCellNr(&cellNearbyInfo));
    current.ratType = RatType::NETWORK_TYPE_GSM;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = RatType::NETWORK_TYPE_LTE;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = RatType::NETWORK_TYPE_WCDMA;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = RatType::NETWORK_TYPE_TDSCDMA;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = RatType::NETWORK_TYPE_CDMA;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = RatType::NETWORK_TYPE_NR;
    EXPECT_TRUE(cellInfo->ProcessCurrentCell(&current));
    current.ratType = RatType::NETWORK_TYPE_UNKNOWN;
    EXPECT_FALSE(cellInfo->ProcessCurrentCell(&current));
}

/**
 * @tc.number   Telephony_CellInfo_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CellInfo_003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager_ = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto cellInfo = std::make_shared<CellInfo>(networkSearchManager_, INVALID_SLOTID);
    EXPECT_EQ(
        cellInfo->ConvertToCellType(SignalInformation::NetworkType::GSM), CellInformation::CellType::CELL_TYPE_GSM);
    EXPECT_EQ(
        cellInfo->ConvertToCellType(SignalInformation::NetworkType::WCDMA), CellInformation::CellType::CELL_TYPE_WCDMA);
    EXPECT_EQ(
        cellInfo->ConvertToCellType(SignalInformation::NetworkType::LTE), CellInformation::CellType::CELL_TYPE_LTE);
    EXPECT_EQ(
        cellInfo->ConvertToCellType(SignalInformation::NetworkType::CDMA), CellInformation::CellType::CELL_TYPE_CDMA);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::TDSCDMA),
        CellInformation::CellType::CELL_TYPE_TDSCDMA);
    EXPECT_EQ(cellInfo->ConvertToCellType(SignalInformation::NetworkType::NR), CellInformation::CellType::CELL_TYPE_NR);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_GSM), CellInformation::CellType::CELL_TYPE_GSM);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_WCDMA), CellInformation::CellType::CELL_TYPE_WCDMA);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_HSPAP), CellInformation::CellType::CELL_TYPE_WCDMA);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_HSPA), CellInformation::CellType::CELL_TYPE_WCDMA);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_LTE), CellInformation::CellType::CELL_TYPE_LTE);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_LTE_CA), CellInformation::CellType::CELL_TYPE_LTE);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_TD_SCDMA),
        CellInformation::CellType::CELL_TYPE_TDSCDMA);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_1XRTT), CellInformation::CellType::CELL_TYPE_CDMA);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_EVDO), CellInformation::CellType::CELL_TYPE_CDMA);
    EXPECT_EQ(
        cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_EHRPD), CellInformation::CellType::CELL_TYPE_CDMA);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_NR), CellInformation::CellType::CELL_TYPE_NR);
    EXPECT_EQ(cellInfo->ConvertTechToCellType(RadioTech::RADIO_TECHNOLOGY_UNKNOWN),
        CellInformation::CellType::CELL_TYPE_NONE);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(RatType::NETWORK_TYPE_GSM), CellInformation::CellType::CELL_TYPE_GSM);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(RatType::NETWORK_TYPE_WCDMA), CellInformation::CellType::CELL_TYPE_WCDMA);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(RatType::NETWORK_TYPE_LTE), CellInformation::CellType::CELL_TYPE_LTE);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(RatType::NETWORK_TYPE_CDMA), CellInformation::CellType::CELL_TYPE_CDMA);
    EXPECT_EQ(
        cellInfo->ConvertRatToCellType(RatType::NETWORK_TYPE_TDSCDMA), CellInformation::CellType::CELL_TYPE_TDSCDMA);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(RatType::NETWORK_TYPE_NR), CellInformation::CellType::CELL_TYPE_NR);
    EXPECT_EQ(cellInfo->ConvertRatToCellType(RatType::NETWORK_TYPE_UNKNOWN), CellInformation::CellType::CELL_TYPE_NONE);
}

/**
 * @tc.number   Telephony_SimFileManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFileManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    SimFileManager simFileManager { runner, telRilManager, simStateManager };
    const std::u16string emptyStr = Str8ToStr16("");
    const std::u16string mailName = Str8ToStr16("张三");
    const std::u16string mailnumber = Str8ToStr16("12345678901");
    simFileManager.ClearData();
    EXPECT_EQ(simFileManager.GetSimOperatorNumeric(), u"");
    simFileManager.GetISOCountryCodeForSim();
    EXPECT_EQ(simFileManager.GetSimSpn(), u"");
    EXPECT_EQ(simFileManager.GetSimEons("46001", 1, true), u"");
    EXPECT_EQ(simFileManager.GetSimIccId(), u"");
    EXPECT_EQ(simFileManager.GetLocaleFromDefaultSim(), u"");
    EXPECT_EQ(simFileManager.GetSimGid1(), u"");
    EXPECT_EQ(simFileManager.GetSimGid2(), u"");
    EXPECT_EQ(simFileManager.GetSimTelephoneNumber(), u"");
    EXPECT_EQ(simFileManager.GetSimTeleNumberIdentifier(), u"");
    EXPECT_EQ(simFileManager.GetSimIst(), u"");
    EXPECT_EQ(simFileManager.GetVoiceMailIdentifier(), u"");
    EXPECT_EQ(simFileManager.GetVoiceMailNumber(), u"");
    EXPECT_EQ(simFileManager.GetIccFile(), nullptr);
    EXPECT_EQ(simFileManager.GetIccFileController(), nullptr);
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    simFileManager.ProcessEvent(event);
    simFileManager.SetImsi("46001");
    simFileManager.SetOpName("46001");
    simFileManager.SetOpKey("CMCC");
    simFileManager.SetOpKeyExt("opkeyext");
    EXPECT_EQ(simFileManager.ObtainSpnCondition(true, "46001"), 0);
    EXPECT_FALSE(simFileManager.SetVoiceMailInfo(mailName, mailnumber));
    EXPECT_FALSE(simFileManager.HasSimCard());
    EXPECT_NE(simFileManager.GetIMSI(), u"46001");
    EXPECT_EQ(simFileManager.GetOpKey(), u"CMCC");
    EXPECT_EQ(simFileManager.GetOpName(), u"46001");
    EXPECT_EQ(simFileManager.GetOpKeyExt(), u"opkeyext");
}

/**
 * @tc.number   Telephony_SimFileManager_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFileManager_002, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    SimFileManager simFileManager { runner, telRilManager, simStateManager };
    auto tech = std::make_shared<VoiceRadioTechnology>();
    simFileManager.ChangeSimFileByCardType(SimFileManager::IccType::ICC_TYPE_USIM);
    EXPECT_EQ(
        simFileManager.GetIccTypeByCardType(CardType::SINGLE_MODE_RUIM_CARD), SimFileManager::IccType::ICC_TYPE_CDMA);
    EXPECT_EQ(simFileManager.GetIccTypeByCardType(CardType::DUAL_MODE_UG_CARD), SimFileManager::IccType::ICC_TYPE_GSM);
    EXPECT_EQ(
        simFileManager.GetIccTypeByCardType(CardType::SINGLE_MODE_USIM_CARD), SimFileManager::IccType::ICC_TYPE_USIM);
    tech->actType = HRilRadioTech::RADIO_TECHNOLOGY_EHRPD;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_CDMA);
    tech->actType = HRilRadioTech::RADIO_TECHNOLOGY_1XRTT;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_CDMA);
    tech->actType = HRilRadioTech::RADIO_TECHNOLOGY_WCDMA;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_GSM);
    tech->actType = HRilRadioTech::RADIO_TECHNOLOGY_LTE_CA;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_GSM);
    tech->actType = HRilRadioTech::RADIO_TECHNOLOGY_LTE;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_GSM);
    tech->actType = HRilRadioTech::RADIO_TECHNOLOGY_GSM;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_GSM);
    tech->actType = HRilRadioTech::RADIO_TECHNOLOGY_TD_SCDMA;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_GSM);
    tech->actType = HRilRadioTech::RADIO_TECHNOLOGY_HSPA;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_GSM);
    EXPECT_TRUE(simFileManager.IsValidType(SimFileManager::IccType::ICC_TYPE_CDMA));
    tech = nullptr;
    EXPECT_EQ(simFileManager.GetIccTypeByTech(tech), SimFileManager::IccType::ICC_TYPE_GSM);
    EXPECT_EQ(simFileManager.GetIccTypeByTech(nullptr), SimFileManager::IccType::ICC_TYPE_GSM);
}

/**
 * @tc.number   Telephony_SimFile_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFile_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("SimFile");
    std::shared_ptr<SimFile> simFile = std::make_shared<SimFile>(eventLoopRecord, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    EXPECT_TRUE(simFile->ProcessGetAdDone(event));
    EXPECT_TRUE(simFile->ProcessVoiceMailCphs(event));
    EXPECT_TRUE(simFile->ProcessGetMwisDone(event));
    EXPECT_TRUE(simFile->ProcessGetMbdnDone(event));
    event = nullptr;
    simFile->ProcessEvent(event);
    simFile->ObtainSpnPhase(false, event);
    simFile->ProcessSpnGeneral(event);
    simFile->ProcessSpnCphs(event);
    simFile->ProcessSpnShortCphs(event);
    simFile->InitMemberFunc();
    simFile->ProcessFileLoaded(false);
    simFile->ProcessFileLoaded(true);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_MBDN);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_MAILBOX_CPHS);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_CSP_CPHS);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_FDN);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_MSISDN);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_CFIS);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_CFF_CPHS);
    EXPECT_EQ(simFile->ObtainIsoCountryCode(), "");
    simFile->imsi_ = "1234567890";
    EXPECT_EQ(simFile->ObtainIsoCountryCode(), "");
    simFile->lengthOfMnc_ = OBTAIN_SPN_GENERAL;
    simFile->CheckMncLength();
    simFile->lengthOfMnc_ = UNKNOWN_MNC;
    simFile->CheckMncLength();
    simFile->lengthOfMnc_ = UNINITIALIZED_MNC;
    simFile->CheckMncLength();
    EXPECT_FALSE(simFile->CphsVoiceMailAvailable());
    EXPECT_FALSE(simFile->ProcessIccReady(event));
    EXPECT_TRUE(simFile->ProcessGetAdDone(event));
    EXPECT_TRUE(simFile->ProcessVoiceMailCphs(event));
    EXPECT_TRUE(simFile->ProcessGetMwisDone(event));
    EXPECT_TRUE(simFile->ProcessGetMbdnDone(event));
}

/**
 * @tc.number   Telephony_SimFile_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFile_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("SimFile");
    std::shared_ptr<SimFile> simFile = std::make_shared<SimFile>(eventLoopRecord, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    std::string testStr = "";
    simFile->UpdateMsisdnNumber(testStr, testStr, event);
    EXPECT_TRUE(simFile->ProcessGetCphsMailBoxDone(event));
    EXPECT_TRUE(simFile->ProcessGetMbiDone(event));
    EXPECT_TRUE(simFile->ProcessGetCfisDone(event));
    EXPECT_TRUE(simFile->ProcessGetCffDone(event));
    EXPECT_TRUE(simFile->ProcessObtainIMSIDone(event));
    EXPECT_TRUE(simFile->ProcessGetIccIdDone(event));
    EXPECT_TRUE(simFile->ProcessGetPlmnActDone(event));
    EXPECT_TRUE(simFile->ProcessGetOplmnActDone(event));
    EXPECT_TRUE(simFile->ProcessGetSpdiDone(event));
    EXPECT_TRUE(simFile->ProcessGetMsisdnDone(event));
    EXPECT_FALSE(simFile->ProcessSetMsisdnDone(event));
    EXPECT_TRUE(simFile->ProcessObtainGid1Done(event));
    EXPECT_TRUE(simFile->ProcessObtainGid2Done(event));
    EXPECT_FALSE(simFile->ProcessSmsOnSim(event));
    EXPECT_TRUE(simFile->ProcessGetCspCphs(event));
    EXPECT_TRUE(simFile->ProcessGetInfoCphs(event));
    EXPECT_TRUE(simFile->ProcessGetSstDone(event));
    EXPECT_FALSE(simFile->ProcessGetSmsDone(event));
    EXPECT_TRUE(simFile->ProcessGetAllSmsDone(event));
    EXPECT_TRUE(simFile->ProcessGetHplmActDone(event));
    EXPECT_TRUE(simFile->ProcessGetEhplmnDone(event));
    EXPECT_TRUE(simFile->ProcessGetPnnDone(event));
    EXPECT_TRUE(simFile->ProcessGetOplDone(event));
    EXPECT_TRUE(simFile->ProcessGetOpl5gDone(event));
    EXPECT_FALSE(simFile->ProcessUpdateDone(event));
    EXPECT_TRUE(simFile->ProcessSetCphsMailbox(event));
    EXPECT_TRUE(simFile->ProcessGetFplmnDone(event));
    EXPECT_TRUE(simFile->ProcessSetMbdn(event));
    EXPECT_FALSE(simFile->ProcessMarkSms(event));
    EXPECT_TRUE(simFile->ProcessObtainSpnPhase(event));
    EXPECT_TRUE(simFile->ProcessObtainLiLanguage(event));
    EXPECT_TRUE(simFile->ProcessObtainPlLanguage(event));
}

/**
 * @tc.number   Telephony_SimFile_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFile_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("SimFile");
    std::shared_ptr<SimFile> simFile = std::make_shared<SimFile>(eventLoopRecord, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    std::string mailName = "";
    std::string mailNumber = "1234";
    simFile->indexOfMailbox_ = 0;
    EXPECT_FALSE(simFile->UpdateVoiceMail(mailName, mailNumber));
    simFile->efCfis_ = (unsigned char *)mailNumber.c_str();
    simFile->imsi_ = "123";
    simFile->lengthOfMnc_ = UNKNOWN_MNC;
    EXPECT_EQ(simFile->ObtainSimOperator(), "");
    simFile->lengthOfMnc_ = UNINITIALIZED_MNC;
    EXPECT_EQ(simFile->ObtainSimOperator(), "");
    EXPECT_TRUE(simFile->ProcessGetCphsMailBoxDone(event));
    EXPECT_TRUE(simFile->ProcessGetMbiDone(event));
    EXPECT_TRUE(simFile->ProcessGetCfisDone(event));
    EXPECT_TRUE(simFile->ProcessGetCffDone(event));
    EXPECT_TRUE(simFile->ProcessObtainIMSIDone(event));
    EXPECT_TRUE(simFile->ProcessGetIccIdDone(event));
    EXPECT_TRUE(simFile->ProcessGetPlmnActDone(event));
    EXPECT_TRUE(simFile->ProcessGetOplmnActDone(event));
    EXPECT_TRUE(simFile->ProcessGetSpdiDone(event));
    EXPECT_TRUE(simFile->ProcessGetMsisdnDone(event));
    EXPECT_FALSE(simFile->ProcessSetMsisdnDone(event));
    EXPECT_TRUE(simFile->ProcessObtainGid1Done(event));
    EXPECT_TRUE(simFile->ProcessObtainGid2Done(event));
    EXPECT_FALSE(simFile->ProcessSmsOnSim(event));
    EXPECT_TRUE(simFile->ProcessGetCspCphs(event));
    EXPECT_TRUE(simFile->ProcessGetInfoCphs(event));
    EXPECT_TRUE(simFile->ProcessGetSstDone(event));
    EXPECT_FALSE(simFile->ProcessGetSmsDone(event));
    EXPECT_TRUE(simFile->ProcessGetAllSmsDone(event));
    EXPECT_TRUE(simFile->ProcessGetHplmActDone(event));
    EXPECT_TRUE(simFile->ProcessGetEhplmnDone(event));
    EXPECT_TRUE(simFile->ProcessGetPnnDone(event));
    EXPECT_TRUE(simFile->ProcessGetOplDone(event));
    EXPECT_FALSE(simFile->ProcessUpdateDone(event));
    EXPECT_TRUE(simFile->ProcessGetFplmnDone(event));
}

/**
 * @tc.number   Telephony_SimFile_004
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFile_004, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("SimFile");
    std::shared_ptr<SimFile> simFile = std::make_shared<SimFile>(eventLoopRecord, simStateManager);
    std::string operatorNum = "";
    EXPECT_EQ(simFile->ObtainSpnCondition(true, operatorNum), 0);
    simFile->displayConditionOfSpn_ = OBTAIN_SPN_GENERAL;
    EXPECT_GT(simFile->ObtainSpnCondition(false, operatorNum), 0);
    simFile->displayConditionOfSpn_ = -1;
    EXPECT_EQ(simFile->ObtainSpnCondition(false, operatorNum), 0);
    EXPECT_EQ(simFile->ObtainCallForwardStatus(), 0);
    EXPECT_EQ(simFile->ObtainUsimFunctionHandle(), nullptr);
    EXPECT_EQ(simFile->AnalysisBcdPlmn(operatorNum, operatorNum), "");
    simFile->ProcessElementaryFileCsp(operatorNum);
    simFile->AnalysisElementaryFileSpdi(operatorNum);
    simFile->ProcessSmses(operatorNum);
    simFile->ProcessSms(operatorNum);
    std::vector<std::string> emptyRecords = {};
    std::vector<std::string> records = { "46000", "46002", "46004", "46007", "46008" };
    simFile->ParsePnn(emptyRecords);
    simFile->ParseOpl(emptyRecords);
    simFile->ParsePnn(records);
    simFile->ParseOpl(records);
    std::vector<std::string> invalidRecords = { "64F0100000GGGG02", "64F0000000GGGG01" };
    simFile->ParseOpl(invalidRecords);
    std::vector<std::string> invalidPlmnRecords = { "F640100000FFFE02", "F640000000FFFE01" };
    simFile->ParseOpl(invalidPlmnRecords);
    std::vector<std::string> records5g = { "64F0100000FFFE02", "64F0000000FFFE01" };
    simFile->ParseOpl(records5g);
    SimFile::SpnStatus newStatus;
    EXPECT_TRUE(simFile->IsContinueGetSpn(false, SimFile::SpnStatus::OBTAIN_SPN_NONE, newStatus));
    EXPECT_TRUE(simFile->IsContinueGetSpn(true, SimFile::SpnStatus::OBTAIN_SPN_NONE, newStatus));
    EXPECT_FALSE(simFile->IsContinueGetSpn(true, SimFile::SpnStatus::OBTAIN_SPN_START, newStatus));
    EXPECT_FALSE(simFile->IsContinueGetSpn(true, SimFile::SpnStatus::OBTAIN_SPN_GENERAL, newStatus));
    EXPECT_FALSE(simFile->IsContinueGetSpn(true, SimFile::SpnStatus::OBTAIN_OPERATOR_NAMESTRING, newStatus));
    EXPECT_FALSE(simFile->IsContinueGetSpn(true, SimFile::SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM, newStatus));
    EXPECT_EQ(simFile->ObtainExtensionElementaryFile(ELEMENTARY_FILE_MSISDN), ELEMENTARY_FILE_EXT5);
    EXPECT_EQ(simFile->ObtainExtensionElementaryFile(ELEMENTARY_FILE_SPN), ELEMENTARY_FILE_EXT1);
    EXPECT_EQ(simFile->ParseSpn(operatorNum, 0), "");
    EXPECT_EQ(simFile->ParseSpn("CMCC", OBTAIN_SPN_NONE), "");
    EXPECT_EQ(simFile->ParseSpn("CMCC", OBTAIN_SPN_START), "");
    EXPECT_EQ(simFile->ParseSpn("CMCC", OBTAIN_SPN_GENERAL), "\xCC");
    EXPECT_EQ(simFile->ParseSpn("CMCC", OBTAIN_OPERATOR_NAMESTRING), "\xC0\xCC");
    EXPECT_EQ(simFile->ParseSpn("CMCC", OBTAIN_OPERATOR_NAME_SHORTFORM), "\xC0\xCC");
    EXPECT_EQ(simFile->ParseSpn("", 0), "");
}

/**
 * @tc.number   Telephony_SimFile_005
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFile_005, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("SimFile");
    std::shared_ptr<SimFile> simFile = std::make_shared<SimFile>(eventLoopRecord, simStateManager);
    std::vector<std::string> emptyRecords = {};
    simFile->ParseOpl5g(emptyRecords);
    EXPECT_TRUE(simFile->opl5gFiles_.empty());
    std::vector<std::string> records = { "46000", "46002", "46004", "46007", "46008" };
    simFile->ParseOpl5g(records);
    EXPECT_TRUE(simFile->opl5gFiles_.empty());
    std::vector<std::string> invalidRecords = { "64F010000000GGGGGG02", "64F000000000GGGGGG01" };
    simFile->ParseOpl5g(invalidRecords);
    EXPECT_TRUE(simFile->opl5gFiles_.empty());
    std::vector<std::string> invalidPlmnRecords = { "F64010000000FFFFFE02", "F64000000000FFFFFE01" };
    simFile->ParseOpl5g(invalidPlmnRecords);
    EXPECT_TRUE(simFile->opl5gFiles_.empty());
    std::vector<std::string> records5g = { "64F010000000FFFFFE02", "64F000000000FFFFFE01" };
    simFile->ParseOpl5g(records5g);
    EXPECT_FALSE(simFile->opl5gFiles_.empty());
}

/**
 * @tc.number   Telephony_ISimFile_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_ISimFile_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("IsimFile");
    std::shared_ptr<IsimFile> iSimFile = std::make_shared<IsimFile>(eventLoopRecord, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_READY, 1);
    iSimFile->InitMemberFunc();
    iSimFile->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(0, 1);
    iSimFile->ProcessEvent(event);
    EXPECT_TRUE(iSimFile->ProcessGetIccidDone(event));
    EXPECT_TRUE(iSimFile->ProcessGetImsiDone(event));
    EXPECT_TRUE(iSimFile->ProcessGetImpiDone(event));
    EXPECT_TRUE(iSimFile->ProcessGetIstDone(event));
    event = nullptr;
    iSimFile->ProcessEvent(event);
    EXPECT_FALSE(iSimFile->ProcessIccReady(event));
    EXPECT_EQ(iSimFile->ObtainIsimImpi(), "");
    EXPECT_EQ(iSimFile->ObtainIsimDomain(), "");
    EXPECT_EQ(iSimFile->ObtainIsimImpu(), nullptr);
    EXPECT_EQ(iSimFile->ObtainIsimIst(), "");
    EXPECT_EQ(iSimFile->ObtainIsimPcscf(), nullptr);
    EXPECT_FALSE(iSimFile->UpdateVoiceMail("", ""));
    EXPECT_EQ(iSimFile->ObtainSpnCondition(true, ""), 0);
    EXPECT_EQ(iSimFile->ObtainIsoCountryCode(), "");
    iSimFile->ProcessFileLoaded(false);
    iSimFile->ProcessLockedAllFilesFetched();
    EXPECT_FALSE(iSimFile->ProcessIsimRefresh(event));
    EXPECT_TRUE(iSimFile->ProcessGetImsiDone(event));
    EXPECT_TRUE(iSimFile->ProcessGetIccidDone(event));
    EXPECT_TRUE(iSimFile->ProcessGetImpiDone(event));
    EXPECT_TRUE(iSimFile->ProcessGetIstDone(event));
}

/**
 * @tc.number   Telephony_RuimFile_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_RuimFile_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("RuimFile");
    std::shared_ptr<RuimFile> rUimFile = std::make_shared<RuimFile>(eventLoopRecord, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_READY, 1);
    rUimFile->InitMemberFunc();
    rUimFile->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(0, 1);
    rUimFile->ProcessEvent(event);
    rUimFile->ProcessFileLoaded(false);
    unsigned char spnData[10] = { 0 };
    rUimFile->ParseSpnName(IccDiallingNumberConstant::CSIM_SPN_OCTET, spnData, 0);
    rUimFile->ParseSpnName(IccDiallingNumberConstant::CSIM_SPN_LATIN, spnData, 0);
    rUimFile->ParseSpnName(IccDiallingNumberConstant::CSIM_SPN_IA5, spnData, 0);
    rUimFile->ParseSpnName(IccDiallingNumberConstant::CSIM_SPN_7BIT_ALPHABET, spnData, 0);
    rUimFile->ParseSpnName(IccDiallingNumberConstant::NAME_CHAR_POS, spnData, 0);
    EXPECT_TRUE(rUimFile->ProcessGetIccidDone(event));
    EXPECT_TRUE(rUimFile->ProcessGetImsiDone(event));
    EXPECT_TRUE(rUimFile->ProcessGetSpnDone(event));
    event = nullptr;
    rUimFile->ProcessEvent(event);
    EXPECT_EQ(rUimFile->ObtainSimOperator(), "");
    EXPECT_EQ(rUimFile->ObtainIsoCountryCode(), "");
    rUimFile->imsi_ = "12345678";
    EXPECT_EQ(rUimFile->ObtainSimOperator(), "12345");
    EXPECT_EQ(rUimFile->ObtainIsoCountryCode(), "");
    EXPECT_EQ(rUimFile->ObtainMdnNumber(), "");
    EXPECT_EQ(rUimFile->ObtainCdmaMin(), "");
    EXPECT_EQ(rUimFile->ObtainPrlVersion(), "");
    EXPECT_EQ(rUimFile->ObtainNAI(), "");
    EXPECT_EQ(rUimFile->ObtainMdn(), "");
    EXPECT_EQ(rUimFile->ObtainMin(), "");
    EXPECT_EQ(rUimFile->ObtainSid(), "");
    EXPECT_EQ(rUimFile->ObtainNid(), "");
    EXPECT_FALSE(rUimFile->ObtainCsimSpnDisplayCondition());
    EXPECT_EQ(rUimFile->ObtainSpnCondition(true, ""), 0);
    EXPECT_FALSE(rUimFile->UpdateVoiceMail("", ""));
    EXPECT_TRUE(rUimFile->ProcessGetImsiDone(event));
    EXPECT_TRUE(rUimFile->ProcessGetIccidDone(event));
    EXPECT_TRUE(rUimFile->ProcessGetSubscriptionDone(event));
    EXPECT_TRUE(rUimFile->ProcessGetSpnDone(event));
}

/**
 * @tc.number   Telephony_IccFileController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_IccFileController_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<IccFileController> iccFileController = std::make_shared<SimFileController>(runner, 1);
    auto event = AppExecFwk::InnerEvent::Get(0);
    iccFileController->ProcessEvent(event);
    event = nullptr;
    iccFileController->ProcessEvent(event);
    iccFileController->telRilManager_ = nullptr;
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_ICCID);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_PL);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_ADN);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_FDN);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_MSISDN);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_SDN);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_EXT1);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_EXT2);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_EXT3);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_PBR);
    iccFileController->ObtainElementFileForPublic(ELEMENTARY_FILE_IMG);
    iccFileController->ObtainElementFileForPublic(0);
    EXPECT_TRUE(iccFileController->IsFixedNumberType(ELEMENTARY_FILE_ADN));
    EXPECT_TRUE(iccFileController->IsFixedNumberType(ELEMENTARY_FILE_FDN));
    EXPECT_TRUE(iccFileController->IsFixedNumberType(ELEMENTARY_FILE_USIM_ADN));
    iccFileController->SetRilManager(iccFileController->telRilManager_);
    EXPECT_TRUE(iccFileController->IsFixedNumberType(ELEMENTARY_FILE_USIM_IAP));
    EXPECT_FALSE(iccFileController->IsFixedNumberType(0));
}

/**
 * @tc.number   Telephony_CoreManagerInner_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CoreManagerInner_001, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    mInner.OnInit(nullptr, nullptr, nullptr);
    mInner.SetTelRilMangerObj(nullptr);
    EXPECT_TRUE(mInner.IsInitFinished());
    EXPECT_FALSE(mInner.IsInitFinishedForTelRil());
    EXPECT_EQ(mInner.GetDefaultSlotId(), 0);
    EXPECT_GT(mInner.GetMaxSimCount(), 0);
    EXPECT_GT(mInner.SetRadioState(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetRadioState(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.ShutDown(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.Dial(0, 0, "", 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.Reject(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.Hangup(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.Answer(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCallList(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.HoldCall(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.UnHoldCall(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SwitchCall(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.CombineConference(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SeparateConference(0, 0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.CallSupplement(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetDataPermitted(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    DataProfile mDataProfile;
    EXPECT_GT(mInner.SetInitApnInfo(0, 0, mDataProfile, nullptr), TELEPHONY_ERR_SUCCESS);
    ActivateDataParam mActivateDataParam;
    EXPECT_GT(mInner.ActivatePdpContext(0, 0, mActivateDataParam, nullptr), TELEPHONY_ERR_SUCCESS);
    DeactivateDataParam mDeactivateDataParam;
    EXPECT_GT(mInner.DeactivatePdpContext(0, 0, mDeactivateDataParam, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetPdpContextList(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetLinkBandwidthInfo(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    LinkBandwidthRule mLinkBandwidthRule;
    EXPECT_GT(mInner.SetLinkBandwidthReportingRule(0, 0, mLinkBandwidthRule, nullptr), TELEPHONY_ERR_SUCCESS);
    bool airplaneMode = false;
    EXPECT_GT(mInner.GetAirplaneMode(airplaneMode), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.UpdateRadioOn(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetLinkCapability(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreManagerInner_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CoreManagerInner_002, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    EXPECT_GT(mInner.StopDTMF(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.StartDTMF(0, 0, 'A', 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SendDTMF(0, 0, 'A', 0, nullptr), TELEPHONY_ERR_SUCCESS);
    DtmfParam mDtmfParam;
    EXPECT_GT(mInner.SendDTMF(0, 0, mDtmfParam, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetSignalStrength(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCsRegStatus(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetPsRegStatus(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetCallPreferenceMode(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCallPreferenceMode(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetUssd(0, 0, "", nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetUssd(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetMute(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetMute(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetEmergencyCallList(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    std::vector<EmergencyCall> eccVec;
    EXPECT_GT(mInner.SetEmergencyCallList(0, 0, eccVec, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCallFailReason(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetOperatorInfo(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCellInfoList(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCurrentCellInfo(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreManagerInner_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CoreManagerInner_003, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    mInner.DcPhysicalLinkActiveUpdate(0, true);
    int32_t radioTech;
    EXPECT_NE(mInner.GetPsRadioTech(0, radioTech), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetCsRadioTech(0, radioTech), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mInner.GetPsRegState(0), -1);
    EXPECT_EQ(mInner.GetRadioState(0), -1);
    EXPECT_EQ(mInner.GetCsRegState(0), -1);
    EXPECT_EQ(mInner.GetPsRoamingState(0), -1);
    ImsRegInfo info;
    EXPECT_EQ(mInner.GetImsRegStatus(0, ImsServiceType::TYPE_VOICE, info), TELEPHONY_ERR_LOCAL_PTR_NULL);
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    sptr<INetworkSearchCallback> callback = nullptr;
    EXPECT_FALSE(mInner.SetNetworkSelectionMode(0, 1, networkInfo, true, callback));
    EXPECT_NE(mInner.SetRadioState(0, true, 0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetRadioState(0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetNetworkSearchInformation(0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetNetworkSelectionMode(0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetPreferredNetwork(0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.SetPreferredNetwork(0, 0, callback), TELEPHONY_ERR_SUCCESS);
    std::vector<sptr<SignalInformation>> signals;
    mInner.GetSignalInfoList(0, signals);
    EXPECT_EQ(signals, std::vector<sptr<SignalInformation>>());
    std::vector<sptr<CellInformation>> cellInfo;
    EXPECT_EQ(mInner.GetCellInfoList(0, cellInfo), TELEPHONY_ERR_LOCAL_PTR_NULL);
    ASSERT_TRUE(cellInfo.empty());
    EXPECT_EQ(mInner.GetOperatorNumeric(0), std::u16string());
    std::u16string operatorName = u"";
    EXPECT_NE(mInner.GetOperatorName(0, operatorName), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(operatorName, std::u16string());
    std::u16string countryCode = u"";
    EXPECT_NE(mInner.GetIsoCountryCodeForNetwork(0, countryCode), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(countryCode, std::u16string());
    std::u16string result = u"";
    EXPECT_NE(mInner.GetImei(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, std::u16string());
    EXPECT_NE(mInner.GetMeid(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, std::u16string());
    EXPECT_NE(mInner.GetUniqueDeviceId(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, std::u16string());
    sptr<NetworkState> networkState = nullptr;
    mInner.GetNetworkStatus(0, networkState);
    EXPECT_EQ(networkState, nullptr);
}

/**
 * @tc.number   Telephony_CoreManagerInner_004
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CoreManagerInner_004, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    EXPECT_EQ(mInner.ObtainSpnCondition(0, false, ""), 0);
    std::u16string result;
    EXPECT_GT(mInner.GetSimSpn(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetShowNumber(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetShowName(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetSimOperatorNumeric(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetISOCountryCodeForSim(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetSimIccId(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetIMSI(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mInner.GetLocaleFromDefaultSim(0), std::u16string());
    EXPECT_GT(mInner.GetSimGid1(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mInner.GetSimGid2(0), std::u16string());
    EXPECT_GT(mInner.GetSimTelephoneNumber(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mInner.GetSimTeleNumberIdentifier(0), std::u16string());
    EXPECT_GT(mInner.GetVoiceMailIdentifier(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetVoiceMailNumber(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mInner.GetSimIst(0), std::u16string());
    EXPECT_GT(mInner.SetVoiceMailInfo(0, u"", u""), TELEPHONY_ERR_SUCCESS);
    bool boolResult = false;
    EXPECT_GT(mInner.HasOperatorPrivileges(0, boolResult), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.HasSimCard(0, boolResult), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SendEnvelopeCmd(0, ""), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SendTerminalResponseCmd(0, ""), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SendTerminalResponseCmd(0, ""), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.DelSmsIcc(0, 0), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(mInner.IsSimActive(0));
    EXPECT_GT(mInner.SetShowName(0, u""), TELEPHONY_ERR_SUCCESS);
    LockStatusResponse response;
    PersoLockInfo lockInfo;
    EXPECT_GT(mInner.UnlockSimLock(0, lockInfo, response), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.UnlockPin(0, "", response), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.UnlockPuk(0, "", "", response), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.AlterPin(0, "", "", response), TELEPHONY_ERR_SUCCESS);
    LockInfo options;
    EXPECT_GT(mInner.SetLockState(0, options, response), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.UnlockPin2(0, "", response), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.UnlockPuk2(0, "", "", response), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.AlterPin2(0, "", "", response), TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<DiallingNumbersInfo> diallingNumbers = std::make_shared<DiallingNumbersInfo>();
    EXPECT_GT(mInner.AddIccDiallingNumbers(0, 0, diallingNumbers), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.DelIccDiallingNumbers(0, 0, diallingNumbers), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.UpdateIccDiallingNumbers(0, 0, diallingNumbers), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mInner.GetNrState(0), NrState::NR_STATE_NOT_SUPPORT);
    EXPECT_NE(mInner.SendUpdateCellLocationRequest(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(mInner.IsNrSupported(0));
}

/**
 * @tc.number   Telephony_CoreManagerInner_005
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CoreManagerInner_005, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    OperatorConfig mOperatorConfig;
    EXPECT_GT(mInner.GetOperatorConfigs(0, mOperatorConfig), TELEPHONY_ERR_SUCCESS);
    IccAccountInfo mIccAccountInfo;
    EXPECT_GT(mInner.GetSimAccountInfo(0, mIccAccountInfo), TELEPHONY_ERR_SUCCESS);
    std::vector<IccAccountInfo> iccAccountInfoList;
    EXPECT_GT(mInner.GetActiveSimAccountInfoList(iccAccountInfoList), TELEPHONY_ERR_SUCCESS);
    LockState lockState;
    EXPECT_NE(mInner.GetLockState(0, LockType::PIN_LOCK, lockState), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.SendCallSetupRequestResult(0, true), TELEPHONY_ERR_SUCCESS);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    EXPECT_NE(mInner.GetSimState(0, simState), TELEPHONY_ERR_SUCCESS);
    CardType cardType = CardType::UNKNOWN_CARD;
    EXPECT_NE(mInner.GetCardType(0, cardType), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mInner.RefreshSimState(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetSlotId(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetSimId(0), TELEPHONY_ERR_SUCCESS);
    mInner.SetDefaultCellularDataSlotId(0);
    mInner.SetDefaultSmsSlotId(0);
    mInner.SetDefaultVoiceSlotId(0);
    mInner.SetPrimarySlotId(0);
    std::u16string test = u"";
    EXPECT_NE(mInner.GetOpName(0, test), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetOpKeyExt(0, test), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetOpKey(test), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetOpKey(0, test), TELEPHONY_ERR_SUCCESS);
    mInner.GetDefaultVoiceSlotId();
    mInner.GetDefaultSmsSlotId();
    mInner.GetDefaultCellularDataSlotId();
    int32_t slotId = INVALID_VALUE;
    mInner.GetPrimarySlotId(slotId);
    int32_t dsdsMode = INVALID_VALUE;
    mInner.GetDsdsMode(dsdsMode);
    mInner.SetDsdsMode(0);
    EXPECT_NE(mInner.SaveImsSwitch(0, 0), TELEPHONY_ERR_SUCCESS);
    int32_t imsSwitchValue = 0;
    EXPECT_NE(mInner.SaveImsSwitch(0, imsSwitchValue), TELEPHONY_ERR_SUCCESS);
    std::vector<std::string> result;
    EXPECT_EQ(mInner.ObtainAllSmsOfIcc(0), result);
    std::string pduData = "test";
    std::string smsc = "test";
    EXPECT_GT(mInner.UpdateSmsIcc(0, 0, 0, pduData, smsc), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.AddSmsToIcc(0, 0, pduData, smsc), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreManagerInner_006
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CoreManagerInner_006, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    EXPECT_GT(mInner.GetClip(0, event), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetClip(0, 0, event), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetClir(0, event), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetClir(0, 0, event), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetCallWaiting(0, 0, event), TELEPHONY_ERR_SUCCESS);
    CallTransferParam mCallTransferParam;
    EXPECT_GT(mInner.SetCallTransferInfo(0, mCallTransferParam, event), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCallTransferInfo(0, 0, event), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCallWaiting(0, event), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCallRestriction(0, "", event), TELEPHONY_ERR_SUCCESS);
    CallRestrictionParam mCallRestrictionParam;
    EXPECT_GT(mInner.SetCallRestriction(0, mCallRestrictionParam, event), TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    sptr<NetworkSearchCallBackBase> callback = nullptr;
    mInner.RegisterCellularDataObject(callback);
    mInner.UnRegisterCellularDataObject(callback);
    mInner.RegisterCellularCallObject(callback);
    mInner.UnRegisterCellularCallObject(callback);
    EXPECT_EQ(mInner.RegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_NR_STATE_CHANGED, nullptr),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnRegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_NR_STATE_CHANGED),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.RegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_SIM_STATE_READY, nullptr),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnRegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_SIM_GET_RADIO_PROTOCOL),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.RegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_SIM_STATE_READY, nullptr),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnRegisterCoreNotify(INVALID_SLOTID, handler, RadioEvent::RADIO_SIM_GET_RADIO_PROTOCOL),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    std::string bundleName = "";
    sptr<SimAccountCallback> simAccountCallback;
    int32_t imsSwitchValue = 1;
    EXPECT_EQ(mInner.RegisterSimAccountCallback(bundleName, simAccountCallback), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.UnregisterSimAccountCallback(bundleName), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.GetSmscAddr(INVALID_SLOTID, 1, handler), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(mInner.QueryImsSwitch(INVALID_SLOTID, imsSwitchValue), TELEPHONY_ERROR);
    EXPECT_GT(mInner.SetVoNRSwitch(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_CoreManagerInner_007
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CoreManagerInner_007, Function | MediumTest | Level1)
{
    CoreManagerInner mInner;
    GsmSimMessageParam mGsmSimMessageParam;
    EXPECT_GT(mInner.SendGsmSms(0, 0, mGsmSimMessageParam, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SendSmsMoreMode(0, 0, mGsmSimMessageParam, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SendCdmaSms(0, 0, "", 0L, nullptr), TELEPHONY_ERR_SUCCESS);
    SimMessageParam mSimMessageParam;
    EXPECT_GT(mInner.AddSimMessage(0, 0, mSimMessageParam, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCdmaCBConfig(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetSmscAddr(0, 0, 0, "", nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.DelSimMessage(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SendSmsAck(0, 0, true, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetCBConfig(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    CBConfigParam mCBConfigParam;
    EXPECT_GT(mInner.SetCBConfig(0, 0, mCBConfigParam, nullptr), TELEPHONY_ERR_SUCCESS);
    CdmaCBConfigInfoList mCdmaCBConfigInfoList;
    EXPECT_GT(mInner.SetCdmaCBConfig(0, 0, mCdmaCBConfigInfoList, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetNetworkSearchInformation(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetNetworkSelectionMode(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.AddCdmaSimMessage(0, 0, 0, "", nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.DelCdmaSimMessage(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    CdmaSimMessageParam mCdmaSimMessageParam;
    EXPECT_GT(mInner.UpdateCdmaSimMessage(0, 0, mCdmaSimMessageParam, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.SetPreferredNetworkPara(0, 0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(mInner.GetPreferredNetworkPara(0, 0, nullptr), TELEPHONY_ERR_SUCCESS);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    EXPECT_GT(mInner.QueryIccDiallingNumbers(0, 0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mInner.GetCellLocation(0), nullptr);
    EXPECT_EQ(mInner.GetPhoneType(0), PhoneType::PHONE_TYPE_IS_NONE);
    NrMode mode = NrMode::NR_MODE_UNKNOWN;
    EXPECT_NE(mInner.GetNrOptionMode(0, mode), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mode, NrMode::NR_MODE_UNKNOWN);
    EXPECT_EQ(mInner.GetFrequencyType(0), FrequencyType::FREQ_TYPE_UNKNOWN);
}

/**
 * @tc.number   Telephony_TagService_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_TagService_001, Function | MediumTest | Level1)
{
    std::vector<uint8_t> parameter = {};
    std::string testEmptyStr = "";
    std::string testStr = "12345";
    std::string testCnStr = "123456";
    std::shared_ptr<TagService> tagService = std::make_shared<TagService>(testEmptyStr);
    std::shared_ptr<TagService> tagService1 = std::make_shared<TagService>(testStr);
    std::shared_ptr<TagService> tagService2 = std::make_shared<TagService>(testCnStr);
    EXPECT_NE(tagService->GetTagCode(), 1);
    EXPECT_NE(tagService1->GetTagCode(), 1);
    EXPECT_NE(tagService2->GetTagCode(), 1);
    EXPECT_FALSE(tagService->Next());
    EXPECT_FALSE(tagService1->Next());
    EXPECT_FALSE(tagService2->Next());
}

/**
 * @tc.number   Telephony_SimSmsController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimSmsController_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("SimSmsController");
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<Telephony::SimSmsController> simSmsController =
        std::make_shared<SimSmsController>(runner, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    auto eventGet = simSmsController->BuildCallerInfo(SIM_SMS_GET_COMPLETED);
    auto eventUpdate = simSmsController->BuildCallerInfo(SIM_SMS_UPDATE_COMPLETED);
    auto eventWrite = simSmsController->BuildCallerInfo(SIM_SMS_WRITE_COMPLETED);
    auto eventDelete = simSmsController->BuildCallerInfo(SIM_SMS_DELETE_COMPLETED);
    simSmsController->ProcessLoadDone(event);
    simSmsController->ProcessUpdateDone(event);
    simSmsController->ProcessWriteDone(event);
    simSmsController->ProcessDeleteDone(event);
    simSmsController->ProcessDeleteDone(event);
    simSmsController->ProcessEvent(event);
    simSmsController->ProcessEvent(eventGet);
    simSmsController->ProcessEvent(eventUpdate);
    simSmsController->ProcessEvent(eventWrite);
    simSmsController->ProcessEvent(eventDelete);
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(runner, telRilManager, simStateManager);
    simSmsController->SetRilAndFileManager(telRilManager, simFileManager);
    simFileManager = nullptr;
    simSmsController->SetRilAndFileManager(telRilManager, simFileManager);
    telRilManager = nullptr;
    simSmsController->SetRilAndFileManager(telRilManager, simFileManager);
    std::string smsc = "";
    std::string pdu = "";
    EXPECT_FALSE(simSmsController->IsCdmaCardType());
}

/**
 * @tc.number   Telephony_MultiSimController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_MultiSimController_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("MultiSimController");
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager, runner);
    multiSimController->SortCache();
    std::shared_ptr<RadioProtocolController> radioProtocolController = nullptr;
    EXPECT_FALSE(multiSimController->InitData(0));
    EXPECT_GT(multiSimController->SetDefaultSmsSlotId(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(multiSimController->RefreshActiveIccAccountInfoList());
    EXPECT_FALSE(multiSimController->IsSimActive(0));
    EXPECT_FALSE(multiSimController->IsSimActivatable(0));
    EXPECT_FALSE(multiSimController->ForgetAllData());
    EXPECT_FALSE(multiSimController->ForgetAllData(0));
    EXPECT_FALSE(multiSimController->IsValidData(0));
    EXPECT_TRUE(multiSimController->AnnounceDefaultMainSimIdChanged(0));
    EXPECT_TRUE(multiSimController->AnnounceDefaultVoiceSimIdChanged(0));
    EXPECT_TRUE(multiSimController->AnnounceDefaultSmsSimIdChanged(0));
    EXPECT_TRUE(multiSimController->AnnounceDefaultCellularDataSimIdChanged(0));
    AAFwk::Want want;
    EXPECT_FALSE(multiSimController->PublishSimFileEvent(want, 0, ""));
    EXPECT_FALSE(multiSimController->InitShowName(0));
    EXPECT_FALSE(multiSimController->InitShowNumber(0));
    EXPECT_FALSE(multiSimController->InitIccId(0));
    EXPECT_FALSE(multiSimController->GetListFromDataBase());
    EXPECT_FALSE(multiSimController->SetIccId(0, u""));
}

/**
 * @tc.number   Telephony_MultiSimController_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_MultiSimController_002, Function | MediumTest | Level1)
{
    std::u16string testU16Str = u"";
    std::string testStr = "";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("MultiSimController");
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager, runner);
    multiSimController->GetDefaultVoiceSlotId();
    EXPECT_NE(multiSimController->SetDefaultVoiceSlotId(0), TELEPHONY_ERR_SUCCESS);
    multiSimController->GetDefaultSmsSlotId();
    IccAccountInfo mIccAccountInfo;
    EXPECT_NE(multiSimController->GetSimAccountInfo(0, false, mIccAccountInfo), TELEPHONY_ERR_SUCCESS);
    multiSimController->GetDefaultCellularDataSlotId();
    EXPECT_NE(multiSimController->SetDefaultCellularDataSlotId(0), TELEPHONY_ERR_SUCCESS);
    multiSimController->GetPrimarySlotId();
    multiSimController->SetPrimarySlotId(0);
    EXPECT_NE(multiSimController->GetShowNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->SetShowNumber(0, testU16Str, false), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->GetShowName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->SetShowName(0, testU16Str, false), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->SetActiveSim(0, 1, false), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->GetSlotId(1), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->SaveImsSwitch(0, 1), TELEPHONY_ERR_SUCCESS);
    int32_t imsSwitchValue;
    EXPECT_NE(multiSimController->QueryImsSwitch(0, imsSwitchValue), TELEPHONY_ERR_SUCCESS);
    std::vector<IccAccountInfo> iccAccountInfoList = {};
    EXPECT_NE(multiSimController->GetActiveSimAccountInfoList(false, iccAccountInfoList), TELEPHONY_ERR_SUCCESS);
    multiSimController->radioProtocolController_ = nullptr;
    EXPECT_NE(multiSimController->GetRadioProtocolTech(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->GetFirstActivedSlotId(), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->UpdateDataByIccId(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(multiSimController->InsertData(0, testStr), TELEPHONY_ERR_SUCCESS);
    multiSimController->GetDefaultCellularDataSlotIdUnit();
    EXPECT_EQ(multiSimController->GetIccId(0), u"");
}

/**
 * @tc.number   Telephony_SimManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    simManager->SetNetworkSearchManager(nullptr);
    std::u16string testStr = u"";
    EXPECT_GT(simManager->SetShowNumber(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SetShowNumber(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimOperatorNumeric(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimOperatorNumeric(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    bool boolResult = false;
    EXPECT_GT(simManager->HasSimCard(0, boolResult), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->HasSimCard(INVALID_SLOTID, boolResult), TELEPHONY_ERR_SUCCESS);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    EXPECT_GE(simManager->GetSimState(0, simState), TELEPHONY_ERR_SUCCESS);
    EXPECT_GE(simManager->GetSimState(INVALID_SLOTID, simState), TELEPHONY_ERR_SUCCESS);
    CardType cardType = CardType::UNKNOWN_CARD;
    EXPECT_NE(simManager->GetCardType(0, cardType), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetCardType(INVALID_SLOTID, cardType), TELEPHONY_ERR_SUCCESS);
    LockType mLockType = LockType::PIN_LOCK;
    LockState lockState;
    EXPECT_NE(simManager->GetLockState(0, mLockType, lockState), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetLockState(INVALID_SLOTID, mLockType, lockState), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->RefreshSimState(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->RefreshSimState(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_SimManager_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimManager_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    std::u16string testStr = u"";
    EXPECT_GT(simManager->GetISOCountryCodeForSim(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetISOCountryCodeForSim(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SetShowName(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SetShowName(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimSpn(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimSpn(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    std::u16string result = u"";
    EXPECT_GT(simManager->GetSimIccId(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimIccId(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetIMSI(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetIMSI(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simManager->GetLocaleFromDefaultSim(0), testStr);
    EXPECT_EQ(simManager->GetLocaleFromDefaultSim(INVALID_SLOTID), testStr);
    EXPECT_GT(simManager->GetSimGid1(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimGid1(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simManager->GetSimGid2(0), testStr);
    EXPECT_EQ(simManager->GetSimGid2(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetSimEons(0, "46001", 1, true), testStr);
    EXPECT_EQ(simManager->GetSimEons(INVALID_SLOTID, "46001", 1, true), testStr);
    EXPECT_GT(simManager->GetShowNumber(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetShowNumber(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetShowName(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetShowName(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimTelephoneNumber(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimTelephoneNumber(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simManager->GetSimTeleNumberIdentifier(0), testStr);
    EXPECT_EQ(simManager->GetSimTeleNumberIdentifier(INVALID_SLOTID), testStr);
    EXPECT_GT(simManager->GetVoiceMailIdentifier(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetVoiceMailIdentifier(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetVoiceMailNumber(0, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetVoiceMailNumber(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(simManager->GetSimIst(0), testStr);
    EXPECT_EQ(simManager->GetSimIst(INVALID_SLOTID), testStr);
    EXPECT_NE(simManager->GetOpName(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpName(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpKey(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpKey(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpKeyExt(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpKeyExt(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SetVoiceMailInfo(0, testStr, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SetVoiceMailInfo(INVALID_SLOTID, testStr, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SetActiveSim(0, 1), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SetActiveSim(INVALID_SLOTID, 1), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_SimManager_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimManager_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    simManager->SetDefaultVoiceSlotId(0);
    simManager->SetDefaultVoiceSlotId(INVALID_SLOTID);
    simManager->SetDefaultSmsSlotId(0);
    simManager->SetDefaultSmsSlotId(INVALID_SLOTID);
    simManager->SetDefaultCellularDataSlotId(0);
    simManager->SetDefaultCellularDataSlotId(INVALID_SLOTID);
    simManager->SetPrimarySlotId(0);
    simManager->SetPrimarySlotId(INVALID_SLOTID);
    simManager->GetDefaultVoiceSlotId();
    simManager->GetDefaultSmsSlotId();
    simManager->GetDefaultCellularDataSlotId();
    int32_t slotId = INVALID_VALUE;
    simManager->GetPrimarySlotId(slotId);
    EXPECT_NE(simManager->GetSlotId(1), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetSimId(0), TELEPHONY_ERR_SUCCESS);
    std::vector<IccAccountInfo> iccAccountInfoList;
    EXPECT_GT(simManager->GetActiveSimAccountInfoList(false, iccAccountInfoList), TELEPHONY_ERR_SUCCESS);
    OperatorConfig mOperatorConfig;
    EXPECT_GT(simManager->GetOperatorConfigs(0, mOperatorConfig), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetOperatorConfigs(INVALID_SLOTID, mOperatorConfig), TELEPHONY_ERR_SUCCESS);
    bool boolResult = false;
    EXPECT_GT(simManager->HasOperatorPrivileges(0, boolResult), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->HasOperatorPrivileges(INVALID_SLOTID, boolResult), TELEPHONY_ERR_SUCCESS);
    int32_t testRadioProtocolTech = static_cast<int32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_UNKNOWN);
    EXPECT_EQ(simManager->GetRadioProtocolTech(0), testRadioProtocolTech);
    EXPECT_EQ(simManager->GetRadioProtocolTech(INVALID_SLOTID), testRadioProtocolTech);
    EXPECT_GT(simManager->SendEnvelopeCmd(0, ""), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SendEnvelopeCmd(INVALID_SLOTID, ""), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SendTerminalResponseCmd(0, ""), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SendTerminalResponseCmd(INVALID_SLOTID, ""), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->SendCallSetupRequestResult(0, true), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->SendCallSetupRequestResult(INVALID_SLOTID, true), TELEPHONY_ERR_SUCCESS);
    std::string testAddress = "";
    EXPECT_GT(simManager->AddSmsToIcc(0, 1, testAddress, testAddress), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->AddSmsToIcc(INVALID_SLOTID, 1, testAddress, testAddress), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UpdateSmsIcc(0, 1, 1, testAddress, testAddress), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UpdateSmsIcc(INVALID_SLOTID, 1, 1, testAddress, testAddress), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->DelSmsIcc(0, 1), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->DelSmsIcc(INVALID_SLOTID, 1), TELEPHONY_ERR_SUCCESS);
    std::vector<std::string> result;
    EXPECT_EQ(simManager->ObtainAllSmsOfIcc(0), result);
    EXPECT_EQ(simManager->ObtainAllSmsOfIcc(INVALID_SLOTID), result);
}

/**
 * @tc.number   Telephony_SimManager_004
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimManager_004, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> list;
    EXPECT_GT(simManager->QueryIccDiallingNumbers(0, 1, list), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->QueryIccDiallingNumbers(INVALID_SLOTID, 1, list), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->AddIccDiallingNumbers(0, 1, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->AddIccDiallingNumbers(INVALID_SLOTID, 1, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->DelIccDiallingNumbers(0, 1, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->DelIccDiallingNumbers(INVALID_SLOTID, 1, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UpdateIccDiallingNumbers(0, 1, nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UpdateIccDiallingNumbers(INVALID_SLOTID, 1, nullptr), TELEPHONY_ERR_SUCCESS);
    simManager->RegisterCoreNotify(0, nullptr, 1);
    simManager->RegisterCoreNotify(INVALID_SLOTID, nullptr, 1);
    simManager->UnRegisterCoreNotify(0, nullptr, 1);
    simManager->UnRegisterCoreNotify(INVALID_SLOTID, nullptr, 1);
    EXPECT_NE(simManager->SaveImsSwitch(0, 1), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->SaveImsSwitch(INVALID_SLOTID, 1), TELEPHONY_ERR_SUCCESS);
    int32_t imsSwitchValue;
    EXPECT_NE(simManager->QueryImsSwitch(0, imsSwitchValue), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->QueryImsSwitch(INVALID_SLOTID, imsSwitchValue), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->RegisterSimAccountCallback("", nullptr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->UnregisterSimAccountCallback(""), TELEPHONY_ERR_SUCCESS);
    int32_t dsdsMode = INVALID_VALUE;
    simManager->GetDsdsMode(dsdsMode);
    simManager->SetDsdsMode(0);
    std::string testString = "";
    EXPECT_NE(simManager->ObtainSpnCondition(0, true, testString), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->ObtainSpnCondition(INVALID_SLOTID, true, testString), TELEPHONY_ERR_SUCCESS);
    SimAuthenticationResponse mResponse;
    EXPECT_NE(simManager->SimAuthentication(0, static_cast<AuthType>(0), "", mResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(
        simManager->SimAuthentication(INVALID_SLOTID, static_cast<AuthType>(0), "", mResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->SimAuthentication(0, AuthType::SIM_AUTH_EAP_SIM_TYPE, "", mResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->SimAuthentication(INVALID_SLOTID, AuthType::SIM_AUTH_EAP_SIM_TYPE, "", mResponse),
        TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_SimManager_005
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimManager_005, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    simManager->SetNetworkSearchManager(nullptr);
    std::string password = "1234";
    LockStatusResponse mLockStatusResponse;
    EXPECT_GT(simManager->UnlockPin(0, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UnlockPin(INVALID_SLOTID, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UnlockPuk(0, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UnlockPuk(INVALID_SLOTID, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->AlterPin(0, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->AlterPin(INVALID_SLOTID, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    LockInfo mLockInfo;
    EXPECT_GT(simManager->SetLockState(0, mLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->SetLockState(INVALID_SLOTID, mLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UnlockPin2(0, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UnlockPin2(INVALID_SLOTID, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UnlockPuk2(0, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UnlockPuk2(INVALID_SLOTID, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->AlterPin2(0, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->AlterPin2(INVALID_SLOTID, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    PersoLockInfo mPersoLockInfo;
    EXPECT_GT(simManager->UnlockSimLock(0, mPersoLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->UnlockSimLock(INVALID_SLOTID, mPersoLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(simManager->IsSimActive(0));
    EXPECT_FALSE(simManager->IsSimActive(INVALID_SLOTID));
    IccAccountInfo mIccAccountInfo;
    EXPECT_GT(simManager->GetSimAccountInfo(0, false, mIccAccountInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simManager->GetSimAccountInfo(INVALID_SLOTID, false, mIccAccountInfo), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_SimStateManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimStateManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    simStateManager->RegisterCoreNotify(nullptr, 1);
    simStateManager->UnRegisterCoreNotify(nullptr, 1);
    EXPECT_FALSE(simStateManager->HasSimCard());
    std::string password = "1234";
    LockStatusResponse mLockStatusResponse;
    EXPECT_GT(simStateManager->UnlockPin(0, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simStateManager->UnlockPuk(0, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simStateManager->AlterPin(0, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    LockInfo mLockInfo;
    EXPECT_GT(simStateManager->SetLockState(0, mLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    mLockInfo.lockType = LockType::PIN_LOCK;
    mLockInfo.lockState = LockState::LOCK_ERROR;
    EXPECT_GT(simStateManager->SetLockState(0, mLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    mLockInfo.lockState = LockState::LOCK_ON;
    EXPECT_GT(simStateManager->SetLockState(0, mLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    LockInfo testLockInfo;
    LockState lockState;
    EXPECT_GT(simStateManager->GetLockState(0, testLockInfo.lockType, lockState), TELEPHONY_ERR_SUCCESS);
    LockType lockType = LockType::PIN_LOCK;
    EXPECT_GT(simStateManager->GetLockState(0, lockType, lockState), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simStateManager->UnlockPin2(0, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simStateManager->UnlockPuk2(0, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(simStateManager->AlterPin2(0, password, password, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    PersoLockInfo mPersoLockInfo;
    EXPECT_GT(simStateManager->UnlockSimLock(0, mPersoLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    SimAuthenticationResponse mResponse;
    EXPECT_NE(
        simStateManager->SimAuthentication(0, AuthType::SIM_AUTH_EAP_SIM_TYPE, "", mResponse), TELEPHONY_ERR_SUCCESS);
    auto simStateManagerTwo = std::make_shared<SimStateManager>(telRilManager);
    simStateManager->simStateHandle_ = std::make_shared<SimStateHandle>(runner, simStateManagerTwo);
    EXPECT_GE(simStateManager->GetCardType(), CardType::UNKNOWN_CARD);
    EXPECT_GT(simStateManager->UnlockSimLock(0, mPersoLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_SimStateHandle_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimStateHandle_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    auto simStateHandle = std::make_shared<SimStateHandle>(runner, simStateManager);
    EXPECT_EQ(simStateHandle->GetAidByCardType(CardType::SINGLE_MODE_RUIM_CARD), CDMA_FAKE_AID);
    EXPECT_EQ(simStateHandle->GetAidByCardType(CardType::SINGLE_MODE_SIM_CARD), GSM_FAKE_AID);
    EXPECT_EQ(simStateHandle->GetAidByCardType(CardType::DUAL_MODE_CG_CARD), GSM_FAKE_AID);
    EXPECT_EQ(simStateHandle->GetAidByCardType(CardType::CT_NATIONAL_ROAMING_CARD), GSM_FAKE_AID);
    EXPECT_EQ(simStateHandle->GetAidByCardType(CardType::CU_DUAL_MODE_CARD), GSM_FAKE_AID);
    EXPECT_EQ(simStateHandle->GetAidByCardType(CardType::DUAL_MODE_TELECOM_LTE_CARD), GSM_FAKE_AID);
    EXPECT_EQ(simStateHandle->GetAidByCardType(CardType::DUAL_MODE_UG_CARD), GSM_FAKE_AID);
    EXPECT_EQ(simStateHandle->GetAidByCardType(CardType::UNKNOWN_CARD), USIM_AID);
}

/**
 * @tc.number   Telephony_NetworkRegister_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_NetworkRegister_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0, 1);
    networkRegister->ProcessPsRegister(event);
    networkRegister->ProcessCsRegister(event);
    networkRegister->ProcessChannelConfigInfo(event);
    networkRegister->NotifyNrFrequencyChanged();
    event = nullptr;
    networkRegister->ProcessPsRegister(event);
    networkRegister->ProcessCsRegister(event);
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
HWTEST_F(BranchTest, Telephony_NetworkRegister_002, Function | MediumTest | Level1)
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
}

/**
 * @tc.number   Telephony_NetworkRegister_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_NetworkRegister_003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, INVALID_SLOTID);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_GSM), RadioTech::RADIO_TECHNOLOGY_GSM);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_1XRTT), RadioTech::RADIO_TECHNOLOGY_1XRTT);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_HSPA), RadioTech::RADIO_TECHNOLOGY_HSPA);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_HSPAP), RadioTech::RADIO_TECHNOLOGY_HSPAP);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_NR), RadioTech::RADIO_TECHNOLOGY_NR);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_WCDMA), RadioTech::RADIO_TECHNOLOGY_WCDMA);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_LTE), RadioTech::RADIO_TECHNOLOGY_LTE);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_EVDO), RadioTech::RADIO_TECHNOLOGY_EVDO);
    EXPECT_EQ(
        networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_EHRPD), RadioTech::RADIO_TECHNOLOGY_EHRPD);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_TD_SCDMA),
        RadioTech::RADIO_TECHNOLOGY_TD_SCDMA);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_LTE_CA),
        RadioTech::RADIO_TECHNOLOGY_LTE_CA);
    EXPECT_EQ(networkRegister->ConvertTechFromRil(HRilRadioTech::RADIO_TECHNOLOGY_INVALID),
        RadioTech::RADIO_TECHNOLOGY_UNKNOWN);
}

/**
 * @tc.number   Telephony_OperatorName_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_OperatorName_001, Function | MediumTest | Level1)
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
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0, 1);
    std::string plmn = "";
    bool showPlmn = true;
    std::string numeric = "qwe";
    std::vector<std::string> pnnCust;
    sptr<NetworkState> networkState;
    operatorName->NotifyGsmSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState);
    operatorName->NotifyCdmaSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState);
    operatorName->UpdateOperatorConfig();
    operatorName->UpdatePnnCust(pnnCust);
    operatorName->UpdateOplCust(pnnCust);
    EXPECT_EQ(operatorName->GetPlmn(networkState, true), "");
    networkState = new NetworkState;
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_IN_SERVICE, networkState, 1, plmn, showPlmn);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_NO_SERVICE, networkState, 1, plmn, showPlmn);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_EMERGENCY_ONLY, networkState, 1, plmn, showPlmn);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_SEARCH, networkState, 1, plmn, showPlmn);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_UNKNOWN, networkState, 1, plmn, showPlmn);
    operatorName->UpdatePlmn(RegServiceState::REG_STATE_POWER_OFF, networkState, 1, plmn, showPlmn);
    operatorName->UpdateSpn(RegServiceState::REG_STATE_IN_SERVICE, networkState, 1, plmn, showPlmn);
    operatorName->NotifyGsmSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState);
    operatorName->NotifyCdmaSpnChanged(RegServiceState::REG_STATE_IN_SERVICE, networkState);
    operatorName->GsmOperatorInfo(event);
    operatorName->HandleOperatorInfo(event);
    operatorName->NotifySpnChanged();
    operatorName->CdmaOperatorInfo(event);
    event = nullptr;
    operatorName->GsmOperatorInfo(event);
    operatorName->CdmaOperatorInfo(event);
    EXPECT_EQ(operatorName->GetCurrentLac(), 0);
    EXPECT_TRUE(operatorName->GetNetworkStatus() == nullptr);
    EXPECT_EQ(operatorName->GetCustomName(plmn), "");
    EXPECT_EQ(operatorName->GetCustomName(numeric), "");
    EXPECT_EQ(operatorName->GetCustSpnRule(true), 0);
    operatorName->displayConditionCust_ = 1;
    EXPECT_NE(operatorName->GetCustSpnRule(true), 0);
    operatorName->simManager_ = nullptr;
    EXPECT_EQ(operatorName->GetEons(plmn, 1, true), "");
}

/**
 * @tc.number   Telephony_NetworkSearchState_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_NetworkSearchState_001, Function | MediumTest | Level1)
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
HWTEST_F(BranchTest, Telephony_NetworkSearchManager_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    sptr<NetworkInformation> networkInfo = nullptr;
    ImsRegInfo info;
    std::u16string testStr = u"";
    sptr<INetworkSearchCallback> networkSearchCallback = nullptr;
    networkSearchManager->SetRadioState(INVALID_SLOTID, true, 1);
    EXPECT_EQ(networkSearchManager->GetRadioState(INVALID_SLOTID), ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE);
    EXPECT_NE(networkSearchManager->GetNetworkSearchInformation(INVALID_SLOTID, networkSearchCallback),
        TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(networkSearchManager->SetNetworkSelectionMode(INVALID_SLOTID, 1, networkInfo, true));
    EXPECT_NE(networkSearchManager->GetPreferredNetwork(INVALID_SLOTID, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(
        networkSearchManager->SetPreferredNetwork(INVALID_SLOTID, 1, networkSearchCallback), TELEPHONY_ERR_SUCCESS);
    std::u16string result = u"";
    EXPECT_NE(networkSearchManager->GetIsoCountryCodeForNetwork(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    EXPECT_NE(networkSearchManager->GetImei(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    EXPECT_EQ(networkSearchManager->GetImsRegStatus(INVALID_SLOTID, ImsServiceType::TYPE_SMS, info),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(networkSearchManager->GetUniqueDeviceId(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
    EXPECT_NE(networkSearchManager->GetMeid(INVALID_SLOTID, result), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(result, testStr);
}

/**
 * @tc.number   Telephony_NetworkSearchManager_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_NetworkSearchManager_002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(runner, networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->networkSearchState_ = networkSearchState;
    inner->observerHandler_ = std::make_unique<ObserverHandler>();
    inner->networkSearchHandler_ = networkSearchHandler;
    std::string bundleName = "qwe";
    std::u16string imei = u"";
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
    networkSearchManager->UpdateCellLocation(INVALID_SLOTID, 1, 1, 1);
    networkSearchManager->SetMeid(INVALID_SLOTID, imei);
    networkSearchManager->SetNrOptionMode(INVALID_SLOTID, NrMode::NR_MODE_UNKNOWN);
    networkSearchManager->SetFrequencyType(INVALID_SLOTID, FrequencyType::FREQ_TYPE_MMWAVE);
    networkSearchManager->SetRadioFirstPowerOn(INVALID_SLOTID, true);
    networkSearchManager->SetLocalAirplaneMode(INVALID_SLOTID, true);
    bool state = false;
    networkSearchManager->GetLocalAirplaneMode(INVALID_SLOTID, state);
    EXPECT_TRUE(networkSearchManager->GetNetworkSearchInformationValue(INVALID_SLOTID) == nullptr);
    EXPECT_TRUE(networkSearchManager->GetNetworkSearchState(INVALID_SLOTID) != nullptr);
    EXPECT_TRUE(networkSearchManager->IsRadioFirstPowerOn(INVALID_SLOTID));
    EXPECT_EQ(networkSearchManager->RegisterImsRegInfoCallback(
                  INVALID_SLOTID, ImsServiceType::TYPE_SMS, bundleName, callback),
        TELEPHONY_ERR_ARGUMENT_NULL);
    EXPECT_EQ(networkSearchManager->UnregisterImsRegInfoCallback(INVALID_SLOTID, ImsServiceType::TYPE_SMS, bundleName),
        TELEPHONY_SUCCESS);
}

/**
 * @tc.number   Telephony_NetworkSearchManager_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_NetworkSearchManager_003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(runner, networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
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
    EXPECT_EQ(mode, NrMode::NR_MODE_UNKNOWN);
}

/**
 * @tc.number   Telephony_NetworkSearchManager_004
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_NetworkSearchManager_004, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(runner, networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
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
    EXPECT_EQ(networkSearchManager->SetNetworkCapability(INVALID_SLOTID, networkAbilityType, networkAbilityState),
        TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_NetworkSearchHandler_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_NetworkSearchHandler_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(runner, networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
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
HWTEST_F(BranchTest, Telephony_NetworkSearchHandler_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(runner, networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
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
    networkSearchHandler->RadioGetRrcConnectionState(event);
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
    networkSearchHandler->HandleRrcStateChanged(1);
    networkSearchHandler->RadioGetRrcConnectionState(event);
    EXPECT_EQ(networkSearchHandler->GetPhoneType(), PhoneType::PHONE_TYPE_IS_NONE);
}

/**
 * @tc.number   Telephony_SimFileController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimFileController_001, Function | MediumTest | Level1)
{
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto simFileController = std::make_shared<SimFileController>(runner, INVALID_SLOTID);
    EXPECT_EQ(simFileController->ObtainElementFilePath(0), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_SMS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_VOICE_MAIL_INDICATOR_CPHS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_CFF_CPHS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_SPN_CPHS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_INFO_CPHS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_MAILBOX_CPHS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_SPN_SHORT_CPHS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_SST), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_GID1), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_GID2), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_SPN), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_AD), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_PNN), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_MBDN), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_EXT6), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_MBI), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_MWIS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_CFIS), "");
    EXPECT_NE(simFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSP_CPHS), "");
}

/**
 * @tc.number   Telephony_CsimFileController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CsimFileController_001, Function | MediumTest | Level1)
{
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto csimFileController = std::make_shared<CsimFileController>(runner, INVALID_SLOTID);
    EXPECT_NE(csimFileController->ObtainElementFilePath(0), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SMS), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CST), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_FDN), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_MSISDN), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_RUIM_SPN), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_LI), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_MDN), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_IMSIM), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_CDMAHOME), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_EPRL), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_MIPUPP), "");
    EXPECT_NE(csimFileController->ObtainElementFilePath(ELEMENTARY_FILE_PCSCF), "");
}

/**
 * @tc.number   Telephony_RuimFileController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_RuimFileController_001, Function | MediumTest | Level1)
{
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto rUimFileController = std::make_shared<RuimFileController>(runner, INVALID_SLOTID);
    EXPECT_EQ(rUimFileController->ObtainElementFilePath(0), "");
    EXPECT_NE(rUimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SMS), "");
    EXPECT_NE(rUimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CST), "");
    EXPECT_NE(rUimFileController->ObtainElementFilePath(ELEMENTARY_FILE_RUIM_SPN), "");
    EXPECT_NE(rUimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_LI), "");
    EXPECT_NE(rUimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_MDN), "");
    EXPECT_NE(rUimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_IMSIM), "");
    EXPECT_NE(rUimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_CDMAHOME), "");
    EXPECT_NE(rUimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSIM_EPRL), "");
}

/**
 * @tc.number   Telephony_IsimFileController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_IsimFileController_001, Function | MediumTest | Level1)
{
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto iSimFileController = std::make_shared<IsimFileController>(runner, INVALID_SLOTID);
    EXPECT_EQ(iSimFileController->ObtainElementFilePath(0), "");
    EXPECT_NE(iSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_IMPI), "");
    EXPECT_NE(iSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_IMPU), "");
    EXPECT_NE(iSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_DOMAIN), "");
    EXPECT_NE(iSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_IST), "");
    EXPECT_NE(iSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_PCSCF), "");
}

/**
 * @tc.number   Telephony_UsimFileController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_UsimFileController_001, Function | MediumTest | Level1)
{
    auto runner = AppExecFwk::EventRunner::Create("test");
    auto uSimFileController = std::make_shared<UsimFileController>(runner, INVALID_SLOTID);
    EXPECT_NE(uSimFileController->ObtainElementFilePath(0), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_IMPI), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SMS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_EXT5), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_EXT6), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_MWIS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_MBI), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SPN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_AD), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_MBDN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_PNN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_OPL), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_OPL5G), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SPDI), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SST), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CFIS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_MAILBOX_CPHS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_VOICE_MAIL_INDICATOR_CPHS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CFF_CPHS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SPN_CPHS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SPN_SHORT_CPHS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_FDN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_SDN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_EXT3), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_MSISDN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_EXT2), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_INFO_CPHS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_CSP_CPHS), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_GID1), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_GID2), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_LI), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_PLMN_W_ACT), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_OPLMN_W_ACT), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_HPLMN_W_ACT), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_EHPLMN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_FPLMN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_LRPLMNSI), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_HPPLMN), "");
    EXPECT_NE(uSimFileController->ObtainElementFilePath(ELEMENTARY_FILE_PBR), "");
}

/**
 * @tc.number   Telephony_RadioProtocolController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_RadioProtocolController_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(INVALID_SLOTID, 1);
    auto radioProtocolController = std::make_shared<RadioProtocolController>(telRilManager, runner);
    radioProtocolController->UnRegisterEvents();
    radioProtocolController->ProcessGetRadioProtocol(event);
    radioProtocolController->ProcessCheckRadioProtocol(event);
    radioProtocolController->ProcessSetRadioProtocolComplete(event);
    radioProtocolController->communicatingSlotCount_ = 1;
    radioProtocolController->ProcessCheckRadioProtocol(event);
    radioProtocolController->communicatingSlotCount_ = true;
    radioProtocolController->ProcessCheckRadioProtocol(event);
    radioProtocolController->ProcessRadioProtocolNotify(event);
    radioProtocolController->ProcessSetRadioProtocolTimeout(event);
    radioProtocolController->ProcessActiveSimToRilResponse(event);
    event = nullptr;
    radioProtocolController->ProcessEvent(event);
    radioProtocolController->ProcessGetRadioProtocol(event);
    radioProtocolController->ProcessCheckRadioProtocol(event);
    radioProtocolController->ProcessUpdateRadioProtocol(event);
    radioProtocolController->ProcessRadioProtocolNotify(event);
    radioProtocolController->ProcessSetRadioProtocolComplete(event);
    radioProtocolController->ProcessSetRadioProtocolTimeout(event);
    radioProtocolController->ProcessActiveSimToRilResponse(event);
    radioProtocolController->BuildRadioProtocolForCommunication(
        RadioProtocolPhase::RADIO_PROTOCOL_PHASE_CHECK, RadioProtocolStatus::RADIO_PROTOCOL_STATUS_FAIL);
    radioProtocolController->BuildRadioProtocolForCommunication(
        RadioProtocolPhase::RADIO_PROTOCOL_PHASE_COMPLETE, RadioProtocolStatus::RADIO_PROTOCOL_STATUS_FAIL);
    radioProtocolController->BuildRadioProtocolForCommunication(
        RadioProtocolPhase::RADIO_PROTOCOL_PHASE_INITIAL, RadioProtocolStatus::RADIO_PROTOCOL_STATUS_FAIL);
    radioProtocolController->BuildRadioProtocolForCommunication(
        RadioProtocolPhase::RADIO_PROTOCOL_PHASE_NOTIFY, RadioProtocolStatus::RADIO_PROTOCOL_STATUS_FAIL);
    radioProtocolController->BuildRadioProtocolForCommunication(
        RadioProtocolPhase::RADIO_PROTOCOL_PHASE_UPDATE, RadioProtocolStatus::RADIO_PROTOCOL_STATUS_FAIL);
    EXPECT_TRUE(radioProtocolController->RadioProtocolControllerPoll());
    EXPECT_FALSE(radioProtocolController->SetRadioProtocol(INVALID_SLOTID));
    radioProtocolController->isCommunicating_ = true;
    EXPECT_FALSE(radioProtocolController->SetRadioProtocol(INVALID_SLOTID));
    radioProtocolController->telRilManager_ = nullptr;
    std::vector<RadioProtocol> radioProtocol;
    radioProtocolController->SendRadioProtocolEvent(radioProtocol, 1);
    radioProtocolController->UnRegisterEvents();
    radioProtocolController->GetRadioProtocol(INVALID_SLOTID);
    EXPECT_FALSE(radioProtocolController->SetActiveSimToRil(INVALID_SLOTID, 1, 1));
}

/**
 * @tc.number   Telephony_StkController_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_StkController_001, Function | MediumTest | Level1)
{
    std::string name = "StkController_";
    auto stkEventLoop = AppExecFwk::EventRunner::Create(name.c_str());
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_CALL_SETUP, 1);
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto stkController = std::make_shared<StkController>(stkEventLoop, telRilManager, simStateManager, INVALID_SLOTID);
    std::string strCmd = "";
    stkController->UnRegisterEvents();
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_IS_READY, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SESSION_END, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_PROACTIVE_COMMAND, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_ALPHA_NOTIFY, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_EVENT_NOTIFY, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_ICC_REFRESH, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_TERMINAL_RESPONSE, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_ENVELOPE, 1);
    stkController->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_CALL_SETUP_REQUEST_RESULT, 1);
    stkController->ProcessEvent(event);
    event = nullptr;
    stkController->ProcessEvent(event);
    EXPECT_EQ(stkController->SendCallSetupRequestResult(true), TELEPHONY_ERR_FAIL);
    EXPECT_GT(stkController->SendTerminalResponseCmd(strCmd), TELEPHONY_ERR_SUCCESS);
    EXPECT_GT(stkController->SendEnvelopeCmd(strCmd), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_IccOperatorRule_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_IccOperatorRule_001, Function | MediumTest | Level1)
{
    auto iccOperatorRule = std::make_shared<IccOperatorRule>();
    auto operatorMatchingRule = std::make_shared<OperatorMatchingRule>();
    std::string numIt = "123";
    IccOperatorRule result;
    std::string::const_iterator hexStrBeg = numIt.begin();
    std::string::const_iterator hexStrEnd = numIt.begin();
    std::vector<IccOperatorRule> list;
    std::string_view certHash;
    std::string_view packageName;
    std::string hexStr = "12";
    std::string iccidFromSim = "";
    std::string iccidRegex = "";
    int32_t len = 1;
    EXPECT_FALSE(iccOperatorRule->DecodeTLVTagRule(hexStrBeg, hexStrEnd, result, len));
    EXPECT_FALSE(iccOperatorRule->DecodeTLVTagCertPkg(hexStrBeg, hexStrEnd, result));
    EXPECT_FALSE(iccOperatorRule->DecodeTLVTagLimits(hexStrBeg, hexStrEnd, result));
    EXPECT_FALSE(iccOperatorRule->CreateFromTLV(hexStrBeg, hexStrEnd, list));
    EXPECT_FALSE(iccOperatorRule->CreateFromTLV(numIt, list));
    EXPECT_TRUE(iccOperatorRule->Matche(certHash, packageName));
    EXPECT_TRUE(iccOperatorRule->SetPackageNameByHexStr(hexStr));
    EXPECT_FALSE(operatorMatchingRule->IccidRegexMatch(iccidFromSim, iccidRegex));
    EXPECT_FALSE(operatorMatchingRule->ImsiRegexMatch(iccidFromSim, iccidRegex));
    EXPECT_FALSE(operatorMatchingRule->SpnRegexMatch(iccidFromSim, iccidRegex));
    EXPECT_FALSE(operatorMatchingRule->PrefixMatch(iccidFromSim, iccidRegex));
}

/**
 * @tc.number   Telephony_SIMUtils_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SIMUtils_001, Function | MediumTest | Level1)
{
    auto simUtils = std::make_shared<SIMUtils>();
    char spnData = '0';
    std::string str = "";
    int byteslen = 1;
    EXPECT_EQ(simUtils->HexCharConvertToInt(spnData), 0);
    spnData = 'B';
    EXPECT_GT(simUtils->HexCharConvertToInt(spnData), 0);
    spnData = 'b';
    EXPECT_GT(simUtils->HexCharConvertToInt(spnData), 0);
    EXPECT_TRUE(simUtils->HexStringConvertToBytes(str, byteslen) == nullptr);
    str = "123";
    unsigned char *bytes = (unsigned char *)str.c_str();
    std::shared_ptr<unsigned char> bytesTwo = std::make_shared<unsigned char>(1);
    simUtils->ArrayCopy(bytes, 1, bytes, 1, 1);
    EXPECT_TRUE(simUtils->HexStringConvertToBytes(str, byteslen) == nullptr);
    str = "1";
    EXPECT_TRUE(simUtils->IsShowableAsciiOnly(str));
    EXPECT_TRUE(simUtils->HexStringConvertToBytes(str, byteslen) == nullptr);
    byteslen = 2;
    str = "12";
    EXPECT_TRUE(simUtils->HexStringConvertToBytes(str, byteslen) != nullptr);
    EXPECT_EQ(simUtils->BytesConvertToHexString(nullptr, 1), "");
    EXPECT_NE(simUtils->BytesConvertToHexString(bytes, 1), "");
    int outChar16Len = 1;
    EXPECT_TRUE(simUtils->CharsConvertToChar16(nullptr, 1, outChar16Len, true) == nullptr);
    EXPECT_TRUE(simUtils->CharsConvertToChar16(bytes, 0, outChar16Len, true) == nullptr);
    EXPECT_TRUE(simUtils->CharsConvertToChar16(bytes, BYTES_LENGTH, outChar16Len, true) == nullptr);
    EXPECT_TRUE(simUtils->CharsConvertToChar16(bytes, 1, outChar16Len, true) == nullptr);
    EXPECT_FALSE(simUtils->CharsConvertToChar16(bytes, OBTAIN_SPN_GENERAL, outChar16Len, true) == nullptr);
    EXPECT_FALSE(simUtils->CharsConvertToChar16(bytes, OBTAIN_SPN_GENERAL, outChar16Len, false) == nullptr);
    EXPECT_NE(simUtils->Gsm7bitConvertToString(bytes, 1), "");
    EXPECT_EQ(simUtils->DiallingNumberStringFieldConvertToString(bytesTwo, 0, 0, 1), "");
    EXPECT_EQ(simUtils->DiallingNumberStringFieldConvertToString(nullptr, 0, 1, 1), "");
    EXPECT_EQ(simUtils->UcsCodeConvertToString(bytesTwo, 0, BYTES_LENGTH, 1), "");
}

/**
 * @tc.number   Telephony_SimNumberDecode_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimNumberDecode_001, Function | MediumTest | Level1)
{
    auto simNumberDecode = std::make_shared<SimNumberDecode>();
    std::string number = "a";
    EXPECT_FALSE(simNumberDecode->IsValidNumberString(number));
    EXPECT_TRUE(simNumberDecode->chooseExtendedByType(1) != nullptr);
    EXPECT_TRUE(simNumberDecode->chooseExtendedByType(OBTAIN_SPN_GENERAL) != nullptr);
    char spnData = '0';
    uint8_t result = 1;
    EXPECT_TRUE(simNumberDecode->CharToBCD(spnData, result, 1));
    spnData = 'a';
    EXPECT_FALSE(simNumberDecode->CharToBCD(spnData, result, BYTES_LENGTH));
    EXPECT_TRUE(simNumberDecode->BcdToChar(1, spnData, 1));
    EXPECT_FALSE(simNumberDecode->BcdToChar(VALUE_LENGTH, spnData, BYTES_LENGTH));
    EXPECT_FALSE(simNumberDecode->BcdToChar(VALUE_LENGTH, spnData, 1));
    number = "+-";
    std::vector<uint8_t> bcdCodes;
    std::shared_ptr<unsigned char> bytesData = nullptr;
    EXPECT_FALSE(simNumberDecode->NumberConvertToBCD(number, bcdCodes, true, BYTES_LENGTH));
    number = "0+";
    EXPECT_TRUE(simNumberDecode->NumberConvertToBCD(number, bcdCodes, true, 1));
    EXPECT_EQ(simNumberDecode->BCDConvertToString(bytesData, 1, 1, 1), "");
    bytesData = std::make_shared<unsigned char>(1);
    EXPECT_EQ(simNumberDecode->BCDConvertToString(bytesData, 1, 1, 1), "");
    bcdCodes.push_back(1);
    bcdCodes.push_back(LO_FOUR_LENGTH);
    std::vector<uint8_t>::const_iterator codeBeg = bcdCodes.begin();
    std::vector<uint8_t>::const_iterator codeEnd = bcdCodes.end();
    EXPECT_FALSE(simNumberDecode->BCDSectionConvertToString(codeBeg, codeEnd, number, BYTES_LENGTH));
    EXPECT_FALSE(simNumberDecode->BCDSectionConvertToString(codeBeg, codeEnd, number, 1));
    EXPECT_FALSE(simNumberDecode->BCDConvertToString(codeBeg, codeEnd, number, BYTES_LENGTH));
    EXPECT_FALSE(simNumberDecode->BCDConvertToString(codeBeg, codeEnd, number, 1));
}

/**
 * @tc.number   Telephony_IccFile_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_IccFile_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(runner, simStateManager);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(StateMessage::MSG_ICC_REFRESH, 1);
    iccFile->ProcessEvent(event);
    event = nullptr;
    iccFile->ProcessEvent(event);
    std::shared_ptr<AppExecFwk::EventHandler> handler = nullptr;
    iccFile->RegisterCoreNotify(handler, RadioEvent::RADIO_SIM_RECORDS_LOADED);
    iccFile->RegisterCoreNotify(handler, RadioEvent::RADIO_SIM_RECORDS_LOADED);
    iccFile->UnRegisterCoreNotify(handler, RadioEvent::RADIO_SIM_RECORDS_LOADED);
    iccFile->UnRegisterCoreNotify(handler, RadioEvent::RADIO_SIM_GET_RADIO_PROTOCOL);
    iccFile->imsi_ = "123";
    iccFile->RegisterCoreNotify(handler, RadioEvent::RADIO_IMSI_LOADED_READY);
    iccFile->UnRegisterCoreNotify(handler, RadioEvent::RADIO_IMSI_LOADED_READY);
    std::string plmn = "";
    EXPECT_EQ(iccFile->ObtainEons(plmn, 1, true), "");
    plmn = "123";
    iccFile->UpdateSPN(plmn);
    EXPECT_EQ(iccFile->ObtainEons(plmn, 1, true), "");
    auto plmnNetworkName = std::make_shared<PlmnNetworkName>();
    iccFile->pnnFiles_.push_back(plmnNetworkName);
    EXPECT_EQ(iccFile->ObtainEons(plmn, 1, true), "");
    auto opl = std::make_shared<OperatorPlmnInfo>();
    opl->plmnNumeric = "123";
    opl->lacStart = 0;
    opl->lacEnd = 0xfffe;
    opl->pnnRecordId = 1;
    iccFile->oplFiles_.push_back(opl);
    iccFile->oplFiles_.push_back(nullptr);
    EXPECT_EQ(iccFile->ObtainEons(plmn, 0, true), "");
    EXPECT_EQ(iccFile->ObtainEons(plmn, 0, false), "");
    std::string langData = "";
    EXPECT_EQ(iccFile->ObtainValidLanguage(langData), "");
}

/**
 * @tc.number   Telephony_SimRdbHelper_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimRdbHelper_001, Function | MediumTest | Level1)
{
    auto simRdbHelper = std::make_shared<SimRdbHelper>();
    SimRdbInfo simBean;
    std::string iccId = "";
    std::vector<SimRdbInfo> vec;
    EXPECT_GE(simRdbHelper->GetDefaultMainCardSlotId(), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->GetDefaultMessageCardSlotId(), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->GetDefaultCellularDataCardSlotId(), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->GetDefaultVoiceCardSlotId(), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->SetDefaultMainCard(INVALID_SLOTID), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->SetDefaultVoiceCard(INVALID_SLOTID), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->SetDefaultMessageCard(INVALID_SLOTID), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->SetDefaultCellularData(INVALID_SLOTID), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->QueryDataBySlotId(INVALID_SLOTID, simBean), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->QueryDataByIccId(iccId, simBean), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->QueryAllData(vec), TELEPHONY_ERROR);
    EXPECT_GE(simRdbHelper->QueryAllValidData(vec), TELEPHONY_ERROR);
}

/**
 * @tc.number   Telephony_MultiSimMonitor_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_MultiSimMonitor_001, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("test");
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager, runner);
    auto multiSimMonitor =
        std::make_shared<MultiSimMonitor>(runner, multiSimController, simStateManager, simFileManager);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_RECORDS_LOADED, 1);
    multiSimMonitor->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);
    multiSimMonitor->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioProtocolEvent::MSG_SIM_FORGET_ALLDATA, 1);
    multiSimMonitor->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_SIMLOCK, 1);
    multiSimMonitor->ProcessEvent(event);
    event = nullptr;
    multiSimMonitor->ProcessEvent(event);
    multiSimMonitor->InitData(INVALID_SLOTID);
    multiSimMonitor->InitData(0);
    multiSimMonitor->RefreshData(INVALID_SLOTID);
    multiSimMonitor->RefreshData(0);
    multiSimMonitor->NotifySimAccountChanged();
    std::string bundleName = "123";
    sptr<SimAccountCallback> callback = nullptr;
    EXPECT_GT(multiSimMonitor->RegisterSimAccountCallback(bundleName, callback), TELEPHONY_ERROR);
    EXPECT_EQ(multiSimMonitor->UnregisterSimAccountCallback(bundleName), TELEPHONY_ERROR);
}

/**
 * @tc.number   Telephony_ImsCoreServiceCallbackProxy_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_ImsCoreServiceCallbackProxy_001, Function | MediumTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGE("Telephony_ImsCoreServiceCallbackProxy systemAbilityMgr is nullptr");
        return;
    }
    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote == nullptr) {
        TELEPHONY_LOGE("Telephony_ImsCoreServiceCallbackProxy remote is nullptr");
        return;
    }
    auto imsCoreServiceCallbackProxy = std::make_shared<ImsCoreServiceCallbackProxy>(remote);
    ImsServiceStatus imsServiceStatus;
    EXPECT_GE(imsCoreServiceCallbackProxy->UpdateImsServiceStatusChanged(INVALID_SLOTID, imsServiceStatus), 0);
    ImsRegistrationStatus imsRegStatus;
    EXPECT_GE(imsCoreServiceCallbackProxy->GetImsRegistrationStatusResponse(INVALID_SLOTID, imsRegStatus), 0);
    auto imsCoreServiceCallbackStub = std::make_shared<ImsCoreServiceCallbackStub>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_GE(imsCoreServiceCallbackStub->OnRemoteRequest(0, data, reply, option), 0);
}

/**
 * @tc.number   Telephony_ImsCoreServiceProxy_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_ImsCoreServiceProxy_001, Function | MediumTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGE("Telephony_ImsCoreServiceProxy systemAbilityMgr is nullptr");
        return;
    }
    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_IMS_SYS_ABILITY_ID);
    if (remote == nullptr) {
        TELEPHONY_LOGE("Telephony_ImsCoreServiceProxy remote is nullptr");
        return;
    }
    auto imsCoreServiceProxy = std::make_shared<ImsCoreServiceProxy>(remote);
    EXPECT_GE(imsCoreServiceProxy->GetImsRegistrationStatus(0), 0);
    EXPECT_GE(imsCoreServiceProxy->RegisterImsCoreServiceCallback(nullptr), 0);
}

/**
 * @tc.number   Telephony_CoreServiceClient_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_CoreServiceClient_001, Function | MediumTest | Level1)
{
    auto coreServiceClient = std::make_shared<CoreServiceClient>();
    coreServiceClient->OnRemoteDied(nullptr);
    auto recipient = std::make_shared<CoreServiceClient::CoreServiceDeathRecipient>(CoreServiceClient::GetInstance());
    recipient->OnRemoteDied(nullptr);
    EXPECT_GE(coreServiceClient->GetNetworkSelectionMode(INVALID_SLOTID, nullptr), 0);
    EXPECT_NE(coreServiceClient->RefreshSimState(INVALID_SLOTID), 0);
    EXPECT_GE(coreServiceClient->GetPreferredNetwork(INVALID_SLOTID, nullptr), 0);
    EXPECT_GE(coreServiceClient->SetPreferredNetwork(INVALID_SLOTID, 0, nullptr), 0);
}

/**
 * @tc.number   Telephony_SignalInformation_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SignalInformation_001, Function | MediumTest | Level1)
{
    std::shared_ptr<SignalInformation> wCdmaSignalInformation = std::make_shared<WcdmaSignalInformation>();
    std::shared_ptr<SignalInformation> nrSignalInformation = std::make_shared<NrSignalInformation>();
    std::shared_ptr<SignalInformation> cdmaSignalInformation = std::make_shared<CdmaSignalInformation>();
    std::shared_ptr<SignalInformation> tdScdmaSignalInformation = std::make_shared<TdScdmaSignalInformation>();
    std::shared_ptr<SignalInformation> gsmSignalInformation = std::make_shared<GsmSignalInformation>();
    Parcel parcel;
    gsmSignalInformation->SignalInformation::Unmarshalling(parcel);
    EXPECT_GE(wCdmaSignalInformation->GetSignalIntensity(), 0);
    EXPECT_GE(nrSignalInformation->GetSignalIntensity(), 0);
    EXPECT_GE(cdmaSignalInformation->GetSignalIntensity(), 0);
    EXPECT_GE(tdScdmaSignalInformation->GetSignalIntensity(), 0);
    EXPECT_GE(gsmSignalInformation->GetSignalIntensity(), 0);
    std::shared_ptr<CellLocation> cellLocation = std::make_shared<GsmCellLocation>();
    cellLocation->CellLocation::Unmarshalling(parcel);
    std::shared_ptr<GsmCellLocation> gsmCellLocation = std::make_shared<GsmCellLocation>();
    EXPECT_GE(gsmCellLocation->GetCellId(), 0);
}
} // namespace Telephony
} // namespace OHOS
