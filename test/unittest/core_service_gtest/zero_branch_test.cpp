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
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "gtest/gtest.h"
#include "network_search_manager.h"
#include "sim_file_manager.h"
#include "sim_manager.h"
#include "sim_state_manager.h"
#include "stk_manager.h"
#include "tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_hisysevent.h"
#include "telephony_log_wrapper.h"

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
    sptr<CellInformation> cdmaCellInformation = new NrCellInformation();
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
    telRilManager->OnInit();
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
    telRilManager->OnInit();
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
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("SimFile");
    std::shared_ptr<SimFile> simFile = std::make_shared<SimFile>(eventLoopRecord, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    simFile->ProcessEvent(event);
    simFile->ObtainSpnPhase(false, event);
    simFile->ProcessSpnGeneral(event);
    simFile->ProcessSpnCphs(event);
    simFile->ProcessSpnShortCphs(event);
    simFile->CheckMncLength();
    simFile->InitMemberFunc();
    simFile->ProcessFileLoaded(false);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_MBDN);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_MAILBOX_CPHS);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_CSP_CPHS);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_FDN);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_MSISDN);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_CFIS);
    simFile->ProcessIccRefresh(ELEMENTARY_FILE_CFF_CPHS);
    EXPECT_EQ(simFile->ObtainSimOperator(), "");
    EXPECT_EQ(simFile->ObtainIsoCountryCode(), "");
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
    telRilManager->OnInit();
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
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("SimFile");
    std::shared_ptr<SimFile> simFile = std::make_shared<SimFile>(eventLoopRecord, simStateManager);
    std::string operatorNum = "";
    EXPECT_EQ(simFile->ObtainSpnCondition(true, operatorNum), 0);
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
 * @tc.number   Telephony_ISimFile_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_ISimFile_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("IsimFile");
    std::shared_ptr<IsimFile> iSimFile = std::make_shared<IsimFile>(eventLoopRecord, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    iSimFile->ProcessEvent(event);
    EXPECT_EQ(iSimFile->ObtainIsimImpi(), "");
    EXPECT_EQ(iSimFile->ObtainIsimDomain(), "");
    EXPECT_EQ(iSimFile->ObtainIsimImpu(), nullptr);
    EXPECT_EQ(iSimFile->ObtainIsimIst(), "");
    EXPECT_EQ(iSimFile->ObtainIsimPcscf(), nullptr);
    EXPECT_FALSE(iSimFile->UpdateVoiceMail("", ""));
    EXPECT_EQ(iSimFile->ObtainSpnCondition(true, ""), 0);
    EXPECT_EQ(iSimFile->ObtainIsoCountryCode(), "");
    iSimFile->ProcessFileLoaded(false);
    iSimFile->InitMemberFunc();
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
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord = AppExecFwk::EventRunner::Create("RuimFile");
    std::shared_ptr<RuimFile> rUimFile = std::make_shared<RuimFile>(eventLoopRecord, simStateManager);
    auto event = AppExecFwk::InnerEvent::Get(0);
    event = nullptr;
    rUimFile->ProcessEvent(event);
    EXPECT_EQ(rUimFile->ObtainSimOperator(), "");
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
    rUimFile->ProcessFileLoaded(false);
    unsigned char spnData[10] = { 0 };
    rUimFile->ParseSpnName(0, spnData, 0);
    rUimFile->InitMemberFunc();
    rUimFile->ProcessLockedAllFilesFetched();
    EXPECT_TRUE(rUimFile->ProcessGetImsiDone(event));
    EXPECT_TRUE(rUimFile->ProcessGetIccidDone(event));
    EXPECT_TRUE(rUimFile->ProcessGetSubscriptionDone(event));
    EXPECT_TRUE(rUimFile->ProcessGetSpnDone(event));
}
} // namespace Telephony
} // namespace OHOS
