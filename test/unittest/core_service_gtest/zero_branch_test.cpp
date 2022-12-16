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
    EXPECT_FALSE(mInner.SetRadioState(0, 0, 0, nullptr));
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
    EXPECT_EQ(mInner.QueryIccDiallingNumbers(0, 0), result);
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
    EXPECT_EQ(mInner.GetPsRadioTech(0), -1);
    EXPECT_EQ(mInner.GetCsRadioTech(0), -1);
    EXPECT_EQ(mInner.GetPsRegState(0), -1);
    EXPECT_EQ(mInner.GetRadioState(0), -1);
    EXPECT_EQ(mInner.GetCsRegState(0), -1);
    EXPECT_EQ(mInner.GetPsRoamingState(0), -1);
    ImsRegInfo info;
    EXPECT_EQ(mInner.GetImsRegStatus(0, ImsServiceType::TYPE_VOICE, info), TELEPHONY_ERR_LOCAL_PTR_NULL);
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    sptr<INetworkSearchCallback> callback = nullptr;
    EXPECT_FALSE(mInner.SetNetworkSelectionMode(0, 1, networkInfo, true, callback));
    EXPECT_FALSE(mInner.SetRadioState(0, true, 0, callback));
    EXPECT_FALSE(mInner.GetRadioState(0, callback));
    EXPECT_FALSE(mInner.GetNetworkSearchInformation(0, callback));
    EXPECT_FALSE(mInner.GetNetworkSelectionMode(0, callback));
    EXPECT_FALSE(mInner.GetPreferredNetwork(0, callback));
    EXPECT_FALSE(mInner.SetPreferredNetwork(0, 0, callback));
    EXPECT_EQ(mInner.GetSignalInfoList(0), std::vector<sptr<SignalInformation>>());
    EXPECT_EQ(mInner.GetCellInfoList(0), std::vector<sptr<CellInformation>>());
    EXPECT_EQ(mInner.GetOperatorNumeric(0), std::u16string());
    EXPECT_EQ(mInner.GetOperatorName(0), std::u16string());
    EXPECT_EQ(mInner.GetIsoCountryCodeForNetwork(0), std::u16string());
    EXPECT_EQ(mInner.GetImei(0), std::u16string());
    EXPECT_EQ(mInner.GetMeid(0), std::u16string());
    EXPECT_EQ(mInner.GetUniqueDeviceId(0), std::u16string());
    EXPECT_EQ(mInner.GetNetworkStatus(0), nullptr);
    EXPECT_EQ(mInner.GetCellLocation(0), nullptr);
    EXPECT_EQ(mInner.GetPhoneType(0), PhoneType::PHONE_TYPE_IS_NONE);
    EXPECT_EQ(mInner.GetNrOptionMode(0), NrMode::NR_MODE_UNKNOWN);
    EXPECT_EQ(mInner.GetFrequencyType(0), FrequencyType::FREQ_TYPE_UNKNOWN);
    EXPECT_EQ(mInner.GetNrState(0), NrState::NR_STATE_NOT_SUPPORT);
    EXPECT_FALSE(mInner.SendUpdateCellLocationRequest(0));
    EXPECT_FALSE(mInner.IsNrSupported(0));
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
    EXPECT_EQ(mInner.GetSpn(0), std::u16string());
    EXPECT_EQ(mInner.GetShowNumber(0), std::u16string());
    EXPECT_EQ(mInner.GetShowName(0), std::u16string());
    EXPECT_EQ(mInner.GetSimOperatorNumeric(0), std::u16string());
    EXPECT_EQ(mInner.GetISOCountryCodeForSim(0), std::u16string());
    EXPECT_EQ(mInner.GetSimIccId(0), std::u16string());
    EXPECT_EQ(mInner.GetIMSI(0), std::u16string());
    EXPECT_EQ(mInner.GetLocaleFromDefaultSim(0), std::u16string());
    EXPECT_EQ(mInner.GetSimGid1(0), std::u16string());
    EXPECT_EQ(mInner.GetSimGid2(0), std::u16string());
    EXPECT_EQ(mInner.GetSimTelephoneNumber(0), std::u16string());
    EXPECT_EQ(mInner.GetSimTeleNumberIdentifier(0), std::u16string());
    EXPECT_EQ(mInner.GetVoiceMailIdentifier(0), std::u16string());
    EXPECT_EQ(mInner.GetVoiceMailNumber(0), std::u16string());
    EXPECT_EQ(mInner.GetSimIst(0), std::u16string());
    EXPECT_FALSE(mInner.SetVoiceMailInfo(0, u"", u""));
    EXPECT_FALSE(mInner.HasOperatorPrivileges(0));
    EXPECT_FALSE(mInner.HasSimCard(0));
    EXPECT_FALSE(mInner.SendEnvelopeCmd(0, ""));
    EXPECT_FALSE(mInner.SendTerminalResponseCmd(0, ""));
    EXPECT_FALSE(mInner.SendTerminalResponseCmd(0, ""));
    EXPECT_FALSE(mInner.DelSmsIcc(0, 0));
    EXPECT_FALSE(mInner.IsSimActive(0));
    EXPECT_FALSE(mInner.SetShowName(0, u""));
    LockStatusResponse response;
    PersoLockInfo lockInfo;
    EXPECT_FALSE(mInner.UnlockSimLock(0, lockInfo, response));
    EXPECT_FALSE(mInner.UnlockPin(0, "", response));
    EXPECT_FALSE(mInner.UnlockPuk(0, "", "", response));
    EXPECT_FALSE(mInner.AlterPin(0, "", "", response));
    LockInfo options;
    EXPECT_FALSE(mInner.SetLockState(0, options, response));
    EXPECT_FALSE(mInner.UnlockPin2(0, "", response));
    EXPECT_FALSE(mInner.UnlockPuk2(0, "", "", response));
    EXPECT_FALSE(mInner.AlterPin2(0, "", "", response));
    std::shared_ptr<DiallingNumbersInfo> result = std::make_shared<DiallingNumbersInfo>();
    EXPECT_FALSE(mInner.AddIccDiallingNumbers(0, 0, result));
    EXPECT_FALSE(mInner.DelIccDiallingNumbers(0, 0, result));
    EXPECT_FALSE(mInner.UpdateIccDiallingNumbers(0, 0, result));
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
    EXPECT_FALSE(mInner.GetOperatorConfigs(0, mOperatorConfig));
    IccAccountInfo mIccAccountInfo;
    EXPECT_FALSE(mInner.GetSimAccountInfo(0, mIccAccountInfo));
    std::vector<IccAccountInfo> iccAccountInfoList;
    EXPECT_FALSE(mInner.GetActiveSimAccountInfoList(iccAccountInfoList));
    EXPECT_FALSE(mInner.GetLockState(0, LockType::PIN_LOCK));
    EXPECT_NE(mInner.SendCallSetupRequestResult(0, true), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetSimState(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mInner.GetCardType(0), TELEPHONY_ERR_SUCCESS);
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
    mInner.GetPrimarySlotId();
    EXPECT_NE(mInner.SaveImsSwitch(0, 0), TELEPHONY_ERR_SUCCESS);
    int32_t imsSwitchValue = 0;
    EXPECT_NE(mInner.SaveImsSwitch(0, imsSwitchValue), TELEPHONY_ERR_SUCCESS);
    std::vector<std::string> result;
    EXPECT_EQ(mInner.ObtainAllSmsOfIcc(0), result);
    std::string pduData = "test";
    std::string smsc = "test";
    EXPECT_FALSE(mInner.UpdateSmsIcc(0, 0, 0, pduData, smsc));
    EXPECT_FALSE(mInner.AddSmsToIcc(0, 0, pduData, smsc));
}

/**
 * @tc.number   Telephony_SimManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    simManager->SetNetworkSearchManager(nullptr);
    std::u16string testStr = u"";
    EXPECT_FALSE(simManager->SetShowNumber(0, testStr));
    EXPECT_FALSE(simManager->SetShowNumber(INVALID_SLOTID, testStr));
    EXPECT_EQ(simManager->GetSimOperatorNumeric(0), testStr);
    EXPECT_EQ(simManager->GetSimOperatorNumeric(INVALID_SLOTID), testStr);
    EXPECT_FALSE(simManager->HasSimCard(0));
    EXPECT_FALSE(simManager->HasSimCard(INVALID_SLOTID));
    EXPECT_NE(simManager->GetSimState(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetSimState(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetCardType(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetCardType(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    std::string password = "1234";
    LockStatusResponse mLockStatusResponse;
    EXPECT_FALSE(simManager->UnlockPin(0, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->UnlockPin(INVALID_SLOTID, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->UnlockPuk(0, password, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->UnlockPuk(INVALID_SLOTID, password, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->AlterPin(0, password, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->AlterPin(INVALID_SLOTID, password, password, mLockStatusResponse));
    LockInfo mLockInfo;
    EXPECT_FALSE(simManager->SetLockState(0, mLockInfo, mLockStatusResponse));
    EXPECT_FALSE(simManager->SetLockState(INVALID_SLOTID, mLockInfo, mLockStatusResponse));
    LockType mLockType = LockType::PIN_LOCK;
    EXPECT_NE(simManager->GetLockState(0, mLockType), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetLockState(INVALID_SLOTID, mLockType), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->RefreshSimState(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->RefreshSimState(INVALID_SLOTID), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(simManager->UnlockPin2(0, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->UnlockPin2(INVALID_SLOTID, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->UnlockPuk2(0, password, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->UnlockPuk2(INVALID_SLOTID, password, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->AlterPin2(0, password, password, mLockStatusResponse));
    EXPECT_FALSE(simManager->AlterPin2(INVALID_SLOTID, password, password, mLockStatusResponse));
    PersoLockInfo mPersoLockInfo;
    EXPECT_FALSE(simManager->UnlockSimLock(0, mPersoLockInfo, mLockStatusResponse));
    EXPECT_FALSE(simManager->UnlockSimLock(INVALID_SLOTID, mPersoLockInfo, mLockStatusResponse));
    EXPECT_FALSE(simManager->IsSimActive(0));
    EXPECT_FALSE(simManager->IsSimActive(INVALID_SLOTID));
    EXPECT_FALSE(simManager->SetActiveSim(0, 1));
    EXPECT_FALSE(simManager->SetActiveSim(INVALID_SLOTID, 1));
    IccAccountInfo mIccAccountInfo;
    EXPECT_FALSE(simManager->GetSimAccountInfo(0, mIccAccountInfo));
    EXPECT_FALSE(simManager->GetSimAccountInfo(INVALID_SLOTID, mIccAccountInfo));
}

/**
 * @tc.number   Telephony_SimManager_002
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimManager_002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    std::u16string testStr = u"";
    EXPECT_EQ(simManager->GetISOCountryCodeForSim(0), testStr);
    EXPECT_EQ(simManager->GetISOCountryCodeForSim(INVALID_SLOTID), testStr);
    EXPECT_FALSE(simManager->SetShowName(0, testStr));
    EXPECT_FALSE(simManager->SetShowName(INVALID_SLOTID, testStr));
    EXPECT_EQ(simManager->GetSimSpn(0), testStr);
    EXPECT_EQ(simManager->GetSimSpn(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetSimIccId(0), testStr);
    EXPECT_EQ(simManager->GetSimIccId(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetIMSI(0), testStr);
    EXPECT_EQ(simManager->GetIMSI(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetLocaleFromDefaultSim(0), testStr);
    EXPECT_EQ(simManager->GetLocaleFromDefaultSim(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetSimGid1(0), testStr);
    EXPECT_EQ(simManager->GetSimGid1(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetSimGid2(0), testStr);
    EXPECT_EQ(simManager->GetSimGid2(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetSimEons(0, "46001", 1, true), testStr);
    EXPECT_EQ(simManager->GetSimEons(INVALID_SLOTID, "46001", 1, true), testStr);
    EXPECT_EQ(simManager->GetShowNumber(0), testStr);
    EXPECT_EQ(simManager->GetShowNumber(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetShowName(0), testStr);
    EXPECT_EQ(simManager->GetShowName(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetSimTelephoneNumber(0), testStr);
    EXPECT_EQ(simManager->GetSimTelephoneNumber(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetSimTeleNumberIdentifier(0), testStr);
    EXPECT_EQ(simManager->GetSimTeleNumberIdentifier(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetVoiceMailIdentifier(0), testStr);
    EXPECT_EQ(simManager->GetVoiceMailIdentifier(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetVoiceMailNumber(0), testStr);
    EXPECT_EQ(simManager->GetVoiceMailNumber(INVALID_SLOTID), testStr);
    EXPECT_EQ(simManager->GetSimIst(0), testStr);
    EXPECT_EQ(simManager->GetSimIst(INVALID_SLOTID), testStr);
    EXPECT_NE(simManager->GetOpName(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpName(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpKey(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpKey(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpKeyExt(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetOpKeyExt(INVALID_SLOTID, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(simManager->SetVoiceMailInfo(0, testStr, testStr));
    EXPECT_FALSE(simManager->SetVoiceMailInfo(INVALID_SLOTID, testStr, testStr));
}

/**
 * @tc.number   Telephony_SimManager_003
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimManager_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
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
    simManager->GetPrimarySlotId();
    EXPECT_NE(simManager->GetSlotId(1), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->GetSimId(0), TELEPHONY_ERR_SUCCESS);
    std::vector<IccAccountInfo> iccAccountInfoList;
    EXPECT_FALSE(simManager->GetActiveSimAccountInfoList(iccAccountInfoList));
    OperatorConfig mOperatorConfig;
    EXPECT_FALSE(simManager->GetOperatorConfigs(0, mOperatorConfig));
    EXPECT_FALSE(simManager->GetOperatorConfigs(INVALID_SLOTID, mOperatorConfig));
    EXPECT_FALSE(simManager->HasOperatorPrivileges(0));
    EXPECT_FALSE(simManager->HasOperatorPrivileges(INVALID_SLOTID));
    SimAuthenticationResponse mResponse;
    EXPECT_NE(simManager->SimAuthentication(0, "", "", mResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->SimAuthentication(INVALID_SLOTID, "", "", mResponse), TELEPHONY_ERR_SUCCESS);
    int32_t testRadioProtocolTech = static_cast<int32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_UNKNOWN);
    EXPECT_EQ(simManager->GetRadioProtocolTech(0), testRadioProtocolTech);
    EXPECT_EQ(simManager->GetRadioProtocolTech(INVALID_SLOTID), testRadioProtocolTech);
    EXPECT_FALSE(simManager->SendEnvelopeCmd(0, ""));
    EXPECT_FALSE(simManager->SendEnvelopeCmd(INVALID_SLOTID, ""));
    EXPECT_FALSE(simManager->SendTerminalResponseCmd(0, ""));
    EXPECT_FALSE(simManager->SendTerminalResponseCmd(INVALID_SLOTID, ""));
    EXPECT_NE(simManager->SendCallSetupRequestResult(0, true), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->SendCallSetupRequestResult(INVALID_SLOTID, true), TELEPHONY_ERR_SUCCESS);
    std::string testAddress = "";
    EXPECT_FALSE(simManager->AddSmsToIcc(0, 1, testAddress, testAddress));
    EXPECT_FALSE(simManager->AddSmsToIcc(INVALID_SLOTID, 1, testAddress, testAddress));
    EXPECT_FALSE(simManager->UpdateSmsIcc(0, 1, 1, testAddress, testAddress));
    EXPECT_FALSE(simManager->UpdateSmsIcc(INVALID_SLOTID, 1, 1, testAddress, testAddress));
    EXPECT_FALSE(simManager->DelSmsIcc(0, 1));
    EXPECT_FALSE(simManager->DelSmsIcc(INVALID_SLOTID, 1));
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
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> list;
    EXPECT_EQ(simManager->QueryIccDiallingNumbers(0, 1), list);
    EXPECT_EQ(simManager->QueryIccDiallingNumbers(INVALID_SLOTID, 1), list);
    EXPECT_FALSE(simManager->AddIccDiallingNumbers(0, 1, nullptr));
    EXPECT_FALSE(simManager->AddIccDiallingNumbers(INVALID_SLOTID, 1, nullptr));
    EXPECT_FALSE(simManager->DelIccDiallingNumbers(0, 1, nullptr));
    EXPECT_FALSE(simManager->DelIccDiallingNumbers(INVALID_SLOTID, 1, nullptr));
    EXPECT_FALSE(simManager->UpdateIccDiallingNumbers(0, 1, nullptr));
    EXPECT_FALSE(simManager->UpdateIccDiallingNumbers(INVALID_SLOTID, 1, nullptr));
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
    std::string testString = "";
    EXPECT_NE(simManager->ObtainSpnCondition(0, true, testString), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(simManager->ObtainSpnCondition(INVALID_SLOTID, true, testString), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_SimStateManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(BranchTest, Telephony_SimStateManager_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    telRilManager->OnInit();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EXPECT_FALSE(simStateManager->HasSimCard());
    EXPECT_EQ(simStateManager->GetSimState(), SimState::SIM_STATE_UNKNOWN);
    EXPECT_EQ(simStateManager->GetCardType(), CardType::UNKNOWN_CARD);
    std::string password = "1234";
    LockStatusResponse mLockStatusResponse;
    EXPECT_TRUE(simStateManager->UnlockPin(0, password, mLockStatusResponse));
    EXPECT_TRUE(simStateManager->UnlockPuk(0, password, password, mLockStatusResponse));
    EXPECT_TRUE(simStateManager->AlterPin(0, password, password, mLockStatusResponse));
    LockInfo mLockInfo;
    EXPECT_FALSE(simStateManager->SetLockState(0, mLockInfo, mLockStatusResponse));
    mLockInfo.lockType = LockType::PIN_LOCK;
    mLockInfo.lockState = LockState::LOCK_ERROR;
    EXPECT_FALSE(simStateManager->SetLockState(0, mLockInfo, mLockStatusResponse));
    mLockInfo.lockState = LockState::LOCK_ON;
    EXPECT_TRUE(simStateManager->SetLockState(0, mLockInfo, mLockStatusResponse));
    LockInfo testLockInfo;
    EXPECT_EQ(simStateManager->GetLockState(0, testLockInfo.lockType), static_cast<int32_t>(LockState::LOCK_ERROR));
    LockType lockType = LockType::PIN_LOCK;
    EXPECT_EQ(simStateManager->GetLockState(0, lockType), 0);
    EXPECT_EQ(simStateManager->RefreshSimState(0), 0);
    EXPECT_TRUE(simStateManager->UnlockPin2(0, password, mLockStatusResponse));
    EXPECT_TRUE(simStateManager->UnlockPuk2(0, password, password, mLockStatusResponse));
    EXPECT_TRUE(simStateManager->AlterPin2(0, password, password, mLockStatusResponse));
    PersoLockInfo mPersoLockInfo;
    EXPECT_FALSE(simStateManager->UnlockSimLock(0, mPersoLockInfo, mLockStatusResponse));
    simStateManager->RegisterCoreNotify(nullptr, 1);
    simStateManager->UnRegisterCoreNotify(nullptr, 1);
    SimAuthenticationResponse mResponse;
    EXPECT_NE(simStateManager->SimAuthentication(0, "", "", mResponse), TELEPHONY_ERR_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS
