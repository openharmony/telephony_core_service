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
#include <set>
#include <unistd.h>
#include "sim_manager.h"
#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"
#include "gtest/gtest.h"
#include "tel_ril_manager.h"
#include "mock_tel_ril_manager.h"
#include "mock_sim_manager.h"
#include "sim_state_type.h"
#include "sim_rdb_helper.h"
#include "icc_file.h"
#include "mock_sim_rdb_helper.h"
#include "mock_multi_sim_controller.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace testing;

class SimManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static MockTelRilManager *telRilManager_;
    static std::shared_ptr<SimManager> simManager_;
};

MockTelRilManager *SimManagerTest::telRilManager_ = nullptr;
std::shared_ptr<SimManager> SimManagerTest::simManager_ = nullptr;

void SimManagerTest::SetUpTestCase()
{
    telRilManager_ = new MockTelRilManager();
    std::shared_ptr<MockTelRilManager> telRilManager(telRilManager_);
    simManager_ = std::make_shared<SimManager>(telRilManager);
    EXPECT_CALL(*telRilManager_, UnRegisterCoreNotify(_, _, _))
        .WillRepeatedly(Return(0));
}

void SimManagerTest::TearDownTestCase()
{
    Mock::AllowLeak(telRilManager_);
    telRilManager_ = nullptr;
    simManager_->telRilManager_ = nullptr;
}

void SimManagerTest::SetUp() {}

void SimManagerTest::TearDown() {}

class SimManagerMock : public SimManager {
public:
    explicit SimManagerMock(std::shared_ptr<ITelRilManager> telRilManager) : SimManager(telRilManager)
    {
    }

    int32_t HasSimCard(int32_t slotId, bool &hasSimCard) override
    {
        if (slotId == 0) {
            hasSimCard = true;
        } else {
            hasSimCard = false;
        }

        return 0;
    }
};

HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_Expand001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<MockTelRilManager>();
    auto simManager = std::make_shared<SimManagerMock>(telRilManager);

    simManager->InitSingleSimObject();
    simManager->slotCount_ = 1;
    simManager->InitMultiSimObject();

    simManager->slotCount_ = -1;
    simManager->InitMultiSimObject();

    simManager->simStateManager_.resize(MAX_SLOT_COUNT);
    simManager->InitTelExtraModule(0);
    simManager->simStateManager_.clear();
    simManager->InitTelExtraModule(0);
    simManager->InitBaseManager(-1);

    simManager->slotCount_ = 1;
    SimState simState;
    IccSimStatus iccSimStatus;
    LockStatusResponse response;
    CardType cardType;
    LockInfo lockInfo;
    LockType lockType = LockType::PIN_LOCK;
    LockState lockState;
    simManager->GetSimState(1, simState);
    simManager->GetSimState(0, simState);
    simManager->GetSimIccStatus(1, iccSimStatus);
    simManager->GetSimIccStatus(0, iccSimStatus);
    simManager->GetCardType(1, cardType);
    simManager->GetCardType(0, cardType);
    simManager->SetModemInit(0, true);
    simManager->SetModemInit(-1, true);
    simManager->UnlockPin(1, "", response);
    simManager->UnlockPin(0, "", response);
    simManager->UnlockPuk(1, "", "", response);
    simManager->UnlockPuk(0, "", "", response);
    simManager->AlterPin(1, "", "", response);
    simManager->AlterPin(0, "", "", response);
    simManager->SetLockState(1, lockInfo, response);
    simManager->SetLockState(0, lockInfo, response);
    simManager->GetLockState(1, lockType, lockState);
    simManager->GetLockState(0, lockType, lockState);
    simManager->RefreshSimState(0);
    simManager->RefreshSimState(-1);
    EXPECT_TRUE(simManager->UnlockPin2(1, "", response) == TELEPHONY_ERR_NO_SIM_CARD);
    simManager->UnlockPin2(0, "", response);
}

HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_Expand002, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<MockTelRilManager>();
    auto simManager = std::make_shared<SimManagerMock>(telRilManager);

    IccAccountInfo iccAccountInfo;
    simManager->slotCount_ = 1;
    simManager->GetSimAccountInfo(0, true, iccAccountInfo);
    simManager->SetDefaultSmsSlotId(0);
    simManager->SetDefaultCellularDataSlotId(0);
    simManager->SetPrimarySlotId(0, true);

    simManager->InitSingleSimObject();
    simManager->InitMultiSimObject();

    LockStatusResponse response;
    PersoLockInfo persoLockInfo;
    EXPECT_TRUE(simManager->UnlockPuk2(1, "", "", response) == TELEPHONY_ERR_NO_SIM_CARD);
    simManager->UnlockPuk2(0, "", "", response);
    simManager->AlterPin2(1, "", "", response);
    simManager->AlterPin2(0, "", "", response);
    simManager->UnlockSimLock(1, persoLockInfo, response);
    simManager->UnlockSimLock(0, persoLockInfo, response);
    simManager->IsSimActive(0);
    simManager->SetActiveSim(0, true);
    simManager->SetActiveSimSatellite(-1, true);
    simManager->SetActiveSimSatellite(0, true);
    simManager->ResetSimLoadAccount(-1);
    simManager->ResetSimLoadAccount(0);
    simManager->GetSimAccountInfo(0, true, iccAccountInfo);
    simManager->SetDefaultSmsSlotId(0);
    simManager->SetDefaultCellularDataSlotId(0);
    simManager->SetPrimarySlotId(0, true);
    simManager->SetShowNumber(0, u"12345678911");
    simManager->SetShowName(0, u"123456");
}

HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_Expand003, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<MockTelRilManager>();
    auto simManager = std::make_shared<SimManagerMock>(telRilManager);

    int32_t dsdsMode;
    std::vector<IccAccountInfo> iccAccountInfoList;
    simManager->slotCount_ = 2;
    simManager->GetDefaultVoiceSlotId();
    simManager->GetDefaultSmsSlotId();
    simManager->GetDefaultCellularDataSlotId();
    simManager->GetDsdsMode(dsdsMode);
    simManager->GetActiveSimAccountInfoList(true, iccAccountInfoList);

    simManager->InitSingleSimObject();
    simManager->InitMultiSimObject();

    int32_t simId;
    std::u16string showNumber;
    OperatorConfig opc;
    bool hasOperatorPrivileges;
    SimAuthenticationResponse response;
    AuthType authType = AuthType::SIM_AUTH_EAP_AKA_TYPE;
    simManager->GetDefaultVoiceSlotId();
    simManager->GetDefaultVoiceSimId(simId);
    simManager->GetDefaultSmsSlotId();
    simManager->GetDefaultSmsSimId(simId);
    simManager->GetDefaultCellularDataSlotId();
    simManager->GetDefaultCellularDataSimId(simId);
    simManager->GetPrimarySlotId(simId);
    simManager->GetShowNumber(0, showNumber);
    simManager->GetShowName(0, showNumber);
    simManager->GetActiveSimAccountInfoList(true, iccAccountInfoList);
    simManager->GetOperatorConfigs(0, opc);
    EXPECT_TRUE(simManager->GetOperatorConfigs(-1, opc) == TELEPHONY_ERR_LOCAL_PTR_NULL);
    simManager->HasOperatorPrivileges(0, hasOperatorPrivileges);
    simManager->HasOperatorPrivileges(-1, hasOperatorPrivileges);
    simManager->SimAuthentication(1, authType, "", response);
    simManager->SimAuthentication(0, authType, "", response);

    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    simManager->GetSlotId(0);
    simManager->GetSimId(0);
    TELEPHONY_EXT_WRAPPER.DeInitTelephonyExtWrapper();

    simManager->simSmsManager_[0].reset();
    simManager->SimAuthentication(0, authType, "", response);
}

HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_Expand004, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<MockTelRilManager>();
    auto simManager = std::make_shared<SimManagerMock>(telRilManager);

    std::u16string operatorNumeric;
    std::set<std::string> ehPlmns;
    simManager->slotCount_ = 2;
    simManager->InitSingleSimObject();
    simManager->InitMultiSimObject();
    simManager->simStateManager_[1].reset();
    simManager->SendSimMatchedOperatorInfo(1, 0, "", "");
    simManager->SendSimMatchedOperatorInfo(0, 0, "", "");
    simManager->GetRadioProtocolTech(0);
    simManager->GetRadioProtocol(0);
    EXPECT_TRUE(simManager->SendEnvelopeCmd(2, "") == TELEPHONY_ERR_LOCAL_PTR_NULL);
    simManager->SendEnvelopeCmd(1, "");
    simManager->SendEnvelopeCmd(0, "");
    simManager->SendTerminalResponseCmd(2, "");
    simManager->SendTerminalResponseCmd(1, "");
    simManager->SendTerminalResponseCmd(0, "");
    simManager->SendCallSetupRequestResult(-1, true);
    simManager->SendCallSetupRequestResult(1, true);
    simManager->stkManager_[1].reset();
    simManager->SendCallSetupRequestResult(1, true);
    simManager->SendCallSetupRequestResult(0, true);
    simManager->GetSimOperatorNumeric(0, operatorNumeric);
    simManager->GetISOCountryCodeForSim(1, operatorNumeric);
    simManager->GetISOCountryCodeForSim(0, operatorNumeric);
    simManager->GetSimSpn(0, operatorNumeric);
    simManager->GetSimEons(0, "", 0, true);
    simManager->GetSimIccId(1, operatorNumeric);
    simManager->GetSimIccId(0, operatorNumeric);
    simManager->GetIMSI(1, operatorNumeric);
    simManager->GetIMSI(0, operatorNumeric);
    simManager->GetEhPlmns(1, ehPlmns);
    simManager->GetEhPlmns(0, ehPlmns);
    simManager->GetSpdiPlmns(1, ehPlmns);
    simManager->GetSpdiPlmns(0, ehPlmns);
    simManager->simFileManager_[0].reset();
    simManager->GetSimOperatorNumeric(0, operatorNumeric);
    simManager->GetISOCountryCodeForSim(0, operatorNumeric);
    simManager->GetSimSpn(0, operatorNumeric);
    simManager->GetSimIccId(0, operatorNumeric);
    simManager->GetIMSI(0, operatorNumeric);
    simManager->GetEhPlmns(0, ehPlmns);
    simManager->GetSpdiPlmns(0, ehPlmns);
}

HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_Expand005, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<MockTelRilManager>();
    auto simManager = std::make_shared<SimManagerMock>(telRilManager);

    bool isCTSimCard;
    std::u16string gid;
    int32_t count;
    simManager->slotCount_ = 2;
    simManager->InitSingleSimObject();
    simManager->InitMultiSimObject();
    simManager->GetLocaleFromDefaultSim(0);
    EXPECT_TRUE(simManager->GetSimGid1(1, gid) == TELEPHONY_ERR_NO_SIM_CARD);
    simManager->GetSimGid1(0, gid);
    simManager->GetSimGid2(0);
    simManager->GetOpName(0, gid);
    simManager->GetOpKey(0, gid);
    simManager->GetOpKeyExt(0, gid);
    simManager->GetSimTelephoneNumber(0, gid);
    simManager->GetSimTelephoneNumber(2, gid);
    simManager->GetSimTeleNumberIdentifier(2);
    simManager->GetSimTeleNumberIdentifier(0);
    simManager->GetVoiceMailIdentifier(1, gid);
    simManager->GetVoiceMailIdentifier(0, gid);
    simManager->GetVoiceMailNumber(1, gid);
    simManager->GetVoiceMailNumber(0, gid);
    simManager->GetVoiceMailCount(1, count);
    simManager->GetVoiceMailCount(0, count);
    simManager->SetVoiceCallForwarding(1, true, "");
    simManager->SetVoiceCallForwarding(0, true, "");
    simManager->SetVoiceMailInfo(0, u"", u"");
    simManager->IsCTSimCard(1, isCTSimCard);
    simManager->IsCTSimCard(0, isCTSimCard);
    simManager->simFileManager_[0].reset();
    simManager->GetLocaleFromDefaultSim(0);
    simManager->GetSimGid1(0, gid);
    simManager->GetSimGid2(0);
    simManager->GetOpName(0, gid);
    simManager->GetOpName(2, gid);
    simManager->GetOpKey(0, gid);
    simManager->GetOpKey(2, gid);
    simManager->GetOpKeyExt(0, gid);
    simManager->GetOpKeyExt(2, gid);
    simManager->GetVoiceMailIdentifier(0, gid);
    simManager->GetVoiceMailNumber(0, gid);
    simManager->GetVoiceMailCount(0, count);
    simManager->SetVoiceCallForwarding(0, true, "");
    simManager->SetVoiceMailInfo(0, u"", u"");
    simManager->IsCTSimCard(0, isCTSimCard);
}

HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_Expand006, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<MockTelRilManager>();
    auto simManager = std::make_shared<SimManagerMock>(telRilManager);
    std::string pdu;
    std::string smsc;
    int32_t imsSwitch;
    ImsCapFromChip imsCapFromChip;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    std::shared_ptr<DiallingNumbersInfo> diallingNumber = nullptr;
    sptr<SimAccountCallback> callback;
    AuthType authType = AuthType::SIM_AUTH_EAP_AKA_TYPE;
    SimAuthenticationResponse response;
    simManager->IsSetPrimarySlotIdInProgress();
    simManager->IsDataShareError();
    simManager->ResetDataShareError();
    simManager->slotCount_ = 2;
    simManager->simStateManager_.resize(1);
    simManager->simStateManager_[0].reset();
    simManager->GetSimIO(0, 0, 0, "12345678", "", response);
    simManager->InitMultiSimObject();
    simManager->InitSingleSimObject();
    simManager->AddSmsToIcc(0, 0, pdu, smsc);
    simManager->UpdateSmsIcc(0, 0, 0, pdu, smsc);
    simManager->DelSmsIcc(0, 0);
    simManager->ObtainAllSmsOfIcc(0);
    simManager->QueryIccDiallingNumbers(0, 0, result);
    simManager->AddIccDiallingNumbers(0, 0, diallingNumber);
    simManager->RefreshCache(0);
    simManager->DelIccDiallingNumbers(0, 0, diallingNumber);
    simManager->UpdateIccDiallingNumbers(0, 0, diallingNumber);
    simManager->IsValidAuthType(authType);
    simManager->IsValidSlotIdForDefault(0);
    simManager->GetSimIst(2);
    simManager->GetSimIst(0);
    EXPECT_TRUE(simManager->SaveImsSwitch(2, 0) == TELEPHONY_ERR_ARGUMENT_INVALID);
    simManager->SaveImsSwitch(0, 0);
    simManager->QueryImsSwitch(2, imsSwitch);
    simManager->QueryImsSwitch(0, imsSwitch);
    simManager->RegisterSimAccountCallback(0, callback);
    simManager->UnregisterSimAccountCallback(callback);
    simManager->IsSetActiveSimInProgress(0);
    simManager->IsSetPrimarySlotIdInProgress();
    simManager->GetSimIO(1, 0, 0, "", "", response);
    simManager->GetSimIO(0, 0, 0, "", "", response);
    simManager->GetSimIO(0, 0, 0, "12345678", "", response);
    simManager->IsDataShareError();
    simManager->ResetDataShareError();
    simManager->UpdateImsCapFromChip(0, imsCapFromChip);
}

HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_Expand007, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<MockTelRilManager>();
    auto simManager = std::make_shared<SimManagerMock>(telRilManager);

    SimLabel simLabel;
    SimType simType = SimType::ESIM;
    std::vector<IccAccountInfo> iccAccountInfoList;
    simManager->slotCount_ = 2;

    simManager->InsertEsimData("", 0, "");
    simManager->SetSimLabelIndexByIccId("", 0);
    simManager->GetAllSimAccountInfoList(true, iccAccountInfoList);
    simManager->IsEsim(0);
    simManager->ClearSimLabel(simType);
    simManager->UpdateSimPresent(0, true);
    simManager->UpdateEsimOpName("", "");
    simManager->CheckIfNeedSwitchMainSlotId(true);
    simManager->SetTargetPrimarySlotId(true, 0);

    simManager->InitMultiSimObject();
    simManager->InitSingleSimObject();

    simManager->GetDefaultMainSlotByIccId();
    EXPECT_TRUE(simManager->GetSimLabel(2, simLabel) == INVALID_VALUE);
    simManager->GetSimLabel(0, simLabel);
    simManager->InsertEsimData("", 0, "");
    simManager->SetSimLabelIndexByIccId("", 0);
    simManager->NotifySimSlotsMapping(1);
    simManager->NotifySimSlotsMapping(0);
    simManager->GetAllSimAccountInfoList(true, iccAccountInfoList);
    simManager->IsEsim(0);
    simManager->ClearSimLabel(simType);
    simManager->UpdateSimPresent(0, true);
    simManager->UpdateEsimOpName("", "");
    simManager->CheckIfNeedSwitchMainSlotId(true);
    simManager->SetIccCardState(1, 0);
    simManager->SetIccCardState(0, 0);
    simManager->SetTargetPrimarySlotId(true, 0);
    simManager->IsModemInitDone(2);
    simManager->IsModemInitDone(0);

    simManager->simStateManager_[0].reset();
    simManager->SetIccCardState(0, 0);
    simManager->GetMaxSimCount();
    simManager->GetRealSimCount();
}
/**
 * @tc.number   Telephony_Sim_SimManager_0100
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t ret = simManager_->InitTelExtraModule(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERROR);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0200
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_002, Function | MediumTest | Level1)
{
    int32_t simId = 0;
    int32_t ret = simManager_->GetDefaultSmsSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0300
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_003, Function | MediumTest | Level1)
{
    int32_t simId = 0;
    int32_t ret = simManager_->GetDefaultCellularDataSimId(simId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0400
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_004, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t ret = simManager_->UpdateOperatorConfigs(slotId);
    EXPECT_EQ(ret, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   Telephony_Sim_SimManager_0500
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_005, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "ABCDEFG";
    std::string path = "";
    SimAuthenticationResponse mResponse;
    IccSimStatus iccStatus = IccSimStatus::ICC_CONTENT_READY;
    CardType cardType = CardType::SINGLE_MODE_USIM_CARD;

    int32_t ret = simManager_->GetSimIO(slotId, command, fileId, data, path, mResponse);
    EXPECT_EQ(ret, TELEPHONY_ERR_NO_SIM_CARD);
    auto simManager = std::make_shared<MockSimManager>();
    EXPECT_CALL(*simManager, HasSimCard(slotId, _))
        .WillRepeatedly(Return(true));
    simManager->GetSimIccStatus(slotId, iccStatus);
    simManager->GetCardType(slotId, cardType);
    ret = simManager->GetSimIO(slotId, command, fileId, data, path, mResponse);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_SimManager_006
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_006, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    simManager_->UpdateImsCapFromChip(slotId, {0, 0, 0, 0});
    EXPECT_EQ(slotId, 0);
}

/**
 * @tc.number   Telephony_Sim_SimManager_007
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_007, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    simManager_->UpdateImsCapFromChip(slotId, {0, 0, 0, 0});
    EXPECT_EQ(slotId, -1);
}

/**
 * @tc.number   Telephony_Sim_SimManager_008
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_008, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    simManager_->UpdateImsCapFromChip(slotId, {0, 0, 0, 0});
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

/**
 * @tc.number   Telephony_Sim_SimManager_009
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_009, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::set<std::string> ehPlmns;
    std::set<std::string> spdiPlmns;
    simManager_->GetEhPlmns(slotId, ehPlmns);
    simManager_->GetSpdiPlmns(slotId, spdiPlmns);
    simManager_->slotCount_  = -1;
    simManager_->InitMultiSimObject();
    simManager_->slotCount_  = 10;
    simManager_->InitMultiSimObject();
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

/**
 * @tc.number   Telephony_Sim_SimManager_010
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_010, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<MultiSimControllerMock> multiSimControllerMock =
        std::make_shared<MultiSimControllerMock>(telRilManager, simStateManager, simFileManager);
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
        std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    int32_t slotId = 0;
    simManager_->multiSimController_ = multiSimController;
    simManager_->SetActiveSim(slotId, 0);
    slotId = -1;
    simManager_->SetActiveSim(slotId, 0);
    slotId = 4;
    simManager_->SetActiveSim(slotId, 0);
    EXPECT_CALL(*multiSimControllerMock, SetActiveSim(_, _, _)).Times(AnyNumber()).
        WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    simManager_->SetActiveSim(slotId, 0);
    EXPECT_CALL(*multiSimControllerMock, SetActiveSim(_, _, _)).Times(AnyNumber()).
        WillOnce(Return(TELEPHONY_ERR_ARGUMENT_INVALID));
    simManager_->SetActiveSim(slotId, 0);
    slotId = 0;
    simManager_->multiSimController_ = nullptr;
    simManager_->SetActiveSim(slotId, 0);
    simManager_->SetActiveSim(slotId, 0);
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

/**
 * @tc.number   Telephony_Sim_SimManager_011
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_011, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    simManager_->SetActiveSimSatellite(slotId, 0);
    slotId = -1;
    simManager_->SetActiveSimSatellite(slotId, 0);
    slotId = 4;
    simManager_->SetActiveSimSatellite(slotId, 0);
    slotId = 0;
    simManager_->multiSimController_ = nullptr;
    simManager_->SetActiveSimSatellite(slotId, 0);
    telRilManager_ = new MockTelRilManager();
    simManager_->SetActiveSimSatellite(slotId, 0);
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

/**
 * @tc.number   Telephony_Sim_SimManager_012
 * @tc.name     SimManager
 * @tc.desc     Function test
 */
HWTEST_F(SimManagerTest, Telephony_Sim_SimManager_012, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    simManager_->SetDefaultCellularDataSlotId(slotId);
    simManager_->ResetSimLoadAccount(slotId);
    slotId = -1;
    simManager_->SetDefaultCellularDataSlotId(slotId);
    simManager_->ResetSimLoadAccount(slotId);
    slotId = 4;
    simManager_->ResetSimLoadAccount(slotId);
    slotId = 0;
    simManager_->multiSimController_ = nullptr;
    simManager_->ResetSimLoadAccount(slotId);
    simManager_->ResetSimLoadAccount(slotId);
    simManager_->SetDefaultCellularDataSlotId(slotId);
    EXPECT_TRUE(simManager_->simFileManager_.empty());
}

HWTEST_F(SimManagerTest, GetSimIccStatustest, Function | MediumTest | Level1)
{
    IccSimStatus status;
    int32_t result = simManager_->GetSimIccStatus(-1, status);
    EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);

    simManager_->simStateManager_.resize(MAX_SLOT_COUNT);
    result = simManager_->InitTelExtraModule(SIM_SLOT_2);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);

    result = simManager_->InitTelExtraModule(SIM_SLOT_2);
    EXPECT_EQ(result, TELEPHONY_SUCCESS);
}

HWTEST_F(SimManagerTest, SetModemInittest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    bool state = true;
    int32_t result = simManager_->SetModemInit(slotId, state);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = -1;
    state = true;
    result = simManager_->SetModemInit(slotId, state);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    state = true;
    simManager_->simStateManager_[slotId] = nullptr;
    result = simManager_->SetModemInit(slotId, state);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimManagerTest, UnlockPintest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::string pin = "1234";
    LockStatusResponse response;
    simManager_->simStateManager_[slotId] = nullptr;
    int32_t result = simManager_->UnlockPin(slotId, pin, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPin2(slotId, pin, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);

    slotId = 0;
    std::string correctPin = "1234";
    
    result = simManager_->UnlockPin(slotId, correctPin, response);
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    result = simManager_->UnlockPin2(slotId, correctPin, response);
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);

    slotId = 0;
    std::string wrongPin = "1235";
    
    result = simManager_->UnlockPin(slotId, wrongPin, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPin2(slotId, wrongPin, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(SimManagerTest, SetLockStatetest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    LockInfo options;
    LockStatusResponse response;
    
    simManager_->simStateManager_[slotId] = nullptr;
    int32_t result = simManager_->SetLockState(slotId, options, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(SimManagerTest, RefreshSimStatetest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t result = simManager_->RefreshSimState(slotId);
    EXPECT_EQ(result, TELEPHONY_ERROR);

    slotId = -1;
    result = simManager_->RefreshSimState(slotId);
    EXPECT_EQ(result, TELEPHONY_ERROR);

    slotId = 1;
    simManager_->simStateManager_[slotId] = nullptr;
    result = simManager_->RefreshSimState(slotId);
    EXPECT_EQ(result, TELEPHONY_ERROR);
}

HWTEST_F(SimManagerTest, UnlockPuktest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::string newPin = "1234";
    std::string correctPuk = "123456";
    LockStatusResponse response;
    int32_t result = simManager_->UnlockPuk(slotId, newPin, correctPuk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPuk2(slotId, newPin, correctPuk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);

    slotId = 0;
    newPin = "1234";
    std::string wrongPuk = "123457";
    
    result = simManager_->UnlockPuk(slotId, newPin, wrongPuk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPuk2(slotId, newPin, wrongPuk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);

    slotId = -1;
    newPin = "1234";
    std::string puk = "123456";
    
    result = simManager_->UnlockPuk(slotId, newPin, puk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
    result = simManager_->UnlockPuk(slotId, newPin, puk, response);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(SimManagerTest, GetLockStatetest, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    // LockType lockType;
    LockState lockState;
    
    int32_t result = simManager_->GetLockState(slotId, LockType::PIN_LOCK, lockState);
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);

    slotId = -1;
    result = simManager_->GetLockState(slotId, LockType::PIN_LOCK, lockState);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);

    slotId = 0;
    
    simManager_->simStateManager_[slotId] = nullptr;
    result = simManager_->GetLockState(slotId, LockType::PIN_LOCK, lockState);
    EXPECT_EQ(result, TELEPHONY_ERR_NO_SIM_CARD);
}

HWTEST_F(SimManagerTest, InsertEsimDatatest, Function | MediumTest | Level1)
{
    simManager_->multiSimController_ = nullptr;
    std::string iccId = "test_icc_id";
    int32_t esimLabel = 0;
    std::string operatorName = "test_operator";
    int32_t result = simManager_->InsertEsimData(iccId, esimLabel, operatorName);
    EXPECT_EQ(result, INVALID_VALUE);
}

HWTEST_F(SimManagerTest, SetSimLabelIndex, Function | MediumTest | Level1)
{
    simManager_->multiSimController_ = nullptr;
    std::string iccId = "test_icc_id";
    int32_t labelIndex = 0;
    int32_t result = simManager_->SetSimLabelIndexByIccId(iccId, labelIndex);
    EXPECT_EQ(result, INVALID_VALUE);
}

HWTEST_F(SimManagerTest, Inserttest, Function | MediumTest | Level1)
{
    auto dataShareHelper = std::shared_ptr<DataShare::DataShareHelper>(nullptr);
    DataShare::DataShareValuesBucket values;
    SimRdbHelper simrdbhelper;
    int result = simrdbhelper.Insert(dataShareHelper, values);
    EXPECT_EQ(result, INVALID_VALUE);

    DataShare::DataSharePredicates predicates;
    result = simrdbhelper.Delete(dataShareHelper, predicates);
    EXPECT_EQ(result, INVALID_VALUE);
}

HWTEST_F(SimManagerTest, GetDefaultMainCardSlotId_01, Function | MediumTest | Level1)
{
    SimRdbHelper simrdbhelper;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;

    int32_t result = simrdbhelper.GetDefaultMainCardSlotId();
    EXPECT_EQ(result, 0);

    result = simrdbhelper.GetDefaultMainCardSlotId();
    EXPECT_EQ(result, 0);

    result = simrdbhelper.GetDefaultCellularDataCardSlotId();
    EXPECT_NE(result, 0);

    result = simrdbhelper.GetDefaultVoiceCardSlotId();
    EXPECT_NE(result, 0);

    result = simrdbhelper.SetDefaultMainCard(-1);
    EXPECT_EQ(result, INVALID_VALUE);

    result = simrdbhelper.SetDefaultMainCard(1);
    EXPECT_EQ(result, INVALID_VALUE);
}

HWTEST_F(SimManagerTest, GetDefaultMainCardSlotId_02, Function | MediumTest | Level1)
{
    SimRdbHelper simrdbhelper;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    int32_t result = simrdbhelper.SetDefaultVoiceCard(-1);
    EXPECT_EQ(result, INVALID_VALUE);

    result = simrdbhelper.SetDefaultVoiceCard(1);
    EXPECT_EQ(result, INVALID_VALUE);

    result = simrdbhelper.SetDefaultMessageCard(-1);
    EXPECT_EQ(result, INVALID_VALUE);

    result = simrdbhelper.SetDefaultMessageCard(1);
    EXPECT_EQ(result, INVALID_VALUE);

    result = simrdbhelper.SetDefaultCellularData(-1);
    EXPECT_EQ(result, INVALID_VALUE);

    result = simrdbhelper.SetDefaultCellularData(1);
    EXPECT_EQ(result, INVALID_VALUE);

    result = simrdbhelper.ClearData();
    EXPECT_EQ(result, INVALID_VALUE);
}

HWTEST_F(SimManagerTest, InsertDatatest, Function | MediumTest | Level1)
{
    auto mocksimrdbhelper = std::make_shared<MockSimRdbHelper>();
    EXPECT_CALL(*mocksimrdbhelper, CreateDataHelper(_)).WillRepeatedly(Return(nullptr));

    EXPECT_CALL(*mocksimrdbhelper, Insert(_, _)).WillRepeatedly(Return(1));

    SimRdbHelper simRdbHelper;
    int64_t id = 123;
    DataShare::DataShareValuesBucket values;
    int32_t result = simRdbHelper.InsertData(id, values);
    EXPECT_NE(result, 1);
}

HWTEST_F(SimManagerTest, UpdateSimPresentNullTest, Function | MediumTest | Level1)
{
    simManager_->multiSimController_ = nullptr;
    int32_t slotId = 0;
    int32_t result = simManager_->UpdateSimPresent(slotId, false);
    EXPECT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}
}
}