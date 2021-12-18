/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "sim_test.h"

#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Telephony {
sptr<ICoreService> SimTest::telephonyService_ = nullptr;
void SimTest::SetUpTestCase()
{
    std::cout << "----------Sim gtest start ------------" << std::endl;
    if (telephonyService_ == nullptr) {
        telephonyService_ = GetProxy();
    }
    std::cout << "Sim connect coreservice  server success!!!" << std::endl;
}

void SimTest::TearDownTestCase()
{
    std::cout << "----------Sim gtest end ------------" << std::endl;
}

void SimTest::SetUp() {}

void SimTest::TearDown() {}

sptr<ICoreService> SimTest::GetProxy()
{
    TELEPHONY_LOGI("TelephonyTestService GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        std::cout << "TelephonyTestService Get ISystemAbilityManager failed!!!" << std::endl;
        return nullptr;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote) {
        sptr<ICoreService> telephonyService = iface_cast<ICoreService>(remote);
        return telephonyService;
    } else {
        std::cout << "TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail ..." << std::endl;
        return nullptr;
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimState_0100
 * @tc.name     Get sim State
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimState_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetSimState(SimTest::slotId_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_HasSimCard_0100
 * @tc.name     Get sim State
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_HasSimCard_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->HasSimCard(SimTest::slotId_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetISOCountryCodeForSim_0100
 * @tc.name     Get sim IsoCountryCode
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetISOCountryCodeForSim_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetISOCountryCodeForSim(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimSpn_0100
 * @tc.name     Get sim service privode name
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimSpn_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimSpn(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimIccId_0100
 * @tc.name     Get sim iccid
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimIccId_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimIccId(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimOperatorNumeric_0100
 * @tc.name     Get sim iccid
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimOperatorNumeric_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimOperatorNumeric(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetIMSI_0100
 * @tc.name     Get sim imsi
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetIMSI_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetIMSI(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimGid1_0100
 * @tc.name     Get sim gid1
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimGid1_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimGid1(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0100
 * @tc.name     Get sim gid1
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTelephoneNumber_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(TelephoneNumber)
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimTelephoneNumber(SimTest::slotId_));
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailIdentifier_0100
 * @tc.name     Get sim gid1
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailIdentifier_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailIdentifier)
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetVoiceMailIdentifier(SimTest::slotId_));
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailNumber_0100
 * @tc.name     Get sim VoiceMailNumber
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailNumber_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailNumber)
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetVoiceMailNumber(SimTest::slotId_));
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_GetDefaultVoiceSlotId_0100
 * @tc.name     Get sim GetDefaultVoiceSlotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetDefaultVoiceSlotId_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetDefaultVoiceSlotId();
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_SetDefaultVoiceSlotId_0100
 * @tc.name     Get sim SetDefaultVoiceSlotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetDefaultVoiceSlotId_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        bool result = SimTest::telephonyService_->SetDefaultVoiceSlotId(SimTest::slotId_);
        EXPECT_TRUE(result);
    }
}


/**
 * @tc.number   Telephony_Sim_RefreshSimState_0100
 * @tc.name     Get sim RefreshSimState
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_RefreshSimState_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->RefreshSimState(SimTest::slotId_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOperatorConfig_0100
 * @tc.name     Get sim GetOperatorConfigs
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOperatorConfig_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        OperatorConfig oc;
        bool result = SimTest::telephonyService_->GetOperatorConfigs(SimTest::slotId_, oc);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_GetActiveSimAccountInfoList_0100
 * @tc.name     Get sim GetActiveSimAccountInfoList
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetActiveSimAccountInfoList_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<IccAccountInfo> iccAccountInfoList;
        bool result = SimTest::telephonyService_->GetActiveSimAccountInfoList(iccAccountInfoList);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccAdnDiallingNumbers_0100
 * @tc.name     Get sim QueryIccAdnDiallingNumbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
            SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId_,
                    DiallingNumbersInfo::SIM_ADN);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0100
 * @tc.name     Get sim AddIccAdnDiallingNumbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("SimAdn17789145956");
        bool result =  SimTest::telephonyService_->AddIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccAdnDiallingNumbers_0100
 * @tc.name     Get sim QueryIccAdnDiallingNumbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccAdnDiallingNumbers_0101, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
                SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId_,
                    DiallingNumbersInfo::SIM_ADN);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_UpdateIccAdnDiallingNumbers_0100
 * @tc.name     Get sim UpdateIccAdnDiallingNumbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UpdateIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        diallingNumber->index_ = index;
        bool result = SimTest::telephonyService_->UpdateIccDiallingNumbers(SimTest::slotId_,
                    DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccAdnDiallingNumbers_0100
 * @tc.name     Get sim QueryIccAdnDiallingNumbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccAdnDiallingNumbers_0102, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
            SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId_,
                    DiallingNumbersInfo::SIM_ADN);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_DelIccAdnDiallingNumbers_0100
 * @tc.name     Get sim DelIccAdnDiallingNumbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_DelIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>();
        diallingNumber->index_ = index;
        bool result = SimTest::telephonyService_->DelIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_SetShowName_0100
 * @tc.name     Get sim SetShowName
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowName_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string cardName = Str8ToStr16("SimNameZhang");
        bool result = SimTest::telephonyService_->SetShowName(SimTest::slotId_, cardName);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_getShowName_0100
 * @tc.name     Get sim getShowName
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowName_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetShowName(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_getShowNumber_0100
 * @tc.name     Get sim getShowNumber
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowNumber_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetShowNumber(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_SetShowNumber_0100
 * @tc.name     Get sim SetShowNumber
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowNumber_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string cardNumber = Str8ToStr16("SimNumber17789145956");
        bool result = SimTest::telephonyService_->SetShowNumber(SimTest::slotId_, cardNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_IsSimActive_0100
 * @tc.name     Get sim IsSimActive
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_IsSimActive_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->IsSimActive(SimTest::slotId_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_GetSimAccountInfo_0100
 * @tc.name     Get sim GetSimAccountInfo
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimAccountInfo_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        IccAccountInfo info;
        bool result = SimTest::telephonyService_->GetSimAccountInfo(SimTest::slotId_, info);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_SetLockState_0100
 * @tc.name     Get sim SetLockState
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetLockState_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string pin = Str8ToStr16("1234");
        int32_t enable = 0;
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->SetLockState(SimTest::slotId_, pin, enable, response);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockPin_0100
 * @tc.name     Get sim UnlockPin
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPin_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string pin = Str8ToStr16("1234");
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->UnlockPin(SimTest::slotId_, pin, response);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockPuk_0100
 * @tc.name     Get sim UnlockPuk
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPuk_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string pin = Str8ToStr16("1234");
        const std::u16string puk = Str8ToStr16("42014264");
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->UnlockPuk(SimTest::slotId_, pin, puk, response);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_AlterPin_0100
 * @tc.name     Get sim AlterPin
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AlterPin_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string newpin = Str8ToStr16("1234");
        const std::u16string oldpin = Str8ToStr16("4321");
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId_, newpin, oldpin, response);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockPin2_0100
 * @tc.name     Get sim UnlockPin2
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPin2_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string pin2 = Str8ToStr16("12345678");
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->UnlockPin2(SimTest::slotId_, pin2, response);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockPuk2_0100
 * @tc.name     Get sim UnlockPuk2
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPuk2_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string pin2 = Str8ToStr16("12345678");
        const std::u16string puk2 = Str8ToStr16("42014264");
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId_, pin2, puk2, response);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_AlterPin2_0100
 * @tc.name     Get sim AlterPin2
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AlterPin2_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string newpin2 = Str8ToStr16("12345678");
        const std::u16string oldpin2 = Str8ToStr16("42014264");
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId_, newpin2, oldpin2, response);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_SetActiveSim_0100
 * @tc.name     Get sim UnlockPuk
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetActiveSim_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int enable = 1;
        bool result = SimTest::telephonyService_->SetActiveSim(SimTest::slotId_, enable);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_ReSetActiveSim_0100
 * @tc.name     Get sim UnlockPuk
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ReSetActiveSim_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int enable = 1;
        bool result = SimTest::telephonyService_->SetActiveSim(SimTest::slotId_, enable);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_GetMaxSimCount_0100
 * @tc.name     Get sim GetMaxSimCount
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetMaxSimCount_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr ||
        !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetMaxSimCount();
        EXPECT_GT(result, -1);
    }
}
} // namespace Telephony
} // namespace OHOS
