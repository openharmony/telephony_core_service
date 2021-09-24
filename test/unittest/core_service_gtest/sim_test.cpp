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

#include <unistd.h>
#include <gtest/gtest.h>
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "core_service_proxy.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
const int32_t slotId = 0;

class SimTest : public testing::Test {
public:
    // execute before first testcase
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    static void TearDownTestCase();

    static sptr<ICoreService> GetProxy();
    static sptr<ICoreService> telephonyService_;
};

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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetSimState(slotId);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimState_0100
 * @tc.name     Get sim State
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_HasSimCard_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->HasSimCard(slotId);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetIsoCountryCodeForSim_0100
 * @tc.name     Get sim IsoCountryCode
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetIsoCountryCodeForSim_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetIsoCountryCodeForSim(slotId));
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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimSpn(slotId));
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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimIccId(slotId));
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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimOperatorNumeric(slotId));
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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetIMSI(slotId));
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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimGid1(slotId));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_GetSimAccountInfo_0100
 * @tc.name     Get sim GetSimAccountInfo
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimAccountInfo_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        IccAccountInfo info;
        bool result = SimTest::telephonyService_->GetSimAccountInfo(slotId, info);
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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string pin = Str8ToStr16("1234");
        int32_t enable = 1;
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->SetLockState(pin, enable, response, slotId);
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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string pin = Str8ToStr16("1234");
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->UnlockPin(pin, response, slotId);
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
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string pin = Str8ToStr16("1234");
        const std::u16string puk = Str8ToStr16("42014264");
        LockStatusResponse response = {0};
        bool result = SimTest::telephonyService_->UnlockPuk(pin, puk, response, slotId);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_GetDefaultVoiceSlotId_0100
 * @tc.name     Get sim GetDefaultVoiceSlotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetDefaultVoiceSlotId_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetDefaultVoiceSlotId();
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_SetDefaultVoiceSlotId_0100
 * @tc.name     Get sim GetDefaultVoiceSlotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetDefaultVoiceSlotId_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        SimTest::telephonyService_ = GetProxy();
    } else {
        bool result = SimTest::telephonyService_->SetDefaultVoiceSlotId(slotId);
        EXPECT_TRUE(result);
    }
}
} // namespace Telephony
} // namespace OHOS
