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
#include <gtest/gtest.h>
#include <string_ex.h>

#include "core_service_test.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_service.h"
#include "core_service_client.h"
#include "core_service_dump_helper.h"
#include "core_service_hisysevent.h"
#include "network_search_manager.h"
#include "operator_name.h"
#include "operator_name_utils.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int32_t NR_NSA_OPTION_ONLY = 1;
static const int32_t SLEEP_TIME = 3;
class CoreServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void CoreServiceTest::SetUpTestCase() {}

void CoreServiceTest::TearDownTestCase()
{
    sleep(SLEEP_TIME);
}

void CoreServiceTest::SetUp() {}

void CoreServiceTest::TearDown() {}

/**
 * @tc.number   CoreService_SetNetworkSelectionMode_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetNetworkSelectionMode_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetNetworkSelectionMode(
        0, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetRadioState_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetRadioState_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetRadioState(0, true, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetImei_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetImei_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string imei = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetImei(0, imei);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetImeiSv_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetImeiSv_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string imeiSv = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetImeiSv(0, imeiSv);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetMeid_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetMeid_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string meid = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetMeid(0, meid);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetUniqueDeviceId_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetUniqueDeviceId_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string deviceId = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetUniqueDeviceId(0, deviceId);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetNrOptionMode_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetNrOptionMode_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t mode = NR_NSA_OPTION_ONLY;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetNrOptionMode(0, mode, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetNrOptionMode_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetNrOptionMode_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNrOptionMode(0, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetDsdsMode_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetDsdsMode_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t dsdsMode;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetDsdsMode(dsdsMode);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetSimIccId_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetSimIccId_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string iccId = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimIccId(0, iccId);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetIMSI_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetIMSI_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string imsi = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetIMSI(0, imsi);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_IsCTSimCard_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_IsCTSimCard_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    bool isCTSimCard = false;
    auto result = DelayedSingleton<CoreService>::GetInstance()->IsCTSimCard(0, isCTSimCard);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetNetworkSearchInformation_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetNetworkSearchInformation_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNetworkSearchInformation(0, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetSimGid1_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetSimGid1_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string gid1 = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimGid1(0, gid1);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetDefaultVoiceSlotId_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetDefaultVoiceSlotId_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetDefaultVoiceSlotId(0);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetPrimarySlotId_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetPrimarySlotId_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetPrimarySlotId(0);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetShowNumber_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetShowNumber_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string number = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetShowNumber(0, number);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetShowNumber_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetShowNumber_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string showNumber = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetShowNumber(0, showNumber);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetShowName_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetShowName_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string name = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetShowName(0, name);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetShowName_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetShowName_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string showName = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetShowName(0, showName);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetOperatorConfigs_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetOperatorConfigs_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    OperatorConfig poc;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetOperatorConfigs(0, poc);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_UnlockPin_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_UnlockPin_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string pin = u"";
    LockStatusResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->UnlockPin(0, pin, response);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_UnlockPuk_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_UnlockPuk_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string newPin = u"";
    std::u16string puk = u"";
    LockStatusResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->UnlockPuk(0, newPin, puk, response);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_AlterPin_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_AlterPin_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string newPin = u"";
    std::u16string oldPin = u"";
    LockStatusResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->AlterPin(0, newPin, oldPin, response);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_UnlockPin2_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_UnlockPin2_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string pin2 = u"";
    LockStatusResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->UnlockPin2(0, pin2, response);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_UnlockPuk2_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_UnlockPuk2_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string newPin2 = u"";
    std::u16string puk2 = u"";
    LockStatusResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->UnlockPuk2(0, newPin2, puk2, response);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_AlterPin2_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_AlterPin2_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string newPin2 = u"";
    std::u16string oldPin2 = u"";
    LockStatusResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->AlterPin2(0, newPin2, oldPin2, response);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetLockState_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetLockState_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    LockInfo options;
    LockStatusResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetLockState(0, options, response);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetLockState_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetLockState_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    LockType lockType = LockType::PIN_LOCK;
    LockState lockState;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetLockState(0, lockType, lockState);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetActiveSim_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetActiveSim_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetActiveSim(0, true);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetPreferredNetwork_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetPreferredNetwork_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetPreferredNetwork(0, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetPreferredNetwork_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetPreferredNetwork_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t networkMode = 0;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetPreferredNetwork(0, networkMode, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetNetworkCapability_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetNetworkCapability_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t networkCapabilityType = 0;
    int32_t networkCapabilityState = 0;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNetworkCapability(0, networkCapabilityType,
        networkCapabilityState);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetNetworkCapability_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetNetworkCapability_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t networkCapabilityType = 0;
    int32_t networkCapabilityState = 0;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetNetworkCapability(0, networkCapabilityType,
        networkCapabilityState);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetSimTelephoneNumber_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetSimTelephoneNumber_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string telephoneNumber = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimTelephoneNumber(0, telephoneNumber);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetVoiceMailIdentifier_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetVoiceMailIdentifier_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string voiceMailIdentifier = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetVoiceMailIdentifier(0, voiceMailIdentifier);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetVoiceMailNumber_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetVoiceMailNumber_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string voiceMailNumber = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetVoiceMailNumber(0, voiceMailNumber);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetVoiceMailCount_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetVoiceMailCount_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t voiceMailCount;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetVoiceMailCount(0, voiceMailCount);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_QueryIccDiallingNumbers_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_QueryIccDiallingNumbers_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbersInfo;
    auto result = DelayedSingleton<CoreService>::GetInstance()->QueryIccDiallingNumbers(0, 0, diallingNumbersInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_AddIccDiallingNumbers_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_AddIccDiallingNumbers_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->AddIccDiallingNumbers(0, 0, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_DelIccDiallingNumbers_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_DelIccDiallingNumbers_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->DelIccDiallingNumbers(0, 0, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_UpdateIccDiallingNumbers_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_UpdateIccDiallingNumbers_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->UpdateIccDiallingNumbers(0, 0, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SetVoiceMailInfo_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SetVoiceMailInfo_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string mailName = u"";
    std::u16string mailNumber = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetVoiceMailInfo(0, mailName, mailNumber);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SendEnvelopeCmd_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SendEnvelopeCmd_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::string cmd = "";
    auto result = DelayedSingleton<CoreService>::GetInstance()->SendEnvelopeCmd(0, cmd);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SendTerminalResponseCmd_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SendTerminalResponseCmd_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::string cmd = "";
    auto result = DelayedSingleton<CoreService>::GetInstance()->SendTerminalResponseCmd(0, cmd);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SendCallSetupRequestResult_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SendCallSetupRequestResult_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SendCallSetupRequestResult(0, true);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_UnlockSimLock_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_UnlockSimLock_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    PersoLockInfo lockInfo;
    LockStatusResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->UnlockSimLock(0, lockInfo, response);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetImsRegStatus_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetImsRegStatus_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    ImsServiceType imsSrvType = ImsServiceType::TYPE_VOICE;
    ImsRegInfo info;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetImsRegStatus(0, imsSrvType, info);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetCellInfoList_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetCellInfoList_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::vector<sptr<CellInformation>> cellInfo;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetCellInfoList(0, cellInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_SendUpdateCellLocationRequest_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_SendUpdateCellLocationRequest_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SendUpdateCellLocationRequest(0);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_RegisterImsRegInfoCallback_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_RegisterImsRegInfoCallback_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    ImsServiceType imsSrvType = ImsServiceType::TYPE_VOICE;
    auto result = DelayedSingleton<CoreService>::GetInstance()->RegisterImsRegInfoCallback(0, imsSrvType, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_UnregisterImsRegInfoCallback_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_UnregisterImsRegInfoCallback_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    ImsServiceType imsSrvType = ImsServiceType::TYPE_VOICE;
    auto result = DelayedSingleton<CoreService>::GetInstance()->UnregisterImsRegInfoCallback(0, imsSrvType);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetBasebandVersion_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetBasebandVersion_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::string version = "";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetBasebandVersion(0, version);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_FactoryReset_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_FactoryReset_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->FactoryReset(0);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetNrSsbIdInfo_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetNrSsbIdInfo_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNrSsbIdInfo(0, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API);
}

/**
 * @tc.number   CoreService_GetResidentNetworkNumeric_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceTest, CoreService_GetResidentNetworkNumeric_001, Function | MediumTest | Level1)
{
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetResidentNetworkNumeric(0);
    ASSERT_STREQ(result.c_str(), "");
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = nullptr;
    result = DelayedSingleton<CoreService>::GetInstance()->GetResidentNetworkNumeric(0);
    ASSERT_STREQ(result.c_str(), "");
}

} // namespace Telephony
} // namespace OHOS