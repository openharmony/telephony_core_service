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

#include <string>
#include <unistd.h>

#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_state_type.h"
#include "sim_test_util.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_Sim_CoreService_0100
 * @tc.name    CoreService
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_CoreService_0100, Function | MediumTest | Level3)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    sptr<INetworkSearchCallback> callback = nullptr;
    mCoreService->SetRadioState(0, true, callback);
    std::u16string testU16Str = u"";
    EXPECT_NE(mCoreService->GetImei(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetImeiSv(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetMeid(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetUniqueDeviceId(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetNrOptionMode(0, callback), TELEPHONY_ERR_SUCCESS);
    std::vector<sptr<CellInformation>> cellInfo = {};
    EXPECT_NE(mCoreService->GetCellInfoList(0, cellInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimIccId(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetIMSI(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    mCoreService->GetNetworkSearchInformation(0, callback);
    EXPECT_NE(mCoreService->GetSimGid1(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    sptr<NetworkInformation> mNetworkInformation = nullptr;
    mCoreService->SetNetworkSelectionMode(0, 1, mNetworkInformation, true, callback);
    LockStatusResponse mLockStatusResponse;
    EXPECT_NE(mCoreService->UnlockPin(0, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UnlockPuk(0, testU16Str, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->AlterPin(0, testU16Str, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UnlockPin2(0, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UnlockPuk2(0, testU16Str, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->AlterPin2(0, testU16Str, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    LockInfo mLockInfo;
    EXPECT_NE(mCoreService->SetLockState(0, mLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    LockState mLockState;
    EXPECT_NE(mCoreService->GetLockState(0, LockType::PIN_LOCK, mLockState), TELEPHONY_ERR_SUCCESS);
    IccAccountInfo mIccAccountInfo;
    EXPECT_NE(mCoreService->GetSimAccountInfo(0, mIccAccountInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SetDefaultVoiceSlotId(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetDefaultVoiceSlotId(), TELEPHONY_ERR_SUCCESS);
    mCoreService->SetPrimarySlotId(INVALID_VALUE);
    mCoreService->GetPreferredNetwork(0, callback);
    mCoreService->SetPreferredNetwork(0, 1, callback);
    EXPECT_NE(mCoreService->SetShowNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetShowNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SetShowName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetShowName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->RefreshSimState(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SetActiveSim(0, 1), TELEPHONY_ERR_SUCCESS);
    int32_t dsdsMode = INVALID_VALUE;
    EXPECT_NE(mCoreService->GetDsdsMode(dsdsMode), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_CoreService_0200
 * @tc.name    CoreService
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_CoreService_0200, Function | MediumTest | Level3)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::string testStr = "";
    std::u16string testU16Str = u"";
    EXPECT_NE(mCoreService->SendEnvelopeCmd(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SendTerminalResponseCmd(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SendCallSetupRequestResult(0, true), TELEPHONY_ERR_SUCCESS);
    PersoLockInfo mPersoLockInfo;
    LockStatusResponse mLockStatusResponse;
    EXPECT_NE(mCoreService->UnlockSimLock(0, mPersoLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    mCoreService->SendUpdateCellLocationRequest(0);
    SimAuthenticationResponse mSimAuthenticationResponse;
    EXPECT_NE(mCoreService->SimAuthentication(0, AuthType::SIM_AUTH_EAP_SIM_TYPE, "", mSimAuthenticationResponse),
        TELEPHONY_ERR_SUCCESS);
    const sptr<ImsRegInfoCallback> mImsRegInfoCallback = nullptr;
    EXPECT_NE(mCoreService->RegisterImsRegInfoCallback(0, ImsServiceType::TYPE_VOICE, mImsRegInfoCallback),
        TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UnregisterImsRegInfoCallback(0, ImsServiceType::TYPE_VOICE), TELEPHONY_ERR_SUCCESS);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> reslut = {};
    EXPECT_NE(mCoreService->QueryIccDiallingNumbers(0, 1, reslut), TELEPHONY_ERR_SUCCESS);
    const std::shared_ptr<DiallingNumbersInfo> diallingNumber = nullptr;
    EXPECT_NE(mCoreService->AddIccDiallingNumbers(0, 1, diallingNumber), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->DelIccDiallingNumbers(0, 1, diallingNumber), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UpdateIccDiallingNumbers(0, 1, diallingNumber), TELEPHONY_ERR_SUCCESS);
    std::vector<IccAccountInfo> iccAccountInfoList = {};
    EXPECT_NE(mCoreService->GetActiveSimAccountInfoList(iccAccountInfoList), TELEPHONY_ERR_SUCCESS);
    OperatorConfig mOperatorConfig;
    EXPECT_NE(mCoreService->GetOperatorConfigs(0, mOperatorConfig), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimTelephoneNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetVoiceMailIdentifier(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetVoiceMailNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SetVoiceMailInfo(0, testU16Str, testU16Str), TELEPHONY_ERR_SUCCESS);
    ImsRegInfo mImsRegInfo;
    EXPECT_NE(mCoreService->GetImsRegStatus(0, ImsServiceType::TYPE_VOICE, mImsRegInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetMaxSimCount(), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetOpKey(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetOpKeyExt(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetOpName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    int32_t slotId = TELEPHONY_ERROR;
    EXPECT_NE(mCoreService->GetPrimarySlotId(slotId), TELEPHONY_ERR_SUCCESS);
    int32_t radioTech = TELEPHONY_ERROR;
    EXPECT_NE(mCoreService->GetPsRadioTech(0, radioTech), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetCsRadioTech(0, radioTech), TELEPHONY_ERR_SUCCESS);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    EXPECT_NE(mCoreService->GetSimState(0, simState), TELEPHONY_ERR_SUCCESS);
    CardType cardType = CardType::UNKNOWN_CARD;
    EXPECT_NE(mCoreService->GetCardType(0, cardType), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSlotId(1), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimId(0), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_CoreService_0300
 * @tc.name    CoreService
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_CoreService_0300, Function | MediumTest | Level3)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::string testStr = "";
    std::u16string testU16Str = u"";
    std::vector<sptr<SignalInformation>> mSignalInfoList = {};
    EXPECT_NE(mCoreService->GetSignalInfoList(0, mSignalInfoList), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mCoreService->GetOperatorNumeric(0), testU16Str);
    EXPECT_NE(mCoreService->GetOperatorName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimOperatorNumeric(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetISOCountryCodeForSim(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimSpn(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mCoreService->GetLocaleFromDefaultSim(), testU16Str);
    EXPECT_EQ(mCoreService->GetSimGid2(0), testU16Str);
    std::string plmn = "46001";
    int32_t lac = 1;
    bool longNameRequired = true;
    EXPECT_EQ(mCoreService->GetSimEons(0, plmn, lac, longNameRequired), testU16Str);
    EXPECT_NE(mCoreService->GetIsoCountryCodeForNetwork(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mCoreService->GetSimTeleNumberIdentifier(0), testU16Str);
    sptr<NetworkState> networkState = nullptr;
    EXPECT_NE(mCoreService->GetNetworkState(0, networkState), TELEPHONY_ERR_SUCCESS);
    sptr<INetworkSearchCallback> callback = nullptr;
    EXPECT_NE(mCoreService->GetRadioState(0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetNetworkSelectionMode(0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(mCoreService->IsNrSupported(0));
    EXPECT_FALSE(mCoreService->IsSimActive(0));
    bool hasValue = false;
    EXPECT_NE(mCoreService->HasSimCard(0, hasValue), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->HasOperatorPrivileges(0, hasValue), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_CoreService_0400
 * @tc.name    CoreService
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_CoreService_0400, Function | MediumTest | Level3)
{
    AccessToken token;
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    sptr<INetworkSearchCallback> callback = nullptr;
    mCoreService->SetRadioState(0, true, callback);
    std::u16string testU16Str = u"";
    EXPECT_NE(mCoreService->GetImei(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetImeiSv(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetMeid(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetUniqueDeviceId(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetNrOptionMode(0, callback), TELEPHONY_ERR_SUCCESS);
    std::vector<sptr<CellInformation>> cellInfo = {};
    EXPECT_NE(mCoreService->GetCellInfoList(0, cellInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimIccId(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetIMSI(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    mCoreService->GetNetworkSearchInformation(0, callback);
    EXPECT_NE(mCoreService->GetSimGid1(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    sptr<NetworkInformation> mNetworkInformation = nullptr;
    mCoreService->SetNetworkSelectionMode(0, 1, mNetworkInformation, true, callback);
    LockStatusResponse mLockStatusResponse;
    EXPECT_NE(mCoreService->UnlockPin(0, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UnlockPuk(0, testU16Str, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->AlterPin(0, testU16Str, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UnlockPin2(0, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UnlockPuk2(0, testU16Str, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->AlterPin2(0, testU16Str, testU16Str, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    LockInfo mLockInfo;
    EXPECT_NE(mCoreService->SetLockState(0, mLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    LockState mLockState;
    EXPECT_NE(mCoreService->GetLockState(0, LockType::PIN_LOCK, mLockState), TELEPHONY_ERR_SUCCESS);
    IccAccountInfo mIccAccountInfo;
    EXPECT_NE(mCoreService->GetSimAccountInfo(0, mIccAccountInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SetDefaultVoiceSlotId(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetDefaultVoiceSlotId(), TELEPHONY_ERR_SUCCESS);
    mCoreService->GetPreferredNetwork(0, callback);
    mCoreService->SetPreferredNetwork(0, 1, callback);
    EXPECT_NE(mCoreService->SetShowNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetShowNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SetShowName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetShowName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->RefreshSimState(0), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SetActiveSim(0, 1), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_CoreService_0500
 * @tc.name    CoreService
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_CoreService_0500, Function | MediumTest | Level3)
{
    AccessToken token;
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::string testStr = "";
    std::u16string testU16Str = u"";
    EXPECT_NE(mCoreService->SendEnvelopeCmd(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SendTerminalResponseCmd(0, testStr), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SendCallSetupRequestResult(0, true), TELEPHONY_ERR_SUCCESS);
    PersoLockInfo mPersoLockInfo;
    LockStatusResponse mLockStatusResponse;
    EXPECT_NE(mCoreService->UnlockSimLock(0, mPersoLockInfo, mLockStatusResponse), TELEPHONY_ERR_SUCCESS);
    mCoreService->SendUpdateCellLocationRequest(0);
    SimAuthenticationResponse mSimAuthenticationResponse;
    EXPECT_NE(mCoreService->SimAuthentication(0, AuthType::SIM_AUTH_EAP_SIM_TYPE, "", mSimAuthenticationResponse),
        TELEPHONY_ERR_SUCCESS);
    const sptr<ImsRegInfoCallback> mImsRegInfoCallback = nullptr;
    EXPECT_NE(mCoreService->RegisterImsRegInfoCallback(0, ImsServiceType::TYPE_VOICE, mImsRegInfoCallback),
        TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UnregisterImsRegInfoCallback(0, ImsServiceType::TYPE_VOICE), TELEPHONY_ERR_SUCCESS);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> reslut = {};
    EXPECT_NE(mCoreService->QueryIccDiallingNumbers(0, 1, reslut), TELEPHONY_ERR_SUCCESS);
    const std::shared_ptr<DiallingNumbersInfo> diallingNumber = nullptr;
    EXPECT_NE(mCoreService->AddIccDiallingNumbers(0, 1, diallingNumber), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->DelIccDiallingNumbers(0, 1, diallingNumber), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->UpdateIccDiallingNumbers(0, 1, diallingNumber), TELEPHONY_ERR_SUCCESS);
    std::vector<IccAccountInfo> iccAccountInfoList = {};
    EXPECT_NE(mCoreService->GetActiveSimAccountInfoList(iccAccountInfoList), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->FactoryReset(0), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_CoreService_0600
 * @tc.name    CoreService
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_CoreService_0600, Function | MediumTest | Level3)
{
    AccessToken token;
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::u16string testU16Str = u"";
    OperatorConfig mOperatorConfig;
    EXPECT_NE(mCoreService->GetOperatorConfigs(0, mOperatorConfig), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimTelephoneNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetVoiceMailIdentifier(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetVoiceMailNumber(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->SetVoiceMailInfo(0, testU16Str, testU16Str), TELEPHONY_ERR_SUCCESS);
    ImsRegInfo mImsRegInfo;
    EXPECT_NE(mCoreService->GetImsRegStatus(0, ImsServiceType::TYPE_VOICE, mImsRegInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetMaxSimCount(), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetOpKey(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetOpKeyExt(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetOpName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    int32_t slotId = TELEPHONY_ERROR;
    EXPECT_NE(mCoreService->GetPrimarySlotId(slotId), TELEPHONY_ERR_SUCCESS);
    int32_t radioTech = TELEPHONY_ERROR;
    EXPECT_NE(mCoreService->GetPsRadioTech(0, radioTech), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetCsRadioTech(0, radioTech), TELEPHONY_ERR_SUCCESS);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    EXPECT_NE(mCoreService->GetSimState(0, simState), TELEPHONY_ERR_SUCCESS);
    CardType cardType = CardType::UNKNOWN_CARD;
    EXPECT_NE(mCoreService->GetCardType(0, cardType), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSlotId(1), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimId(0), TELEPHONY_ERR_SUCCESS);
    int32_t dsdsMode = INVALID_VALUE;
    EXPECT_NE(mCoreService->GetDsdsMode(dsdsMode), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_CoreService_0700
 * @tc.name    CoreService
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_CoreService_0700, Function | MediumTest | Level3)
{
    AccessToken token;
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::string testStr = "";
    std::u16string testU16Str = u"";
    std::vector<sptr<SignalInformation>> mSignalInfoList = {};
    EXPECT_NE(mCoreService->GetSignalInfoList(0, mSignalInfoList), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mCoreService->GetOperatorNumeric(0), testU16Str);
    EXPECT_NE(mCoreService->GetOperatorName(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimOperatorNumeric(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetISOCountryCodeForSim(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetSimSpn(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mCoreService->GetLocaleFromDefaultSim(), testU16Str);
    EXPECT_EQ(mCoreService->GetSimGid2(0), testU16Str);
    std::string plmn = "46001";
    int32_t lac = 1;
    bool longNameRequired = true;
    EXPECT_EQ(mCoreService->GetSimEons(0, plmn, lac, longNameRequired), testU16Str);
    EXPECT_NE(mCoreService->GetIsoCountryCodeForNetwork(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(mCoreService->GetSimTeleNumberIdentifier(0), testU16Str);
    sptr<NetworkState> networkState = nullptr;
    EXPECT_NE(mCoreService->GetNetworkState(0, networkState), TELEPHONY_ERR_SUCCESS);
    sptr<INetworkSearchCallback> callback = nullptr;
    EXPECT_NE(mCoreService->GetRadioState(0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetNetworkSelectionMode(0, callback), TELEPHONY_ERR_SUCCESS);
    EXPECT_FALSE(mCoreService->IsNrSupported(0));
    EXPECT_FALSE(mCoreService->IsSimActive(0));
    bool hasValue = false;
    EXPECT_NE(mCoreService->HasSimCard(0, hasValue), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->HasOperatorPrivileges(0, hasValue), TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   Telephony_Sim_GetDefaultVoiceSimId_0100
 * @tc.name     Get default voice sim simId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetDefaultVoiceSimId_0100, Function | MediumTest | Level1)
{
    if (SimTest::HasSimCard(slotId_) || SimTest::HasSimCard(slotId1_)) {
        int32_t simId;
        CoreServiceClient::GetInstance().GetDefaultVoiceSimId(simId);
        EXPECT_GE(simId, TELEPHONY_ERROR);
    } else {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    }
}

/**
 * @tc.number   Telephony_Sim_InitTelephonyExtService_0100
 * @tc.name     Init Telephony Ext Service.
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_InitTelephonyExtService_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    if (TELEPHONY_EXT_WRAPPER.telephonyExtWrapperHandle_ == nullptr) {
        TELEPHONY_LOGI("telephonyExtWrapperHandle_ null");
    } else {
        TELEPHONY_LOGI("telephonyExtWrapperHandle_ not null");
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.checkOpcVersionIsUpdate_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.updateOpcVersion_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.getVoiceMailIccidParameter_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.setVoiceMailIccidParameter_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.initVoiceMailManagerExt_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.deinitVoiceMailManagerExt_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.resetVoiceMailLoadedFlagExt_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.setVoiceMailOnSimExt_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.getVoiceMailFixedExt_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.getVoiceMailNumberExt_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.getVoiceMailTagExt_ != nullptr, true);
        EXPECT_EQ(TELEPHONY_EXT_WRAPPER.resetVoiceMailManagerExt_ != nullptr, true);
    }
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
