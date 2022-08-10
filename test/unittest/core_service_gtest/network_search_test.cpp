/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "network_search_test.h"

#include "ims_reg_info_callback_gtest.h"
#include "iservice_registry.h"
#include "network_search_test_callback_stub.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
#ifndef TEL_TEST_UNSUPPORT
constexpr int32_t SLOT_ID = 0;
constexpr int32_t SLOT_ID1 = 1;
constexpr ImsServiceType DEFAULT_TYPE = TYPE_VOICE;
constexpr int32_t INVALID_SLOT_ID = -1;
constexpr int32_t INVALID_TYPE = -1;
constexpr int32_t WAIT_TIME_SECOND_LONG = 60;
#endif // TEL_TEST_UNSUPPORT

sptr<ICoreService> NetworkSearchTest::telephonyService_ = nullptr;
std::list<ImsRegStateCallback> NetworkSearchTest::imsRegStateCallbackList_;
void NetworkSearchTest::SetUpTestCase()
{
    TELEPHONY_LOGI("----------NetworkSearch gtest start ------------");
    if (telephonyService_ == nullptr) {
        telephonyService_ = GetProxy();
    }
    TELEPHONY_LOGI("NetworkSearch connect coreservice  server success!!!");
}

void NetworkSearchTest::TearDownTestCase()
{
    TELEPHONY_LOGI("----------NetworkSearch gtest end ------------");
}

void NetworkSearchTest::SetUp() {}

void NetworkSearchTest::TearDown() {}

sptr<ICoreService> NetworkSearchTest::GetProxy()
{
    TELEPHONY_LOGI("TelephonyTestService GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGI("TelephonyTestService Get ISystemAbilityManager failed!!!");
        return nullptr;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote) {
        sptr<ICoreService> telephonyService = iface_cast<ICoreService>(remote);
        return telephonyService;
    } else {
        TELEPHONY_LOGI("TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail ...");
        return nullptr;
    }
}

#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_NetworkSearch_GetPsRadioTech_0100
 * @tc.name     Get RAT of the PS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetPsRadioTech_0100, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = NetworkSearchTest::telephonyService_->GetPsRadioTech(SLOT_ID);
        TELEPHONY_LOGI("TelephonyTestService GetPsRadioTech result: %{public}d", result);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetPsRadioTech_0200
 * @tc.name     Get RAT of the PS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetPsRadioTech_0200, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = NetworkSearchTest::telephonyService_->GetPsRadioTech(SLOT_ID1);
        TELEPHONY_LOGI("TelephonyTestService GetPsRadioTech result: %{public}d", result);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCsRadioTech_0100
 * @tc.name     Get RAT of the CS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCsRadioTech_0100, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = NetworkSearchTest::telephonyService_->GetCsRadioTech(SLOT_ID);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCsRadioTech_0200
 * @tc.name     Get RAT of the CS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCsRadioTech_0200, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = NetworkSearchTest::telephonyService_->GetCsRadioTech(SLOT_ID1);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkState_0100
 * @tc.name     Get Network State
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkState_0100, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkState> result = NetworkSearchTest::telephonyService_->GetNetworkState(SLOT_ID);
        if (result == nullptr) {
            TELEPHONY_LOGI("GetNetworkState result is null");
        } else {
            EXPECT_GT(static_cast<int32_t>(result->GetRegStatus()), -1);
            EXPECT_STRNE(result->GetLongOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetShortOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetPlmnNumeric().c_str(), "");
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkState_0200
 * @tc.name     Get Network State
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkState_0200, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkState> result = NetworkSearchTest::telephonyService_->GetNetworkState(SLOT_ID1);
        if (result == nullptr) {
            TELEPHONY_LOGI("GetNetworkState result is null");
        } else {
            EXPECT_GT(static_cast<int32_t>(result->GetRegStatus()), -1);
            EXPECT_STRNE(result->GetLongOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetShortOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetPlmnNumeric().c_str(), "");
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorNumeric_0100
 * @tc.name     Get Operator Numeric of PLMN
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorNumeric_0100, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetOperatorNumeric(SLOT_ID);
        std::string plmn = Str16ToStr8(result);
        EXPECT_STRNE(plmn.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorNumeric_0200
 * @tc.name     Get Operator Numeric of PLMN
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorNumeric_0200, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetOperatorNumeric(SLOT_ID1);
        std::string plmn = Str16ToStr8(result);
        EXPECT_STRNE(plmn.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorName_0100
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorName_0100, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetOperatorName(SLOT_ID);
        std::string operatorName = Str16ToStr8(result);
        EXPECT_STRNE(operatorName.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorName_0200
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorName_0200, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetOperatorName(SLOT_ID1);
        std::string operatorName = Str16ToStr8(result);
        EXPECT_STRNE(operatorName.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetSignalInfoList_0100
 * @tc.name     Get Signal Info List
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetSignalInfoList_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        auto result = NetworkSearchTest::telephonyService_->GetSignalInfoList(SLOT_ID);
        SignalInformation::NetworkType type;
        for (const auto &v : result) {
            type = v->GetNetworkType();
            if (type == SignalInformation::NetworkType::GSM) {
                GsmSignalInformation *gsm = reinterpret_cast<GsmSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(gsm->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::CDMA) {
                CdmaSignalInformation *cdma = reinterpret_cast<CdmaSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(cdma->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::LTE) {
                LteSignalInformation *lte = reinterpret_cast<LteSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(lte->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::WCDMA) {
                WcdmaSignalInformation *wcdma = reinterpret_cast<WcdmaSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(wcdma->ToString().c_str(), "");
            }
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetSignalInfoList_0200
 * @tc.name     Get Signal Info List
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetSignalInfoList_0200, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        auto result = NetworkSearchTest::telephonyService_->GetSignalInfoList(SLOT_ID1);
        SignalInformation::NetworkType type;
        for (const auto &v : result) {
            type = v->GetNetworkType();
            if (type == SignalInformation::NetworkType::GSM) {
                GsmSignalInformation *gsm = reinterpret_cast<GsmSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(gsm->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::CDMA) {
                CdmaSignalInformation *cdma = reinterpret_cast<CdmaSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(cdma->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::LTE) {
                LteSignalInformation *lte = reinterpret_cast<LteSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(lte->ToString().c_str(), "");
            } else if (type == SignalInformation::NetworkType::WCDMA) {
                WcdmaSignalInformation *wcdma = reinterpret_cast<WcdmaSignalInformation *>(v.GetRefPtr());
                EXPECT_STRNE(wcdma->ToString().c_str(), "");
            }
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0100
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0100, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetIsoCountryCodeForNetwork(SLOT_ID);
        std::string countryCode = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetIsoCountryCodeForNetwork countryCode: %{public}s", countryCode.c_str());
        EXPECT_STRNE(countryCode.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0200
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0200, Function | MediumTest | Level1)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetIsoCountryCodeForNetwork(SLOT_ID1);
        std::string countryCode = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetIsoCountryCodeForNetwork countryCode: %{public}s", countryCode.c_str());
        EXPECT_STRNE(countryCode.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0100
 * @tc.name     Set Manual Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0100, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation(
        "CHINA MOBILE", "CMCC", "46000", static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0200
 * @tc.name     Set Auto Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0200, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0300
 * @tc.name     Set Manual Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0300, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0400
 * @tc.name     Set Auto Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0400, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0100
 * @tc.name     Get Manual Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0100, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = telephonyService_->GetNetworkSelectionMode(SLOT_ID, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForGetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    int32_t networkSelectionMode = callback->GetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSelectionMode syncResult: %{public}d", networkSelectionMode);
    EXPECT_EQ(networkSelectionMode,  static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL));
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0200
 * @tc.name     Get Auto Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0200, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = telephonyService_->GetNetworkSelectionMode(SLOT_ID, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForGetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    int32_t networkSelectionMode = callback->GetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSelectionMode syncResult: %{public}d", networkSelectionMode);
    EXPECT_EQ(networkSelectionMode,  static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO));
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0300
 * @tc.name     Get Manual Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0300, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL), networkInfo, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = telephonyService_->GetNetworkSelectionMode(SLOT_ID1, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForGetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    int32_t networkSelectionMode = callback->GetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSelectionMode syncResult: %{public}d", networkSelectionMode);
    EXPECT_EQ(networkSelectionMode, static_cast<int32_t>(SelectionMode::MODE_TYPE_MANUAL));
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0400
 * @tc.name     Get Auto Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0400, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
    networkInfo->SetOperateInformation("CHINA MOBILE", "CMCC", "46000",
        static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE),
        static_cast<int32_t>(NetworkRat::NETWORK_LTE));
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetNetworkSelectionMode(
        SLOT_ID1, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO), networkInfo, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForSetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetNetworkSelectionMode syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = telephonyService_->GetNetworkSelectionMode(SLOT_ID1, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetNetworkSelectionMode fail");
        return;
    }
    callback->WaitForGetNetworkModeCallback(WAIT_TIME_SECOND_LONG);
    int32_t networkSelectionMode = callback->GetNetworkModeCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSelectionMode syncResult: %{public}d", networkSelectionMode);
    EXPECT_EQ(networkSelectionMode, static_cast<int32_t>(SelectionMode::MODE_TYPE_AUTO));
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0100
 * @tc.name     Set Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0100, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID, false, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetRadioState fail");
        return;
    }
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetRadioState syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0200
 * @tc.name     Set Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0200, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetRadioState fail");
        return;
    }
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetRadioState syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0300
 * @tc.name     Set Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0300, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID1, false, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetRadioState fail");
        return;
    }
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetRadioState syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0400
 * @tc.name     Set Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0400, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID1, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetRadioState fail");
        return;
    }
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetRadioState syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0100
 * @tc.name     Get Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0100, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID, false, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetRadioState fail");
        return;
    }
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetRadioState syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = telephonyService_->GetRadioState(SLOT_ID, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetRadioState fail");
        return;
    }
    callback->WaitForGetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool isRadioOn = callback->GetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetRadioState off isRadioOn: %{public}d", isRadioOn);
    ASSERT_FALSE(isRadioOn);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0200
 * @tc.name     Get Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0200, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetRadioState fail");
        return;
    }
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetRadioState syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = telephonyService_->GetRadioState(SLOT_ID, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetRadioState fail");
        return;
    }
    callback->WaitForGetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool isRadioOn = callback->GetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetRadioState off isRadioOn: %{public}d", isRadioOn);
    ASSERT_TRUE(isRadioOn);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0300
 * @tc.name     Get Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0300, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID1, false, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetRadioState fail");
        return;
    }
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetRadioState syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = telephonyService_->GetRadioState(SLOT_ID1, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetRadioState fail");
        return;
    }
    callback->WaitForGetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool isRadioOn = callback->GetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetRadioState off isRadioOn: %{public}d", isRadioOn);
    ASSERT_FALSE(isRadioOn);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0400
 * @tc.name     Get Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0400, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->SetRadioState(SLOT_ID1, true, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService SetRadioState fail");
        return;
    }
    callback->WaitForSetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->SetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService SetRadioState syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);

    result = telephonyService_->GetRadioState(SLOT_ID1, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetRadioState fail");
        return;
    }
    callback->WaitForGetRadioStateCallback(WAIT_TIME_SECOND_LONG);
    bool isRadioOn = callback->GetRadioStateCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetRadioState off isRadioOn: %{public}d", isRadioOn);
    ASSERT_TRUE(isRadioOn);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImei_0100
 * @tc.name     Get Imei
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImei_0100, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetImei(SLOT_ID);
        std::string imei = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetImei Imei: %{public}s", imei.c_str());
        EXPECT_STRNE(imei.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImei_0200
 * @tc.name     Get Imei
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImei_0200, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetImei(SLOT_ID1);
        std::string imei = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetImei Imei: %{public}s", imei.c_str());
        EXPECT_STRNE(imei.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetMeid_0100
 * @tc.name     Get Meid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetMeid_0100, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetMeid(SLOT_ID);
        std::string meid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetMeid Meid: %{public}s", meid.c_str());
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetMeid_0200
 * @tc.name     Get Meid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetMeid_0200, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetMeid(SLOT_ID1);
        std::string meid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetMeid Meid: %{public}s", meid.c_str());
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetUniqueDeviceId_0100
 * @tc.name     Get unique device id
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetUniqueDeviceId_0100, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetUniqueDeviceId(SLOT_ID);
        std::string deviceid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetUniqueDeviceId DeviceId: %{public}s", deviceid.c_str());
        EXPECT_STRNE(deviceid.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetUniqueDeviceId_0200
 * @tc.name     Get unique device id
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetUniqueDeviceId_0200, Function | MediumTest | Level2)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetUniqueDeviceId(SLOT_ID1);
        std::string deviceid = Str16ToStr8(result);
        TELEPHONY_LOGI("TelephonyTestService GetUniqueDeviceId DeviceId: %{public}s", deviceid.c_str());
        EXPECT_STRNE(deviceid.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SendUpdateCellLocationRequest_0100
 * @tc.name     Send Cell Location Update
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SendUpdateCellLocationRequest_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        bool result = NetworkSearchTest::telephonyService_->SendUpdateCellLocationRequest(SLOT_ID);
        TELEPHONY_LOGI("TelephonyTestService SendUpdateCellLocationRequest result: %{public}d", result);
        ASSERT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SendUpdateCellLocationRequest_0200
 * @tc.name     Send Cell Location Update
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SendUpdateCellLocationRequest_0200, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr ||
        !(NetworkSearchTest::telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        bool result = NetworkSearchTest::telephonyService_->SendUpdateCellLocationRequest(SLOT_ID1);
        TELEPHONY_LOGI("TelephonyTestService SendUpdateCellLocationRequest result: %{public}d", result);
        ASSERT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSearchInformation_0100
 * @tc.name     Get Network Search Information
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSearchInformation_0100, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->GetNetworkSearchInformation(SLOT_ID, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetNetworkSearchInformation fail");
        return;
    }
    callback->WaitForGetNetworkSearchInformationCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->GetNetworkSearchInformationCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSearchInformation syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSearchInformation_0200
 * @tc.name     Get Network Search Information
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSearchInformation_0200, Function | MediumTest | Level3)
{
    if (telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        telephonyService_ = GetProxy();
        return;
    }
    sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = telephonyService_->GetNetworkSearchInformation(SLOT_ID1, callback);
    if (!result) {
        TELEPHONY_LOGE("TelephonyTestService GetNetworkSearchInformation fail");
        return;
    }
    callback->WaitForGetNetworkSearchInformationCallback(WAIT_TIME_SECOND_LONG);
    bool syncResult = callback->GetNetworkSearchInformationCallbackResult();
    TELEPHONY_LOGI("TelephonyTestService GetNetworkSearchInformation syncResult: %{public}d", syncResult);
    ASSERT_TRUE(syncResult);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0100
 * @tc.name     Get ims register status
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0100, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    } else {
        ImsRegInfo info;
        ret = telephonyService_->GetImsRegStatus(SLOT_ID, ImsServiceType::TYPE_VOICE, info);
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0200
 * @tc.name     Get ims register status, but slot id is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0200, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_ERROR;
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    } else {
        ImsRegInfo info;
        ret = telephonyService_->GetImsRegStatus(INVALID_SLOT_ID, ImsServiceType::TYPE_VOICE, info);
        EXPECT_EQ(TELEPHONY_ERR_SLOTID_INVALID, ret);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0300
 * @tc.name     Get ims register status, but ImsServiceType is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0300, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    } else {
        ImsRegInfo info;
        ret = telephonyService_->GetImsRegStatus(SLOT_ID, static_cast<ImsServiceType>(INVALID_TYPE), info);
        EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0400
 * @tc.name     Get ims register status
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0400, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    } else {
        ImsRegInfo info;
        ret = telephonyService_->GetImsRegStatus(SLOT_ID1, ImsServiceType::TYPE_VOICE, info);
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetImsRegStatus_0500
 * @tc.name     Get ims register status, but ImsServiceType is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetImsRegStatus_0500, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
    } else {
        ImsRegInfo info;
        ret = telephonyService_->GetImsRegStatus(SLOT_ID1, static_cast<ImsServiceType>(INVALID_TYPE), info);
        EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0100
 * @tc.name     Register ims registation info callback
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0100, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ImsRegStateCallback imsRegStateCallback;
    imsRegStateCallback.slotId = SLOT_ID;
    imsRegStateCallback.imsSrvType = DEFAULT_TYPE;
    imsRegStateCallback.imsCallback = new ImsRegInfoCallbackGtest();
    ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        imsRegStateCallback.slotId, imsRegStateCallback.imsSrvType, imsRegStateCallback.imsCallback);
    if (ret == TELEPHONY_SUCCESS) {
        NetworkSearchTest::imsRegStateCallbackList_.push_back(imsRegStateCallback);
    } else {
        if (imsRegStateCallback.imsCallback != nullptr) {
            delete imsRegStateCallback.imsCallback;
            imsRegStateCallback.imsCallback = nullptr;
        }
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0200
 * @tc.name     Register ims registation info callback, but slot id is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0200, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_ERROR;
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    sptr<ImsRegInfoCallback> imsRegInfoCallback = new ImsRegInfoCallbackGtest();
    ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        INVALID_SLOT_ID, DEFAULT_TYPE, imsRegInfoCallback);
    delete imsRegInfoCallback;
    imsRegInfoCallback = nullptr;
    EXPECT_EQ(TELEPHONY_ERR_SLOTID_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0300
 * @tc.name     Register ims registation info callback, but ims service type is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0300, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    sptr<ImsRegInfoCallback> imsRegInfoCallback = new ImsRegInfoCallbackGtest();
    ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        SLOT_ID, static_cast<ImsServiceType>(INVALID_TYPE), imsRegInfoCallback);
    delete imsRegInfoCallback;
    imsRegInfoCallback = nullptr;
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0400
 * @tc.name     Register ims registation info callback, but callback is nullptr
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0400, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(SLOT_ID, DEFAULT_TYPE, nullptr);
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_NULL, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0500
 * @tc.name     Register ims registation info callback
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0500, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ImsRegStateCallback imsRegStateCallback;
    imsRegStateCallback.slotId = SLOT_ID1;
    imsRegStateCallback.imsSrvType = DEFAULT_TYPE;
    imsRegStateCallback.imsCallback = new ImsRegInfoCallbackGtest();
    ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        imsRegStateCallback.slotId, imsRegStateCallback.imsSrvType, imsRegStateCallback.imsCallback);
    if (ret == TELEPHONY_SUCCESS) {
        NetworkSearchTest::imsRegStateCallbackList_.push_back(imsRegStateCallback);
    } else {
        if (imsRegStateCallback.imsCallback != nullptr) {
            delete imsRegStateCallback.imsCallback;
            imsRegStateCallback.imsCallback = nullptr;
        }
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0600
 * @tc.name     Register ims registation info callback, but ims service type is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0600, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    sptr<ImsRegInfoCallback> imsRegInfoCallback = new ImsRegInfoCallbackGtest();
    ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(
        SLOT_ID1, static_cast<ImsServiceType>(INVALID_TYPE), imsRegInfoCallback);
    delete imsRegInfoCallback;
    imsRegInfoCallback = nullptr;
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_RegImsRegInfoCallback_0700
 * @tc.name     Register ims registation info callback, but callback is nullptr
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_RegImsRegInfoCallback_0700, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->RegisterImsRegInfoCallback(SLOT_ID1, DEFAULT_TYPE, nullptr);
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_NULL, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0100
 * @tc.name     Unregister ims registation info callback
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0100, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID, DEFAULT_TYPE);
    if (ret != TELEPHONY_SUCCESS) {
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    auto itor = NetworkSearchTest::imsRegStateCallbackList_.begin();
    for (; itor != NetworkSearchTest::imsRegStateCallbackList_.end(); ++itor) {
        if (itor->slotId == SLOT_ID && itor->imsSrvType == DEFAULT_TYPE) {
            if (itor->imsCallback != nullptr) {
                delete itor->imsCallback;
                itor->imsCallback = nullptr;
            }
            NetworkSearchTest::imsRegStateCallbackList_.erase(itor);
            break;
        }
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0200
 * @tc.name     Unregister ims registation info callback, but the callback it not registed
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0200, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID, TYPE_VIDEO);
    EXPECT_EQ(TELEPHONY_ERR_UNREGISTER_CALLBACK_FAIL, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0300
 * @tc.name     Unregister ims registation info callback, but slot id is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0300, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_ERROR;
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(INVALID_SLOT_ID, DEFAULT_TYPE);
    EXPECT_EQ(TELEPHONY_ERR_SLOTID_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0400
 * @tc.name     Unregister ims registation info callback, but ims service type is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0400, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(
        SLOT_ID, static_cast<ImsServiceType>(INVALID_TYPE));
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0500
 * @tc.name     Unregister ims registation info callback
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0500, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID1, DEFAULT_TYPE);
    if (ret != TELEPHONY_SUCCESS) {
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    auto itor = NetworkSearchTest::imsRegStateCallbackList_.begin();
    for (; itor != NetworkSearchTest::imsRegStateCallbackList_.end(); ++itor) {
        if (itor->slotId == SLOT_ID1 && itor->imsSrvType == DEFAULT_TYPE) {
            if (itor->imsCallback != nullptr) {
                delete itor->imsCallback;
                itor->imsCallback = nullptr;
            }
            NetworkSearchTest::imsRegStateCallbackList_.erase(itor);
            break;
        }
    }
    EXPECT_EQ(TELEPHONY_SUCCESS, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0600
 * @tc.name     Unregister ims registation info callback, but the callback it not registed
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0600, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(SLOT_ID1, TYPE_VIDEO);
    EXPECT_EQ(TELEPHONY_ERR_UNREGISTER_CALLBACK_FAIL, ret);
}

/**
 * @tc.number   Telephony_NetworkSearch_UnRegImsRegInfoCallback_0700
 * @tc.name     Unregister ims registation info callback, but ims service type is invalid
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UnRegImsRegInfoCallback_0700, Function | MediumTest | Level2)
{
    int ret = TELEPHONY_SUCCESS;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(telephonyService_->HasSimCard(SLOT_ID1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        EXPECT_EQ(TELEPHONY_SUCCESS, ret);
        return;
    }
    ret = NetworkSearchTest::telephonyService_->UnregisterImsRegInfoCallback(
        SLOT_ID1, static_cast<ImsServiceType>(INVALID_TYPE));
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, ret);
}

#else // TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_NetworkSearch_MockTest_0100
 * @tc.name     A test mock for unsupported platform
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_MockTest_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
    }
    EXPECT_TRUE(true);
}

#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
