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
#include <string_ex.h>
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "core_service_proxy.h"
#include "network_search_test_callback_stub.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int SLOT_ID = 0;
constexpr int WAIT_TIME_SECOND = 10;
constexpr int WAIT_TIME_SECOND_LONG = 60;

class NetworkSearchTest : public testing::Test {
public:
    // execute before first testcase
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    static void TearDownTestCase();

    static sptr<ICoreService> GetProxy();
    static sptr<ICoreService> telephonyService_;
};

sptr<ICoreService> NetworkSearchTest::telephonyService_ = nullptr;
void NetworkSearchTest::SetUpTestCase()
{
    std::cout << "----------NetworkSearch gtest start ------------" << std::endl;
    if (telephonyService_ == nullptr) {
        telephonyService_ = GetProxy();
    }
    std::cout << "NetworkSearch connect coreservice  server success!!!" << std::endl;
}

void NetworkSearchTest::TearDownTestCase()
{
    std::cout << "----------NetworkSearch gtest end ------------" << std::endl;
}

void NetworkSearchTest::SetUp() {}

void NetworkSearchTest::TearDown() {}

sptr<ICoreService> NetworkSearchTest::GetProxy()
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
 * @tc.number   Telephony_NetworkSearch_GetPsRadioTech_0100
 * @tc.name     Get RAT of the PS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetPsRadioTech_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = NetworkSearchTest::telephonyService_->GetPsRadioTech(SLOT_ID);
        std::cout << "TelephonyTestService GetPsRadioTech result:" << result << std::endl;
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCsRadioTech_0100
 * @tc.name     Get RAT of the CS domain on the registered network
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetCsRadioTech_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = NetworkSearchTest::telephonyService_->GetCsRadioTech(SLOT_ID);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkState_0100
 * @tc.name     Get Network State
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkState_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkState> result = NetworkSearchTest::telephonyService_->GetNetworkState(SLOT_ID);
        if (result == nullptr) {
            std::cout << "GetNetworkState result is null" << std::endl;
        } else {
            EXPECT_GT(result->GetRegStatus(), -1);
            EXPECT_STRNE(result->GetLongOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetShortOperatorName().c_str(), "");
            EXPECT_STRNE(result->GetPlmnNumeric().c_str(), "");
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetCsRadioTech_0100
 * @tc.name     Get Operator Numeric of PLMN
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorNumeric_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetOperatorNumeric(SLOT_ID);
        std::string plmn = Str16ToStr8(result);
        EXPECT_STRNE(plmn.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetOperatorName_0100
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetOperatorName_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetOperatorName(SLOT_ID);
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
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
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
 * @tc.number   Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0100
 * @tc.name     Get GetOperator Name
 * @tc.desc     Function test
 */
HWTEST_F(
    NetworkSearchTest, Telephony_NetworkSearch_GetIsoCountryCodeForNetwork_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        std::u16string result = NetworkSearchTest::telephonyService_->GetIsoCountryCodeForNetwork(SLOT_ID);
        std::string countryCode = Str16ToStr8(result);
        std::cout << "TelephonyTestService GetIsoCountryCodeForNetwork countryCode:" << countryCode << std::endl;
        EXPECT_STRNE(countryCode.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0100
 * @tc.name     Set Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
        int32_t selectionMode = 1;
        bool isUpdateDatabase = true;
        networkInfo->SetOperateInformation(
            "CHINA MOBILE", "CMCC", "46000", NETWORK_PLMN_STATE_AVAILABLE, NETWORK_LTE);
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool result = NetworkSearchTest::telephonyService_->SetNetworkSelectionMode(
            SLOT_ID, selectionMode, networkInfo, isUpdateDatabase, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetNetworkSelectionMode syncResult:" << syncResult << std::endl;
            EXPECT_TRUE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetNetworkSelectionMode return fail" << std::endl;
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0100
 * @tc.name     Get Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
        int32_t selectionMode = 1;
        bool isUpdateDatabase = true;
        networkInfo->SetOperateInformation(
            "CHINA MOBILE", "CMCC", "46000", NETWORK_PLMN_STATE_AVAILABLE, NETWORK_LTE);
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool result = NetworkSearchTest::telephonyService_->SetNetworkSelectionMode(
            SLOT_ID, selectionMode, networkInfo, isUpdateDatabase, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetNetworkSelectionMode syncResult:" << syncResult << std::endl;
            EXPECT_TRUE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetNetworkSelectionMode return fail" << std::endl;
        }

        result = NetworkSearchTest::telephonyService_->GetNetworkSelectionMode(SLOT_ID, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND);
            int SearchModel = callback->GetSearchModel();
            std::cout << "TelephonyTestService GetNetworkSelectionMode SearchModel:" << SearchModel << std::endl;
            EXPECT_EQ(SearchModel, 1);
        } else {
            std::cout << "TelephonyTestService GetNetworkSelectionMode return fail" << std::endl;
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SetNetworkSelectionMode_0100
 * @tc.name     Set Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetNetworkSelectionMode_0200, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
        int32_t selectionMode = 0;
        bool isUpdateDatabase = true;
        networkInfo->SetOperateInformation(
            "CHINA MOBILE", "CMCC", "46000", NETWORK_PLMN_STATE_AVAILABLE, NETWORK_LTE);
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool result = NetworkSearchTest::telephonyService_->SetNetworkSelectionMode(
            SLOT_ID, selectionMode, networkInfo, isUpdateDatabase, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetNetworkSelectionMode syncResult:" << syncResult << std::endl;
            EXPECT_TRUE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetNetworkSelectionMode return fail" << std::endl;
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNetworkSelectionMode_0100
 * @tc.name     Get Network Selection Mode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNetworkSelectionMode_0200, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
        int32_t selectionMode = 0;
        bool isUpdateDatabase = true;
        networkInfo->SetOperateInformation(
            "CHINA MOBILE", "CMCC", "46000", NETWORK_PLMN_STATE_AVAILABLE, NETWORK_LTE);
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool result = NetworkSearchTest::telephonyService_->SetNetworkSelectionMode(
            SLOT_ID, selectionMode, networkInfo, isUpdateDatabase, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetNetworkSelectionMode syncResult:" << syncResult << std::endl;
            EXPECT_TRUE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetNetworkSelectionMode return fail" << std::endl;
        }

        result = NetworkSearchTest::telephonyService_->GetNetworkSelectionMode(SLOT_ID, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND);
            int SearchModel = callback->GetSearchModel();
            std::cout << "TelephonyTestService GetNetworkSelectionMode SearchModel:" << SearchModel << std::endl;
            EXPECT_EQ(SearchModel, 0);
        } else {
            std::cout << "TelephonyTestService GetNetworkSelectionMode return fail" << std::endl;
        }
    }
}
/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0100
 * @tc.name     Get Radio State Off
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool isOn = false;
        bool result = NetworkSearchTest::telephonyService_->SetRadioState(isOn, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND_LONG);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetRadioState syncResult:" << syncResult << std::endl;
            EXPECT_TRUE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetRadioState return fail" << std::endl;
        }

        result = NetworkSearchTest::telephonyService_->GetRadioState(callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND_LONG);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetRadioState syncResult:" << syncResult << std::endl;
            EXPECT_FALSE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetRadioState return fail" << std::endl;
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_SetRadioState_0100
 * @tc.name     Set Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_SetRadioState_0200, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool isOn = true;
        bool result = NetworkSearchTest::telephonyService_->SetRadioState(isOn, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND_LONG);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetRadioState syncResult:" << syncResult << std::endl;
            EXPECT_TRUE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetRadioState return fail" << std::endl;
        }
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_GetRadioState_0100
 * @tc.name     Get Radio State On
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetRadioState_0100, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr) {
        std::cout << "TelephonyTestService Remote service is null" << std::endl;
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool isOn = true;
        bool result = NetworkSearchTest::telephonyService_->SetRadioState(isOn, callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND_LONG);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetRadioState syncResult:" << syncResult << std::endl;
            EXPECT_TRUE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetRadioState return fail" << std::endl;
        }

        result = NetworkSearchTest::telephonyService_->GetRadioState(callback);
        if (result) {
            callback->WaitFor(WAIT_TIME_SECOND);
            bool syncResult = callback->GetBoolResult();
            std::cout << "TelephonyTestService SetRadioState syncResult:" << syncResult << std::endl;
            EXPECT_TRUE(syncResult);
        } else {
            std::cout << "TelephonyTestService SetRadioState return fail" << std::endl;
        }
    }
}
} // namespace Telephony
} // namespace OHOS
