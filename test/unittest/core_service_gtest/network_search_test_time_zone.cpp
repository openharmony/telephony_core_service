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

#include "core_service.h"
#include "network_search_manager.h"
#include "network_search_test.h"
#include "sim_manager.h"
#include "telephony_log_wrapper.h"
#include "time_zone_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int32_t SLOT_ID_0 = 0;
constexpr int32_t SLOT_ID_1 = 1;
constexpr int64_t LOCATION_EXPIRATION_TIME_MS = 60 * 60 * 1000;
constexpr int64_t LOCATION_EXPIRATION_TIME_MS_ROAMING = 30 * 60 * 1000;
constexpr int32_t TIMEZONE_OFFSET_0 = 0;
constexpr int32_t TIMEZONE_OFFSET_8 = 8;
constexpr int32_t TIMEZONE_OFFSET_32 = 32;
constexpr int32_t TIMEZONE_OFFSET_NEGATIVE_24 = -24;
constexpr int32_t TIMEZONE_OFFSET_NEGATIVE_1 = -1;

#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_NetworkSearch_UpdateCountryCode_0100
 * @tc.name     UpdateCountryCode
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UpdateCountryCode_0100, Function | MediumTest | Level1)
{
    auto timeZoneUpdater = std::make_shared<TimeZoneUpdater>();
    timeZoneUpdater->Init();
    std::string countryCode = "cn";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    countryCode = "us";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    countryCode = "CN";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    countryCode = "US";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    countryCode = "test";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    countryCode = "";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    countryCode = "cn";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    countryCode = "US";
    EXPECT_EQ(timeZoneUpdater->StringToLower(countryCode), "us");
}

/**
 * @tc.number   Telephony_NetworkSearch_UpdateTimeZoneOffset_0100
 * @tc.name     UpdateTimeZoneOffset
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_UpdateTimeZoneOffset_0100, Function | MediumTest | Level1)
{
    auto timeZoneUpdater = std::make_shared<TimeZoneUpdater>();
    timeZoneUpdater->Init();
    std::string countryCode = "cn";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    int32_t offset = TIMEZONE_OFFSET_0;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    offset = TIMEZONE_OFFSET_32;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    offset = TIMEZONE_OFFSET_8;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    offset = TIMEZONE_OFFSET_NEGATIVE_1;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    offset = TIMEZONE_OFFSET_NEGATIVE_24;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    countryCode = "us";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    offset = TIMEZONE_OFFSET_0;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    offset = TIMEZONE_OFFSET_NEGATIVE_1;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    offset = TIMEZONE_OFFSET_NEGATIVE_24;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    offset = TIMEZONE_OFFSET_32;
    timeZoneUpdater->UpdateTimeZoneOffset(offset, DEFAULT_SIM_SLOT_ID);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    std::string s = "";
    EXPECT_EQ(timeZoneUpdater->StringToLower(s), "");
}

/**
 * @tc.number   Telephony_NetworkSearch_TimeZoneID_0100
 * @tc.name     TimeZoneID
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_TimeZoneID_0100, Function | MediumTest | Level1)
{
    auto timeZoneUpdater = std::make_shared<TimeZoneUpdater>();
    timeZoneUpdater->Init();
    std::string countryCode = "cn";
    timeZoneUpdater->UpdateCountryCode(countryCode, DEFAULT_SIM_SLOT_ID);
    std::string timeZone = "Asia/Shanghai";
    EXPECT_TRUE(timeZoneUpdater->IsTimeZoneMatchCountryCode(timeZone));
    EXPECT_TRUE(timeZoneUpdater->NeedUpdateLocationTimeZone(timeZone));
    timeZone = "Asia/Singapore";
    EXPECT_FALSE(timeZoneUpdater->NeedUpdateLocationTimeZone(timeZone));
    EXPECT_FALSE(timeZoneUpdater->IsTimeZoneMatchCountryCode(timeZone));
    timeZone = "test";
    EXPECT_FALSE(timeZoneUpdater->NeedUpdateLocationTimeZone(timeZone));
    EXPECT_FALSE(timeZoneUpdater->IsTimeZoneMatchCountryCode(timeZone));
    timeZone = "";
    EXPECT_FALSE(timeZoneUpdater->NeedUpdateLocationTimeZone(timeZone));
    EXPECT_FALSE(timeZoneUpdater->IsTimeZoneMatchCountryCode(timeZone));

    countryCode = "cn";
    EXPECT_FALSE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
    countryCode = " ";
    EXPECT_FALSE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
    countryCode = "CN";
    EXPECT_FALSE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
    countryCode = "test";
    EXPECT_FALSE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
    countryCode = "sg";
    EXPECT_FALSE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
    countryCode = "US";
    EXPECT_FALSE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
    countryCode = "us";
    EXPECT_TRUE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
    countryCode = "au";
    EXPECT_TRUE(timeZoneUpdater->IsMultiTimeZoneCountry(countryCode));
}

/**
 * @tc.number   Telephony_NetworkSearch_Location_0100
 * @tc.name     Location
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_Location_0100, Function | MediumTest | Level1)
{
    auto suggester = std::make_shared<TimeZoneLocationSuggester>();
    auto idleState = new (std::nothrow) IdleState(std::weak_ptr<TimeZoneLocationSuggester>(suggester), "IdleState");
    auto nitzState = new (std::nothrow) NitzState(std::weak_ptr<TimeZoneLocationSuggester>(suggester), "NitzState");
    auto locationState =
        new (std::nothrow) LocationState(std::weak_ptr<TimeZoneLocationSuggester>(suggester), "LocationState");
    if (idleState == nullptr || nitzState == nullptr || locationState == nullptr) {
        TELEPHONY_LOGE("state is null");
        return;
    }
    suggester->idleState_ = idleState;
    suggester->nitzState_ = nitzState;
    suggester->locationState_ = locationState;
    suggester->nitzState_->SetParentState(suggester->idleState_);
    suggester->locationState_->SetParentState(suggester->idleState_);
    suggester->SetOriginalState(suggester->idleState_);
    suggester->Start();
    bool isRoaming = TimeZoneManager::GetInstance().IsRoaming();
    if (isRoaming) {
        EXPECT_EQ(suggester->GetLocationExpirationTime(), LOCATION_EXPIRATION_TIME_MS_ROAMING);
    } else {
        EXPECT_EQ(suggester->GetLocationExpirationTime(), LOCATION_EXPIRATION_TIME_MS);
    }
    EXPECT_FALSE(suggester->HasLocation());
    suggester->TransitionTo(suggester->nitzState_);
    suggester->TransitionTo(suggester->nitzState_);
    suggester->TransitionTo(suggester->locationState_);
    suggester->TransitionTo(suggester->idleState_);
    idleState->ShouldUpdateTimeZone();
    nitzState->ShouldUpdateTimeZone();
    locationState->UpdateTimeZone();
#ifdef ABILITY_LOCATION_SUPPORT
    Parcel parcel;
    std::unique_ptr<Location::Location> location = Location::Location::Unmarshalling(parcel);
    suggester->LocationUpdate(location);
    sleep(1);
    EXPECT_TRUE(suggester->HasLocation());
    EXPECT_FALSE(suggester->IsLocationExpired());
#endif
    suggester->ClearLocation();
    EXPECT_FALSE(suggester->HasLocation());
}

/**
 * @tc.number   Telephony_NetworkSearch_FactoryReset_0100
 * @tc.name     Send Cell Location Update
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_FactoryReset_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_0))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().FactoryReset(SLOT_ID_0);
        TELEPHONY_LOGI("TelephonyTestService FactoryReset result: %{public}d", result);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_FactoryReset_0200
 * @tc.name     Send Cell Location Update
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_FactoryReset_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_1))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().FactoryReset(SLOT_ID_1);
        TELEPHONY_LOGI("TelephonyTestService FactoryReset result: %{public}d", result);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_NetworkSearch_FactoryReset_0300
 * @tc.name     Send Cell Location Update without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_FactoryReset_0300, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_0))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    int32_t result = CoreServiceClient::GetInstance().FactoryReset(SLOT_ID_0);
    TELEPHONY_LOGI("TelephonyTestService FactoryReset result: %{public}d", result);
    EXPECT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNrSsbIdInfo_0100
 * @tc.name     Get NR Cell's Ssb Id related info
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNrSsbIdInfo_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_0))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo;
    int32_t result = CoreServiceClient::GetInstance().GetNrSsbIdInfo(SLOT_ID_0, nrCellSsbIdsInfo);
    // Force to set the expected result as failure since incomplete implement in modem.
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    NetworkSearchTest::PrintNrSsbIdInfo(nrCellSsbIdsInfo);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNrSsbIdInfo_0200
 * @tc.name     Get NR Cell's Ssb Id related info
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNrSsbIdInfo_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_1))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo;
    int32_t result = CoreServiceClient::GetInstance().GetNrSsbIdInfo(SLOT_ID_1, nrCellSsbIdsInfo);
    // Force to set the expected result as failure since incomplete implement in modem.
    EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    NetworkSearchTest::PrintNrSsbIdInfo(nrCellSsbIdsInfo);
}

/**
 * @tc.number   Telephony_NetworkSearch_GetNrSsbIdInfo_0300
 * @tc.name     Get NR Cell's Ssb Id related info without permission
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchTest, Telephony_NetworkSearch_GetNrSsbIdInfo_0300, Function | MediumTest | Level3)
{
    if (NetworkSearchTest::telephonyService_ == nullptr || !(NetworkSearchTest::HasSimCard(SLOT_ID_0))) {
        TELEPHONY_LOGE("TelephonyTestService Remote service is null");
        NetworkSearchTest::telephonyService_ = GetProxy();
        return;
    }
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo;
    int32_t result = CoreServiceClient::GetInstance().GetNrSsbIdInfo(SLOT_ID_0, nrCellSsbIdsInfo);
    EXPECT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
    NetworkSearchTest::PrintNrSsbIdInfo(nrCellSsbIdsInfo);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS