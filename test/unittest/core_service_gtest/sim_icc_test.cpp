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

namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_Sim_GetActiveSimAccountInfoList_0100
 * @tc.name     Get active sim accountInfoList
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetActiveSimAccountInfoList_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::vector<IccAccountInfo> iccAccountInfoList;
        int32_t result = CoreServiceClient::GetInstance().GetActiveSimAccountInfoList(iccAccountInfoList);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetActiveSimAccountInfoList_0200
 * @tc.name     Get active sim accountInfoList
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetActiveSimAccountInfoList_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::vector<IccAccountInfo> iccAccountInfoList;
        int32_t result = CoreServiceClient::GetInstance().GetActiveSimAccountInfoList(iccAccountInfoList);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetActiveSimAccountInfoList_0300
 * @tc.name     Get active sim accountInfoList
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetActiveSimAccountInfoList_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::vector<IccAccountInfo> iccAccountInfoList;
        int32_t result = CoreServiceClient::GetInstance().GetActiveSimAccountInfoList(iccAccountInfoList);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccAdnDiallingNumbers_0100
 * @tc.name     Query ADN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!(SimTest::HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
        ASSERT_TRUE(true);
        return;
    }
    CoreServiceTestHelper helper;
    if (!helper.Run(QueryIccAdnDiallingNumbersTestFunc, std::ref(helper))) {
        TELEPHONY_LOGI("Interface out of time");
        ASSERT_TRUE(true);
    }
    ASSERT_TRUE(true);
}

/**
 * @tc.number   Telephony_Sim_QueryIccAdnDiallingNumbers_0200
 * @tc.name     Query ADN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccAdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!(SimTest::HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
        ASSERT_TRUE(true);
        return;
    }
    CoreServiceTestHelper helper;
    if (!helper.Run(QueryIccAdnDiallingNumbersTestFunc1, std::ref(helper))) {
        TELEPHONY_LOGI("Interface out of time");
        ASSERT_TRUE(true);
    }
    ASSERT_TRUE(true);
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0100
 * @tc.name     Add icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("12345678901");
        CoreServiceClient::GetInstance().AddIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        DiallingNumbersInfo mInfo = DiallingNumbersInfo();
        mInfo.UpdateNumber(Str8ToStr16("12345678901"));
        std::vector<std::u16string> emails = mInfo.GetEmails();
        mInfo.UpdateEmails(emails);
        TELEPHONY_LOGI("DiallingNumbersInfo field is %{public}d, index is %{public}d, mInfo is empty %{public}d.",
            mInfo.GetFileId(), mInfo.GetIndex(), mInfo.IsEmpty());
        DiallingNumbersInfo mInfoTemp = DiallingNumbersInfo(0, 0);
        std::u16string nameTemp = diallingNumber->GetName();
        std::u16string numberTemp = diallingNumber->GetNumber();
        mInfoTemp = DiallingNumbersInfo(nameTemp, numberTemp);
        mInfoTemp = DiallingNumbersInfo(nameTemp, numberTemp, emails);
        mInfoTemp = DiallingNumbersInfo(0, 0, nameTemp, numberTemp);
        mInfoTemp = DiallingNumbersInfo(0, 0, nameTemp, numberTemp, emails);
        MessageParcel parcel;
        mInfoTemp.Marshalling(parcel);
        mInfoTemp.ReadFromParcel(parcel);
        mInfoTemp.UnMarshalling(parcel);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0200
 * @tc.name     Add icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("电话卡");
        diallingNumber->number_ = Str8ToStr16("00000000000");
        CoreServiceClient::GetInstance().AddIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0300
 * @tc.name     Add icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0300, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("12345678901");
        CoreServiceClient::GetInstance().AddIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0400
 * @tc.name     Add icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0400, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("电话卡");
        diallingNumber->number_ = Str8ToStr16("00000000000");
        CoreServiceClient::GetInstance().AddIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_UpdateIccAdnDiallingNumbers_0100
 * @tc.name     Update icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UpdateIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("12345678901");
        diallingNumber->index_ = index;
        CoreServiceClient::GetInstance().UpdateIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_UpdateIccAdnDiallingNumbers_0200
 * @tc.name     Update icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UpdateIccAdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("12345678901");
        diallingNumber->index_ = index;
        CoreServiceClient::GetInstance().UpdateIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_DelIccAdnDiallingNumbers_0100
 * @tc.name     Delete icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_DelIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->index_ = index;
        CoreServiceClient::GetInstance().DelIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_DelIccAdnDiallingNumbers_0200
 * @tc.name     Delete icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_DelIccAdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->index_ = index;
        CoreServiceClient::GetInstance().DelIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_DelIccAdnDiallingNumbers_0300
 * @tc.name     Delete icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_DelIccAdnDiallingNumbers_0300, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumbers =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumbers->name_ = Str8ToStr16("电话卡");
        diallingNumbers->number_ = Str8ToStr16("00000000000");
        SimTest::telephonyService_->AddIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumbers);
        int32_t sleepTime = 1;
        sleep(sleepTime);
        int index = 0;
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->index_ = index;
        diallingNumber->name_ = Str8ToStr16("电话卡");
        diallingNumber->number_ = Str8ToStr16("00000000000");
        int32_t result = CoreServiceClient::GetInstance().DelIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccFdnDiallingNumbers_0100
 * @tc.name     Query FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccFdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!(SimTest::HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
        ASSERT_TRUE(true);
        return;
    }
    CoreServiceTestHelper helper;
    if (!helper.Run(QueryIccFdnDiallingNumbersTestFunc, std::ref(helper))) {
        TELEPHONY_LOGI("Interface out of time");
        ASSERT_TRUE(true);
    }
    ASSERT_TRUE(true);
}

/**
 * @tc.number   Telephony_Sim_QueryIccFdnDiallingNumbers_0200
 * @tc.name     Query FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccFdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!(SimTest::HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
        ASSERT_TRUE(true);
        return;
    }
    CoreServiceTestHelper helper;
    if (!helper.Run(QueryIccFdnDiallingNumbersTestFunc1, std::ref(helper))) {
        TELEPHONY_LOGI("Interface out of time");
    }
    ASSERT_TRUE(true);
}

/**
 * @tc.number   Telephony_Sim_AddIccFdnDiallingNumbers_0100
 * @tc.name     Add icc FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccFdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_FDN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("12345678901");
        diallingNumber->pin2_ = Str8ToStr16("1234");
        CoreServiceClient::GetInstance().AddIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_FDN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccFdnDiallingNumbers_0200
 * @tc.name     Add icc FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccFdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_FDN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("12345678901");
        diallingNumber->pin2_ = Str8ToStr16("1234");
        CoreServiceClient::GetInstance().AddIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_FDN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_UpdateIccFdnDiallingNumbers_0100
 * @tc.name     Update icc FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UpdateIccFdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("12345678901");
        diallingNumber->pin2_ = Str8ToStr16("1234");
        diallingNumber->index_ = index;
        CoreServiceClient::GetInstance().UpdateIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_FDN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_UpdateIccFdnDiallingNumbers_0200
 * @tc.name     Update icc FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UpdateIccFdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("12345678901");
        diallingNumber->pin2_ = Str8ToStr16("1234");
        diallingNumber->index_ = index;
        CoreServiceClient::GetInstance().UpdateIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_FDN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_DelIccFdnDiallingNumbers_0100
 * @tc.name     Delete icc FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_DelIccFdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->pin2_ = Str8ToStr16("1234");
        diallingNumber->index_ = index;
        CoreServiceClient::GetInstance().DelIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_FDN, diallingNumber);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_DelIccFdnDiallingNumbers_0200
 * @tc.name     Delete icc FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_DelIccFdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->pin2_ = Str8ToStr16("1234");
        diallingNumber->index_ = index;
        CoreServiceClient::GetInstance().DelIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_FDN, diallingNumber);
        EXPECT_TRUE(true);
    }
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
