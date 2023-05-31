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
 * @tc.number   Telephony_Sim_GetSimSpn_0100
 * @tc.name     Get sim service provider name
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimSpn_0100, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::string result = "testresult";
        std::u16string spn;
        CoreServiceClient::GetInstance().GetSimSpn(SimTest::slotId_, spn);
        result = Str16ToStr8(spn);
        EXPECT_STRNE(result.c_str(), "testresult");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimSpn_0200
 * @tc.name     Get sim service provider name
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimSpn_0200, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::string result = "testresult";
        std::u16string spn;
        CoreServiceClient::GetInstance().GetSimSpn(SimTest::slotId1_, spn);
        result = Str16ToStr8(spn);
        EXPECT_STRNE(result.c_str(), "testresult");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimIccId_0100
 * @tc.name     Get sim iccid
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimIccId_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string iccId;
        CoreServiceClient::GetInstance().GetSimIccId(SimTest::slotId_, iccId);
        std::string result = Str16ToStr8(iccId);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimIccId_0200
 * @tc.name     Get sim iccid
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimIccId_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string iccId;
        CoreServiceClient::GetInstance().GetSimIccId(SimTest::slotId1_, iccId);
        std::string result = Str16ToStr8(iccId);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimIccId_0300
 * @tc.name     Get sim iccid
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimIccId_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string iccId;
        CoreServiceClient::GetInstance().GetSimIccId(SimTest::slotId_, iccId);
        std::string result = Str16ToStr8(iccId);
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimOperatorNumeric_0100
 * @tc.name     Get sim operator numeric
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimOperatorNumeric_0100, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string operatorNumeric;
        CoreServiceClient::GetInstance().GetSimOperatorNumeric(SimTest::slotId_, operatorNumeric);
        std::string result = Str16ToStr8(operatorNumeric);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimOperatorNumeric_0200
 * @tc.name     Get sim operator numeric
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimOperatorNumeric_0200, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string operatorNumeric;
        CoreServiceClient::GetInstance().GetSimOperatorNumeric(SimTest::slotId1_, operatorNumeric);
        std::string result = Str16ToStr8(operatorNumeric);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetIMSI_0100
 * @tc.name     Get sim imsi
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetIMSI_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string imsi;
        CoreServiceClient::GetInstance().GetIMSI(SimTest::slotId_, imsi);
        std::string result = Str16ToStr8(imsi);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetIMSI_0200
 * @tc.name     Get sim imsi
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetIMSI_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string imsi;
        CoreServiceClient::GetInstance().GetIMSI(SimTest::slotId1_, imsi);
        std::string result = Str16ToStr8(imsi);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetIMSI_0300
 * @tc.name     Get sim imsi
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetIMSI_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string imsi;
        CoreServiceClient::GetInstance().GetIMSI(SimTest::slotId_, imsi);
        std::string result = Str16ToStr8(imsi);
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimGid1_0100
 * @tc.name     Get sim gid1
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimGid1_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string gid1;
        CoreServiceClient::GetInstance().GetSimGid1(SimTest::slotId_, gid1);
        std::string result = Str16ToStr8(gid1);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimGid1_0200
 * @tc.name     Get sim gid1
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimGid1_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string gid1;
        CoreServiceClient::GetInstance().GetSimGid1(SimTest::slotId1_, gid1);
        std::string result = Str16ToStr8(gid1);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimGid1_0300
 * @tc.name     Get sim gid1
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimGid1_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string gid1;
        CoreServiceClient::GetInstance().GetSimGid1(SimTest::slotId_, gid1);
        std::string result = Str16ToStr8(gid1);
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimGid2_0100
 * @tc.name     Get sim gid2
 * @tc.desc     Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimGid2_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::string result = Str16ToStr8(CoreServiceClient::GetInstance().GetSimGid2(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimGid2_0200
 * @tc.name     Get sim gid2
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimGid2_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::string result = Str16ToStr8(CoreServiceClient::GetInstance().GetSimGid2(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimGid2_0300
 * @tc.name     Get sim gid2
 * @tc.desc     Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimGid2_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::string result = Str16ToStr8(CoreServiceClient::GetInstance().GetSimGid2(SimTest::slotId_));
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0100
 * @tc.name     Get sim telephony number
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTelephoneNumber_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        // Interface may return empty string, as sim file has not information(TelephoneNumber)
        std::u16string telephoneNumber;
        CoreServiceClient::GetInstance().GetSimTelephoneNumber(SimTest::slotId_, telephoneNumber);
        std::string result = Str16ToStr8(telephoneNumber);
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0200
 * @tc.name     Get sim telephony number
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTelephoneNumber_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        // Interface may return empty string, as sim file has not information(TelephoneNumber)
        std::u16string telephoneNumber;
        CoreServiceClient::GetInstance().GetSimTelephoneNumber(SimTest::slotId1_, telephoneNumber);
        std::string result = Str16ToStr8(telephoneNumber);
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0300
 * @tc.name     Get sim telephony number
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTelephoneNumber_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        // has no permission
        std::u16string telephoneNumber;
        CoreServiceClient::GetInstance().GetSimTelephoneNumber(SimTest::slotId_, telephoneNumber);
        std::string result = Str16ToStr8(telephoneNumber);
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0100
 * @tc.name     Get sim telephony number identifier
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTeleNumberIdentifier_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (SimTest::telephonyService_ == nullptr || !SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(SimTeleNumberIdentifier)
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetSimTeleNumberIdentifier(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0200
 * @tc.name     Get sim telephony number identifier
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTeleNumberIdentifier_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (SimTest::telephonyService_ == nullptr || !SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(SimTeleNumberIdentifier)
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetSimTeleNumberIdentifier(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0300
 * @tc.name     Get sim telephony number identifier
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTeleNumberIdentifier_0300, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // has no permission
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimTeleNumberIdentifier(SimTest::slotId_));
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailIdentifier_0100
 * @tc.name     Get voicemail identifier
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailIdentifier_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailIdentifier)
        std::u16string voiceMailIdentifier;
        CoreServiceClient::GetInstance().GetVoiceMailIdentifier(SimTest::slotId_, voiceMailIdentifier);
        std::string result = Str16ToStr8(voiceMailIdentifier);
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailIdentifier_0200
 * @tc.name     Get voicemail identifier
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailIdentifier_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailIdentifier)
        std::u16string voiceMailIdentifier;
        CoreServiceClient::GetInstance().GetVoiceMailIdentifier(SimTest::slotId1_, voiceMailIdentifier);
        std::string result = Str16ToStr8(voiceMailIdentifier);
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailIdentifier_0300
 * @tc.name     Get voicemail identifier
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailIdentifier_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string voiceMailIdentifier;
        CoreServiceClient::GetInstance().GetVoiceMailIdentifier(SimTest::slotId_, voiceMailIdentifier);
        std::string result = Str16ToStr8(voiceMailIdentifier);
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailNumber_0100
 * @tc.name     Get sim voice mail number
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailNumber_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailNumber)
        std::u16string voiceMailNumber;
        CoreServiceClient::GetInstance().GetVoiceMailNumber(SimTest::slotId_, voiceMailNumber);
        std::string result = Str16ToStr8(voiceMailNumber);
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailNumber_0200
 * @tc.name     Get sim voice mail number
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailNumber_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailNumber)
        std::u16string voiceMailNumber;
        CoreServiceClient::GetInstance().GetVoiceMailNumber(SimTest::slotId1_, voiceMailNumber);
        std::string result = Str16ToStr8(voiceMailNumber);
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailNumber_0300
 * @tc.name     Get sim voice mail number
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailNumber_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string voiceMailNumber;
        CoreServiceClient::GetInstance().GetVoiceMailNumber(SimTest::slotId_, voiceMailNumber);
        std::string result = Str16ToStr8(voiceMailNumber);
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailCount_0100
 * @tc.name     Get sim voice mail count
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailCount_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t voiceMailCount;
        int32_t result = CoreServiceClient::GetInstance().GetVoiceMailCount(SimTest::slotId_, voiceMailCount);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailCount_0200
 * @tc.name     Get sim voice mail count
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailCount_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t voiceMailCount;
        int32_t result = CoreServiceClient::GetInstance().GetVoiceMailCount(SimTest::slotId1_, voiceMailCount);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailCount_0300
 * @tc.name     Get sim voice mail count
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailCount_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t voiceMailCount;
        int32_t result = CoreServiceClient::GetInstance().GetVoiceMailCount(SimTest::slotId_, voiceMailCount);
        EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_SetVoiceMailCount_0100
 * @tc.name     Set sim voice mail count
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetVoiceMailCount_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t voiceMailCount = 0;
        int32_t result = CoreServiceClient::GetInstance().SetVoiceMailCount(SimTest::slotId_, voiceMailCount);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_SetVoiceMailCount_0200
 * @tc.name     Get sim voice mail count
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetVoiceMailCount_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t voiceMailCount = 0;
        int32_t result = CoreServiceClient::GetInstance().SetVoiceMailCount(SimTest::slotId1_, voiceMailCount);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_SetVoiceCallForwarding_0200
 * @tc.name     Set sim voicecall forwarding
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetVoiceCallForwarding_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::string number = "01234567890123456789";
        int32_t result = CoreServiceClient::GetInstance().SetVoiceCallForwarding(SimTest::slotId_, true, number);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_RefreshSimState_0100
 * @tc.name     Refresh sim state
 * @tc.desc     Function test
HWTEST_F(SimTest, Telephony_Sim_RefreshSimState_0100, Function | MediumTest | Level0)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result =CoreServiceClient::GetInstance().RefreshSimState(SimTest::slotId_);
        EXPECT_GT(result, -1);
    }
}
 */

/**
 * @tc.number   Telephony_Sim_RefreshSimState_0200
 * @tc.name     Refresh sim state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_RefreshSimState_0200, Function | MediumTest | Level0)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = CoreServiceClient::GetInstance().RefreshSimState(SimTest::slotId1_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_GetSimAccountInfo_0100
 * @tc.name     Get sim accountInfo
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimAccountInfo_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        IccAccountInfo info;
        int32_t result = CoreServiceClient::GetInstance().GetSimAccountInfo(SimTest::slotId_, info);
        IccAccountInfo mInfo;
        mInfo.Init(SimTest::simId, SimTest::slotId_);
        mInfo.SetIsEsim(false);
        mInfo.SetIsActive(true);
        mInfo.SetIccId(u"");
        mInfo.SetShowName(u"");
        mInfo.SetShowNumber(u"");
        bool ret = mInfo == info;
        TELEPHONY_LOGI("mInfo == info is %{public}d", ret);
        MessageParcel parcel;
        mInfo.Marshalling(parcel);
        mInfo.ReadFromParcel(parcel);
        mInfo.UnMarshalling(parcel);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_GetSimAccountInfo_0200
 * @tc.name     Get sim accountInfo
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimAccountInfo_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        IccAccountInfo info;
        int32_t result = CoreServiceClient::GetInstance().GetSimAccountInfo(SimTest::slotId1_, info);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_GetSimAccountInfo_0300
 * @tc.name     Get sim accountInfo
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimAccountInfo_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        IccAccountInfo info;
        int32_t result = CoreServiceClient::GetInstance().GetSimAccountInfo(SimTest::slotId_, info);
        EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_SetLockState_0100
 * @tc.name     Set sim PIN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetLockState_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetLockStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_SetLockState_0200
 * @tc.name     Set sim PIN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetLockState_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetLockStateTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_SetLockState_0300
 * @tc.name     Set sim PIN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetLockState_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetLockStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_SetFDNState_0100
 * @tc.name     Set sim FDN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetFDNState_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetFDNStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_SetFDNState_0200
 * @tc.name     Set sim FDN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetFDNState_0200, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetFDNStateTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_SetFDNState_0300
 * @tc.name     Set sim FDN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetFDNState_0300, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetFDNStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_GetLockState_0100
 * @tc.name     Get sim PIN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetLockState_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(GetLockStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_GT(result, -1);
        }
    }
}

/**
 * @tc.number   Telephony_GetLockState_0200
 * @tc.name     Get sim PIN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetLockState_0200, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(GetLockStateTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_GT(result, -1);
        }
    }
}

/**
 * @tc.number   Telephony_GetLockState_0300
 * @tc.name     Get sim PIN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetLockState_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(GetLockStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_NE(result, 0);
        }
    }
}

/**
 * @tc.number   Telephony_GetFDNState_0100
 * @tc.name     Get sim FDN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetFDNState_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(GetFDNStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_GT(result, -1);
        }
    }
}

/**
 * @tc.number   Telephony_GetFDNState_0200
 * @tc.name     Get sim FDN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetFDNState_0200, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(GetFDNStateTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_GT(result, -1);
        }
    }
}

/**
 * @tc.number   Telephony_GetFDNState_0300
 * @tc.name     Get sim FDN lock state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetFDNState_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(GetFDNStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_NE(result, 0);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockPin_0100
 * @tc.name     Unlock sim PIN lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPin_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPinTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPin_0200
 * @tc.name     Unlock sim PIN lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPin_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPinTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPin_0300
 * @tc.name     Unlock sim PIN lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPin_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPinTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockPuk_0100
 * @tc.name     Unlock sim PUK lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPuk_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPukTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPuk_0200
 * @tc.name     Unlock sim PUK lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPuk_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPukTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPuk_0300
 * @tc.name     Unlock sim PUK lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPuk_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPukTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_AlterPin_0100
 * @tc.name     Change sim PIN password
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AlterPin_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPinTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_AlterPin_0200
 * @tc.name     Change sim PIN password
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AlterPin_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPinTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_AlterPin_0300
 * @tc.name     Change sim PIN password
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AlterPin_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPinTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockPin2_0100
 * @tc.name     Unlock sim PIN2 lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPin2_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPin2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPin2_0200
 * @tc.name     Unlock sim PIN2 lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPin2_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPin2TestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPin2_0300
 * @tc.name     Unlock sim PIN2 lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPin2_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPin2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockPuk2_0100
 * @tc.name     Unlock sim PUK2 lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPuk2_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPuk2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPuk2_0200
 * @tc.name     Unlock sim PUK2 lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPuk2_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPuk2TestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPuk2_0300
 * @tc.name     Unlock sim PUK2 lock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockPuk2_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPuk2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_AlterPin2_0100
 * @tc.name     Change sim PIN2 password
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AlterPin2_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPin2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_AlterPin2_0200
 * @tc.name     Change sim PIN2 password
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AlterPin2_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPin2TestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_AlterPin2_0300
 * @tc.name     Change sim PIN2 password
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AlterPin2_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPin2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_HasOperatorPrivileges_0100
 * @tc.name     Whether has operator privileges
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_HasOperatorPrivileges_0100, Function | MediumTest | Level3)
{
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreServiceClient::GetInstance().GetSimState(SimTest::slotId_, simState);
    if (!(SimTest::HasSimCard(SimTest::slotId_)) || (simState != SimState::SIM_STATE_READY)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(HasOperatorPrivileges, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_HasOperatorPrivileges_0200
 * @tc.name     Whether has operator privileges
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_HasOperatorPrivileges_0200, Function | MediumTest | Level3)
{
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreServiceClient::GetInstance().GetSimState(SimTest::slotId1_, simState);
    if (!(SimTest::HasSimCard(SimTest::slotId1_)) || (simState != SimState::SIM_STATE_READY)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(HasOperatorPrivileges1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SetVoiceMailInfo_0100
 * @tc.name     Set voice mail info
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetVoiceMailInfo_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetVoiceMailInfoTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SetVoiceMailInfo_0200
 * @tc.name     Set voice mail info
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetVoiceMailInfo_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetVoiceMailInfoTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SetVoiceMailInfo_0300
 * @tc.name     Set voice mail info
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetVoiceMailInfo_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetVoiceMailInfoTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
