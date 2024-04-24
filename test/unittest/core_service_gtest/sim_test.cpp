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
 * @tc.number  Telephony_Sim_ParseOperatorConf_0100
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_ParseOperatorConf_0100, Function | MediumTest | Level1)
{
    EXPECT_TRUE(ParseOperatorConf(SimTest::slotId_));
}

/**
 * @tc.number  Telephony_Sim_ParseOperatorConf_0200
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ParseOperatorConf_0200, Function | MediumTest | Level1)
{
    EXPECT_TRUE(ParseOperatorConf(SimTest::slotId1_));
}

/**
 * @tc.number  Telephony_Sim_ParseOperatorConf_0300
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ParseOperatorConf_0300, Function | MediumTest | Level1)
{
    EXPECT_FALSE(ParseOperatorConf(SimTest::slotIdErr_));
}

/**
 * @tc.number  Telephony_Sim_ParseFromCustomSystem_0100
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_ParseFromCustomSystem_0100, Function | MediumTest | Level1)
{
    if (!(SimTest::HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGE("Telephony_Sim_GetOperatorConf_0100 Sim card is null");
    } else {
        bool isCanGetFromDefaultCustomSystemNormal = false;
        std::vector<const char *> defaultPath { "/system/operator_config.json", "/chipset/operator_config.json",
            "/sys_prod/operator_config.json", "/chip_prod/operator_config.json" };
        int32_t fileExit = 0;
        for (auto path : defaultPath) {
            if (access(path, R_OK) == fileExit) {
                isCanGetFromDefaultCustomSystemNormal = true;
            } else {
                TELEPHONY_LOGI("%{public}s not exist", path);
            }
        }
        OperatorConfig opc;
        OperatorFileParser parser;
        cJSON *opcJsonValue = nullptr;
        if (isCanGetFromDefaultCustomSystemNormal) {
            EXPECT_EQ(parser.ParseFromCustomSystem(SimTest::slotId_, opc, opcJsonValue),
                isCanGetFromDefaultCustomSystemNormal);
        }
        if (opcJsonValue != nullptr) {
            cJSON_Delete(opcJsonValue);
            opcJsonValue = nullptr;
        }
    }
}

/**
 * @tc.number  Telephony_Sim_ParseOperatorConf_0200
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_GetOperatorConf_0200, Function | MediumTest | Level1)
{
    OperatorFileParser ofp;
    OperatorConfig poc;
    if (!(SimTest::HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGE("Telephony_Sim_GetOperatorConf_0200 TelephonyTestService has no sim card");
    } else {
        TELEPHONY_LOGI("Telephony_Sim_GetOperatorConf_0200 TelephonyTestService Remote service start");
        CoreServiceClient::GetInstance().GetOperatorConfigs(SimTest::slotId_, poc);
        CoreManagerInner::GetInstance().GetOperatorConfigs(SimTest::slotId_, poc);
        CompareOperatorConfProcess(poc);
    }
}

/**
 * @tc.number  Telephony_Sim_ParseFromCustomSystem_0300
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ParseFromCustomSystem_0300, Function | MediumTest | Level1)
{
    if (!(SimTest::HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGE("Telephony_Sim_GetOperatorConf_0300 Sim card is null");
    } else {
        bool isCanGetFromDefaultCustomSystemNormal = false;
        std::vector<const char *> defaultPath { "/system/operator_config.json", "/chipset/operator_config.json",
            "/sys_prod/operator_config.json", "/chip_prod/operator_config.json" };
        int32_t fileExit = 0;
        for (auto path : defaultPath) {
            if (access(path, R_OK) == fileExit) {
                isCanGetFromDefaultCustomSystemNormal = true;
            } else {
                TELEPHONY_LOGI("%{public}s not exist", path);
            }
        }
        OperatorConfig opc;
        OperatorFileParser parser;
        cJSON *opcJsonValue = nullptr;
        if (isCanGetFromDefaultCustomSystemNormal) {
            EXPECT_EQ(parser.ParseFromCustomSystem(SimTest::slotId1_, opc, opcJsonValue),
                isCanGetFromDefaultCustomSystemNormal);
        }
        if (opcJsonValue != nullptr) {
            cJSON_Delete(opcJsonValue);
            opcJsonValue = nullptr;
        }
    }
}

/**
 * @tc.number  Telephony_Sim_ParseOperatorConf_0400
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOperatorConf_0400, Function | MediumTest | Level1)
{
    OperatorFileParser ofp;
    OperatorConfig poc;
    if (!(SimTest::HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGE("Telephony_Sim_GetOperatorConf_0400 TelephonyTestService has no sim card");
        SimTest::telephonyService_ = GetProxy();
    } else {
        TELEPHONY_LOGI("Telephony_Sim_GetOperatorConf_0400 TelephonyTestService Remote service start");
        CoreServiceClient::GetInstance().GetOperatorConfigs(SimTest::slotId1_, poc);
        CoreManagerInner::GetInstance().GetOperatorConfigs(SimTest::slotId1_, poc);
        CompareOperatorConfProcess(poc);
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimState_0100
 * @tc.name     Get sim state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimState_0100, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        SimState simState = SimState::SIM_STATE_UNKNOWN;
        int32_t result = CoreServiceClient::GetInstance().GetSimState(SimTest::slotId_, simState);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimState_0200
 * @tc.name     Get sim state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimState_0200, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        SimState simState = SimState::SIM_STATE_UNKNOWN;
        int32_t result = CoreServiceClient::GetInstance().GetSimState(SimTest::slotId1_, simState);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_HasSimCard_0100
 * @tc.name     whether a SIM is present
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_HasSimCard_0100, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = SimTest::HasSimCard(SimTest::slotId_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_HasSimCard_0200
 * @tc.name     whether a SIM is present
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_HasSimCard_0200, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = SimTest::HasSimCard(SimTest::slotId1_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetISOCountryCodeForSim_0100
 * @tc.name     Get sim iso country code
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetISOCountryCodeForSim_0100, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string countryCode;
        CoreServiceClient::GetInstance().GetISOCountryCodeForSim(SimTest::slotId_, countryCode);
        std::string result = Str16ToStr8(countryCode);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetISOCountryCodeForSim_0200
 * @tc.name     Get sim iso country code
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetISOCountryCodeForSim_0200, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string countryCode;
        CoreServiceClient::GetInstance().GetISOCountryCodeForSim(SimTest::slotId1_, countryCode);
        std::string result = Str16ToStr8(countryCode);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetLocaleFromDefaultSim_0100
 * @tc.name     Get sim locale
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_GetLocaleFromDefaultSim_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "test";
        result = Str16ToStr8(CoreServiceClient::GetInstance().GetLocaleFromDefaultSim());
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_SetVoiceCallForwarding_0100
 * @tc.name     Set sim voicecall forwarding
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetVoiceCallForwarding_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::string number = "01234567890123456789";
        int32_t result = CoreServiceClient::GetInstance().SetVoiceCallForwarding(SimTest::slotId_, true, number);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetDefaultVoiceSlotId_0100
 * @tc.name     Get default voice sim slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetDefaultVoiceSlotId_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().GetDefaultVoiceSlotId();
        EXPECT_GT(result, -2);
    }
}

/**
 * @tc.number   Telephony_Sim_SetDefaultVoiceSlotId_0100
 * @tc.name     Set default voice sim slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetDefaultVoiceSlotId_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = CoreServiceClient::GetInstance().SetDefaultVoiceSlotId(SimTest::slotId_);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_SetDefaultVoiceSlotId_0200
 * @tc.name     Set default voice sim slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetDefaultVoiceSlotId_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = CoreServiceClient::GetInstance().SetDefaultVoiceSlotId(SimTest::slotId1_);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_SetDefaultVoiceSlotId_0300
 * @tc.name     Set default voice sim slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetDefaultVoiceSlotId_0300, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = CoreServiceClient::GetInstance().SetDefaultVoiceSlotId(SimTest::slotId_);
        EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOperatorConfig_0100
 * @tc.name     Get operator configs
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOperatorConfig_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        OperatorConfig oc;
        int32_t result = CoreServiceClient::GetInstance().GetOperatorConfigs(SimTest::slotId_, oc);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOperatorConfig_0200
 * @tc.name     Get operator configs
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOperatorConfig_0200, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        OperatorConfig oc;
        int32_t result = CoreServiceClient::GetInstance().GetOperatorConfigs(SimTest::slotId1_, oc);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOperatorConfig_0300
 * @tc.name     Get operator configs
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOperatorConfig_0300, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        OperatorConfig oc;
        int32_t result = CoreServiceClient::GetInstance().GetOperatorConfigs(SimTest::slotId_, oc);
        EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_SetShowName_0100
 * @tc.name     Set a show name for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowName_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        const std::u16string cardName = Str8ToStr16("SimNameZhang");
        int32_t result = CoreServiceClient::GetInstance().SetShowName(SimTest::slotId_, cardName);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_SetShowName_0200
 * @tc.name     Set a show name for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowName_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        const std::u16string cardName = Str8ToStr16("SimNameZhang");
        int32_t result = CoreServiceClient::GetInstance().SetShowName(SimTest::slotId1_, cardName);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_SetShowName_0300
 * @tc.name     Set a show name for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowName_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        const std::u16string cardName = Str8ToStr16("SimNameZhang");
        int32_t result = CoreServiceClient::GetInstance().SetShowName(SimTest::slotId_, cardName);
        EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_getShowName_0100
 * @tc.name     Get show name of the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowName_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string showName;
        CoreServiceClient::GetInstance().GetShowName(SimTest::slotId_, showName);
        std::string result = Str16ToStr8(showName);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_getShowName_0200
 * @tc.name     Get show name of the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowName_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string showName;
        CoreServiceClient::GetInstance().GetShowName(SimTest::slotId1_, showName);
        std::string result = Str16ToStr8(showName);
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_getShowName_0300
 * @tc.name     Get show name of the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowName_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string showName;
        CoreServiceClient::GetInstance().GetShowName(SimTest::slotId_, showName);
        std::string result = Str16ToStr8(showName);
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_getShowNumber_0100
 * @tc.name     Get show number of the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowNumber_0100, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string showNumber;
        CoreServiceClient::GetInstance().GetShowNumber(SimTest::slotId_, showNumber);
        std::string result = Str16ToStr8(showNumber);
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_getShowNumber_0200
 * @tc.name     Get show number of the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowNumber_0200, Function | MediumTest | Level1)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string showNumber;
        CoreServiceClient::GetInstance().GetShowNumber(SimTest::slotId1_, showNumber);
        std::string result = Str16ToStr8(showNumber);
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_getShowNumber_0300
 * @tc.name     Get show number of the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowNumber_0300, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string showNumber;
        CoreServiceClient::GetInstance().GetShowNumber(SimTest::slotId_, showNumber);
        std::string result = Str16ToStr8(showNumber);
        EXPECT_STREQ(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_SetShowNumber_0100
 * @tc.name     Set a show number for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowNumber_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        const std::u16string cardNumber = Str8ToStr16("SimNumber12345678901");
        int32_t result = CoreServiceClient::GetInstance().SetShowNumber(SimTest::slotId_, cardNumber);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_SetShowNumber_0200
 * @tc.name     Set a show number for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowNumber_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        const std::u16string cardNumber = Str8ToStr16("SimNumber12345678901");
        int32_t result = CoreServiceClient::GetInstance().SetShowNumber(SimTest::slotId1_, cardNumber);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_SetShowNumber_0300
 * @tc.name     Set a show number for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowNumber_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        const std::u16string cardNumber = Str8ToStr16("SimNumber12345678901");
        int32_t result = CoreServiceClient::GetInstance().SetShowNumber(SimTest::slotId_, cardNumber);
        EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_IsSimActive_0100
 * @tc.name     Get sim active state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_IsSimActive_0100, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = CoreServiceClient::GetInstance().IsSimActive(SimTest::slotId_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_IsSimActive_0200
 * @tc.name     Get sim active state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_IsSimActive_0200, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = CoreServiceClient::GetInstance().IsSimActive(SimTest::slotId1_);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_SetActiveSim_0100
 * @tc.name     Set current sim active state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetActiveSim_0100, Function | MediumTest | Level2)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetActiveSimTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SetActiveSim_0200
 * @tc.name     Set current sim active state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetActiveSim_0200, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetActiveSimTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SetActiveSim_0300
 * @tc.name     Set current sim active state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetActiveSim_0300, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetActiveSimTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_ReSetActiveSim_0100
 * @tc.name     Reset current sim active state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ReSetActiveSim_0100, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(ReSetActiveSimTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_ReSetActiveSim_0200
 * @tc.name     Reset current sim active state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ReSetActiveSim_0200, Function | MediumTest | Level2)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(ReSetActiveSimTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_GetMaxSimCount_0100
 * @tc.name     Get max sim count for device supported
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetMaxSimCount_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = CoreServiceClient::GetInstance().GetMaxSimCount();
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpKey_0100
 * @tc.name     Get opkey for current sim card
 * @tc.desc     Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpKey_0100, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string opkey;
        int32_t result = CoreServiceClient::GetInstance().GetOpKey(SimTest::slotId_, opkey);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpKey_0200
 * @tc.name     Get opkey for current sim card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpKey_0200, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string opkey;
        int32_t result = CoreServiceClient::GetInstance().GetOpKey(SimTest::slotId1_, opkey);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpKeyExt_0100
 * @tc.name     Get opkey for current sim card
 * @tc.desc     Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpKeyExt_0100, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string opkeyExt;
        int32_t result = CoreServiceClient::GetInstance().GetOpKeyExt(SimTest::slotId_, opkeyExt);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpKeyExt_0200
 * @tc.name     Get opkey for current sim card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpKeyExt_0200, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string opkeyExt;
        int32_t result = CoreServiceClient::GetInstance().GetOpKey(SimTest::slotId1_, opkeyExt);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpName_0100
 * @tc.name     Get opname for current sim card
 * @tc.desc     Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpName_0100, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string opname;
        int32_t result = CoreServiceClient::GetInstance().GetOpName(SimTest::slotId_, opname);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpName_0200
 * @tc.name     Get opname for current sim card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpName_0200, Function | MediumTest | Level1)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::u16string opname;
        int32_t result = CoreServiceClient::GetInstance().GetOpName(SimTest::slotId1_, opname);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_GetCardType_0100
 * @tc.name     Get card type
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetCardType_0100, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CardType cardType = CardType::UNKNOWN_CARD;
        int32_t result = CoreServiceClient::GetInstance().GetCardType(SimTest::slotId_, cardType);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetCardType_0200
 * @tc.name     Get card type
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetCardType_0200, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CardType cardType = CardType::UNKNOWN_CARD;
        int32_t result = CoreServiceClient::GetInstance().GetCardType(SimTest::slotId1_, cardType);
        EXPECT_GT(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_UnlockSimLock_0100
 * @tc.name     Unlock simlock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockSimLock_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockSimLockTestFunc, std::ref(helper))) {
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
 * @tc.number   Telephony_Sim_UnlockSimLock_0200
 * @tc.name     Unlock simlock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockSimLock_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockSimLockTestFunc1, std::ref(helper))) {
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
 * @tc.number   Telephony_Sim_UnlockSimLock_0300
 * @tc.name     Unlock simlock
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UnlockSimLock_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockSimLockTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SimAuthentication_0100
 * @tc.name     Sim authentication
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SimAuthentication_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SimAuthenticationTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SimAuthentication_0200
 * @tc.name     Sim authentication
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SimAuthentication_0200, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SimAuthenticationTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SimAuthentication_0300
 * @tc.name     Sim authentication
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SimAuthentication_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SimAuthenticationTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SimAuthentication_0400
 * @tc.name     Sim authentication
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SimAuthentication_0400, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SimAuthenticationTestFunc2, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SimAuthentication_0500
 * @tc.name     Sim authentication
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SimAuthentication_0500, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SimAuthenticationTestFunc3, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_GetPrimarySlotId_0100
 * @tc.name     Get primary slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetPrimarySlotId_0100, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = TELEPHONY_ERROR;
        CoreServiceClient::GetInstance().GetPrimarySlotId(result);
        EXPECT_GT(result, TELEPHONY_ERROR);
    }
}

/**
 * @tc.number   Telephony_Sim_SendTerminalResponseCmd_0100
 * @tc.name     Send Terminal Response Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendTerminalResponseCmd_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendTerminalResponseCmdTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SendTerminalResponseCmd_0200
 * @tc.name     Send Terminal Response Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendTerminalResponseCmd_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendTerminalResponseCmdTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SendTerminalResponseCmd_0300
 * @tc.name     Send Terminal Response Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendTerminalResponseCmd_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendTerminalResponseCmdTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SendEnvelopeCmd_0100
 * @tc.name     Send Envelope Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendEnvelopeCmd_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendEnvelopeCmdTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SendEnvelopeCmd_0200
 * @tc.name     Send Envelope Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendEnvelopeCmd_0200, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendEnvelopeCmdTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SendEnvelopeCmd_0300
 * @tc.name     Send Envelope Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendEnvelopeCmd_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendEnvelopeCmdTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_FALSE(result);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SendCallSetupRequestResult_0100
 * @tc.name     Send Call Setup Request Result Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendCallSetupRequestResult_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendCallSetupRequestResultTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, 0);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SendCallSetupRequestResult_0200
 * @tc.name     Send Call Setup Request Result Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendCallSetupRequestResult_0200, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId1_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendCallSetupRequestResultTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_EQ(result, 0);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_SendCallSetupRequestResult_0300
 * @tc.name     Send Call Setup Request Result Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendCallSetupRequestResult_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendCallSetupRequestResultTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            int32_t result = helper.GetIntResult();
            EXPECT_NE(result, 0);
        }
    }
}

/**
 * @tc.number   Telephony_Sim_GetSlotId_0100
 * @tc.name     Get slot id
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSlotId_0100, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t simId = 1;
        int32_t result = CoreServiceClient::GetInstance().GetSlotId(simId);
        EXPECT_GE(result, -1);
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimId_0100
 * @tc.name     Get sim id
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimId_0100, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t slotId = 0;
        int32_t result = CoreServiceClient::GetInstance().GetSimId(slotId);
        EXPECT_GT(result, 0);
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimEons_0100
 * @tc.name     Get sim eons
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimEons_0100, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        std::string plmn = "46001";
        int32_t lac = 1;
        bool longNameRequired = true;
        string result = "test";
        result = Str16ToStr8(CoreServiceClient::GetInstance().GetSimEons(slotId_, plmn, lac, longNameRequired));
        EXPECT_NE(result, "test");
    }
}

/**
 * @tc.number   Telephony_Sim_IsNrSupported_0100
 * @tc.name     Is nr  supported
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_IsNrSupported_0100, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceClient::GetInstance().IsNrSupported(slotId_);
        ASSERT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_IsNrSupported_0200
 * @tc.name     Is nr supported
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_IsNrSupported_0200, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        CoreServiceClient::GetInstance().IsNrSupported(slotId_);
        ASSERT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_GetNrOptionMode_0100
 * @tc.name     get nr option mode
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetNrOptionMode_0100, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card or Nr not supported");
    } else {
        sptr<INetworkSearchCallback> callback = nullptr;
        CoreServiceClient::GetInstance().GetNrOptionMode(slotId_, callback);
        ASSERT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_TestTelProfileUtil_0100
 * @tc.name     TestTelProfileUtil
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestTelProfileUtil_0100, Function | MediumTest | Level3)
{
    auto telProfileUtil = DelayedSingleton<TelProfileUtil>::GetInstance();
    std::string key = "test";
    std::string key1 = "test1";
    std::string value = "test";
    std::string defValue = "";
    int saveValue = 1;
    int getValue = 1;
    bool saveBool = true;
    bool getBool = true;
    int64_t longValue = 1;
    int64_t getLongValue = 1;
    float saveFloatValue = 1;
    float getFloatValue = 1;
    telProfileUtil->SaveString(key, value);
    telProfileUtil->ObtainString(key, defValue);
    telProfileUtil->SaveInt(key, saveValue);
    telProfileUtil->ObtainInt(key, getValue);
    telProfileUtil->SaveBool(key, saveBool);
    telProfileUtil->ObtainBool(key, getBool);
    telProfileUtil->SaveLong(key, longValue);
    telProfileUtil->ObtainLong(key, getLongValue);
    telProfileUtil->SaveFloat(key1, saveFloatValue);
    telProfileUtil->ObtainFloat(key1, getFloatValue);
    EXPECT_TRUE(telProfileUtil->IsExistKey(key));
    EXPECT_NE(telProfileUtil->RemoveKey(key), -1);
    EXPECT_NE(telProfileUtil->RemoveAll(), -1);
    telProfileUtil->Refresh();
    EXPECT_NE(telProfileUtil->RefreshSync(), -1);
    EXPECT_NE(telProfileUtil->DeleteProfiles(), -1);
}

/**
 * @tc.number   Telephony_Sim_TestDump_0100
 * @tc.name    TestDump
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestDump_0100, Function | MediumTest | Level3)
{
    std::vector<std::u16string> emptyArgs = {};
    std::vector<std::u16string> args = { u"test", u"test1" };
    EXPECT_GE(DelayedSingleton<CoreService>::GetInstance()->Dump(-1, args), TELEPHONY_ERROR);
    EXPECT_GE(DelayedSingleton<CoreService>::GetInstance()->Dump(0, emptyArgs), TELEPHONY_ERROR);
    EXPECT_GE(DelayedSingleton<CoreService>::GetInstance()->Dump(0, args), TELEPHONY_ERROR);
}

/**
 * @tc.number   Telephony_Sim_SetPrimarySlotId_0100
 * @tc.name     Set primary slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetPrimarySlotId_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (CoreServiceClient::GetInstance().GetMaxSimCount() == 1 ||
        !(SimTest::HasSimCard(slotId_) && SimTest::HasSimCard(slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card or one card version");
    } else {
        int32_t result = CoreServiceClient::GetInstance().SetPrimarySlotId(SimTest::slotId_);
        TELEPHONY_LOGI("TelephonyTestService SetPrimarySlotId_0100 result: %{public}d", result);
        EXPECT_NE(TELEPHONY_ERR_SUCCESS, result);
    }
}

/**
 * @tc.number   Telephony_Sim_SetPrimarySlotId_0200
 * @tc.name     Set primary slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetPrimarySlotId_0200, Function | MediumTest | Level3)
{
    AccessToken token;
    if (CoreServiceClient::GetInstance().GetMaxSimCount() == 1 ||
        !(SimTest::HasSimCard(slotId_) && SimTest::HasSimCard(slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    } else {
        int32_t result = CoreServiceClient::GetInstance().SetPrimarySlotId(SimTest::slotId1_);
        TELEPHONY_LOGI("TelephonyTestService SetPrimarySlotId_0200 result: %{public}d", result);
        EXPECT_NE(TELEPHONY_ERR_SUCCESS, result);
    }
}

/**
 * @tc.number   Telephony_Sim_SetPrimarySlotId_0300
 * @tc.name     Set primary slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetPrimarySlotId_0300, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_) || CoreServiceClient::GetInstance().GetMaxSimCount() == 1) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card or one card version");
    } else {
        int32_t result = CoreServiceClient::GetInstance().SetPrimarySlotId(SimTest::slotId_);
        TELEPHONY_LOGI("TelephonyTestService SetPrimarySlotId_0300 result: %{public}d", result);
        EXPECT_EQ(TELEPHONY_ERR_PERMISSION_ERR, result);
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
 * @tc.number   Telephony_Sim_GetDsdsMode_0100
 * @tc.name     Get Dsds Mode 3.0
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetDsdsMode_0100, Function | MediumTest | Level3)
{
    AccessToken token;
    if (!SimTest::HasSimCard(slotId_) || CoreServiceClient::GetInstance().GetMaxSimCount() == 1) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card or one card version");
    } else {
        int32_t dsdsMode = INVALID_VALUE;
        int32_t result = CoreServiceClient::GetInstance().GetDsdsMode(dsdsMode);
        TELEPHONY_LOGI("TelephonyTestService Telephony_Sim_GetDsdsMode_0100 result: %{public}d ,DsdsMode: %{public}d",
            result, dsdsMode);
        EXPECT_EQ(result, TELEPHONY_ERR_SUCCESS);
    }
}

#else // TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_Sim_MockTest_0100
 * @tc.name     A test mock for unsupported platform
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_MockTest_0100, Function | MediumTest | Level3)
{
    if (!(SimTest::HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    }
    EXPECT_TRUE(true);
}

#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
