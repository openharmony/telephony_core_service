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
#include "sim_test.h"

#include <string>
#include <unistd.h>

#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "core_service_test_helper.h"
#include "enum_convert.h"
#include "iservice_registry.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_operator_brocast_test.h"
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "tel_profile_util.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
sptr<ICoreService> SimTest::telephonyService_ = nullptr;

void SimTest::SetUpTestCase()
{
    TELEPHONY_LOGI("----------Sim gtest start ------------");
    if (telephonyService_ == nullptr) {
        telephonyService_ = GetProxy();
    }
    InitBroadCast();
}

void SimTest::InitBroadCast()
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(1);
    std::shared_ptr<SimOperatorBrocastTest> subscriber = std::make_shared<SimOperatorBrocastTest>(subscribeInfo);
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber);
    SimOperatorBrocastTest::telephonyService_ = telephonyService_;
}

void SimTest::TearDownTestCase()
{
    TELEPHONY_LOGI("----------Sim gtest end ------------");
}

void SimTest::SetUp() {}

void SimTest::TearDown() {}

sptr<ICoreService> SimTest::GetProxy()
{
    TELEPHONY_LOGI("TelephonyTestService GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Get ISystemAbilityManager failed!!!");
        return nullptr;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote) {
        sptr<ICoreService> telephonyService = iface_cast<ICoreService>(remote);
        return telephonyService;
    } else {
        TELEPHONY_LOGE("TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail ...");
        return nullptr;
    }
}

bool SimTest::HasSimCard(int32_t slotId)
{
    bool hasSimCard = false;
    CoreServiceClient::GetInstance().HasSimCard(slotId, hasSimCard);
    return hasSimCard;
}

#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number  Telephony_Sim_ParseOperatorConf_0100
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_ParseOperatorConf_0100, Function | MediumTest | Level1)
{
    ParseOperatorConf(SimTest::slotId_);
}

/**
 * @tc.number  Telephony_Sim_ParseOperatorConf_0200
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ParseOperatorConf_0200, Function | MediumTest | Level1)
{
    ParseOperatorConf(SimTest::slotId1_);
}

/**
 * @tc.number  Telephony_Sim_ParseOperatorConf_0300
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ParseOperatorConf_0300, Function | MediumTest | Level1)
{
    ParseOperatorConf(SimTest::slotIdErr_);
}

void SimTest::ParseOperatorConf(int32_t slotId)
{
    AccessToken token;
    if (SimTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("ParseOperatorConf TelephonyTestService Remote service is null");
        return;
    }
    const std::string rawJson = R"({ "string": "JSON中国", "long": 2147483699, "int": 88, "bool": true,
        "strA": ["street", "city", "country"], "longA": [ 2147483699, 2147483900, 2147499999],
        "intA": [1, 2, 3]})";
    JSONCPP_STRING err;
    Json::Value root;
    Json::CharReaderBuilder builder;
    Json::CharReader *reader(builder.newCharReader());
    if (!reader->parse(rawJson.c_str(), rawJson.c_str() + rawJson.length(), &root, &err)) {
        TELEPHONY_LOGE("ParserUtil::ParserPdpProfileJson reader is error!\n");
        return;
    }
    delete reader;
    OperatorConfigCache ofpc(nullptr, nullptr, slotId);
    OperatorFileParser ofp;
    OperatorConfig poc;
    std::u16string result;
    CoreServiceClient::GetInstance().GetSimIccId(slotId, result);
    const std::string iccid = Str16ToStr8(result);
    std::string filename = ofpc.EncryptIccId(iccid) + ".json";
    if (slotId == SimTest::slotIdErr_) {
        filename = "";
    }
    ofp.WriteOperatorConfigJson(filename, root);
    Json::Value ret;
    ofp.ParseOperatorConfigFromFile(poc, filename, ret);
    if (slotId == SimTest::slotIdErr_) {
        EXPECT_TRUE(true);
        return;
    }
    if (poc.stringArrayValue.find("string") != poc.stringArrayValue.end()) {
        EXPECT_EQ("JSON中国", poc.stringValue["string"]);
    }
    if (poc.stringArrayValue.find("long") != poc.stringArrayValue.end()) {
        EXPECT_EQ(2147483699, poc.longValue["long"]);
    }
    if (poc.stringArrayValue.find("int") != poc.stringArrayValue.end()) {
        EXPECT_EQ(88, poc.intValue["int"]);
    }
    if (poc.stringArrayValue.find("bool") != poc.stringArrayValue.end()) {
        EXPECT_EQ(true, poc.boolValue["bool"]);
    }
    if (poc.stringArrayValue.find("strA") != poc.stringArrayValue.end()) {
        EXPECT_EQ("street", poc.stringArrayValue["strA"][0]);
    }
    if (poc.intArrayValue.find("intA") != poc.intArrayValue.end()) {
        EXPECT_EQ(2, poc.intArrayValue["intA"][1]);
    }
    if (poc.longArrayValue.find("longA") != poc.longArrayValue.end()) {
        EXPECT_EQ(2147499999, poc.longArrayValue["longA"][2]);
    }
}

/**
 * @tc.number  Telephony_Sim_ParseFromCustomSystem_0100
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_ParseFromCustomSystem_0100, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_Sim_ParseFromCustomSystem_0100 start");
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
        Json::Value opcJsonValue;
        if (isCanGetFromDefaultCustomSystemNormal) {
            EXPECT_EQ(parser.ParseFromCustomSystem(SimTest::slotId_, opc, opcJsonValue),
                isCanGetFromDefaultCustomSystemNormal);
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
        if (poc.stringArrayValue.find("string") != poc.stringArrayValue.end()) {
            EXPECT_EQ("JSON中国", poc.stringValue["string"]);
        }
        if (poc.stringArrayValue.find("long") != poc.stringArrayValue.end()) {
            EXPECT_EQ(2147483699, poc.longValue["long"]);
        }
        if (poc.stringArrayValue.find("int") != poc.stringArrayValue.end()) {
            EXPECT_EQ(88, poc.intValue["int"]);
        }
        if (poc.stringArrayValue.find("bool") != poc.stringArrayValue.end()) {
            EXPECT_EQ(true, poc.boolValue["bool"]);
        }
        if (poc.stringArrayValue.find("strA") != poc.stringArrayValue.end()) {
            EXPECT_EQ("street", poc.stringArrayValue["strA"][0]);
        }
        if (poc.intArrayValue.find("intA") != poc.intArrayValue.end()) {
            EXPECT_EQ(2, poc.intArrayValue["intA"][1]);
        }
        if (poc.longArrayValue.find("longA") != poc.longArrayValue.end()) {
            EXPECT_EQ(2147499999, poc.longArrayValue["longA"][2]);
        }
    }
}

/**
 * @tc.number  Telephony_Sim_ParseFromCustomSystem_0300
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ParseFromCustomSystem_0300, Function | MediumTest | Level1)
{
    TELEPHONY_LOGI("Telephony_Sim_ParseFromCustomSystem_0300 start");
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
        Json::Value opcJsonValue;
        if (isCanGetFromDefaultCustomSystemNormal) {
            EXPECT_EQ(parser.ParseFromCustomSystem(SimTest::slotId1_, opc, opcJsonValue),
                isCanGetFromDefaultCustomSystemNormal);
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
        if (poc.stringArrayValue.find("string") != poc.stringArrayValue.end()) {
            EXPECT_EQ("JSON中国", poc.stringValue["string"]);
        }
        if (poc.stringArrayValue.find("long") != poc.stringArrayValue.end()) {
            EXPECT_EQ(2147483699, poc.longValue["long"]);
        }
        if (poc.stringArrayValue.find("int") != poc.stringArrayValue.end()) {
            EXPECT_EQ(88, poc.intValue["int"]);
        }
        if (poc.stringArrayValue.find("bool") != poc.stringArrayValue.end()) {
            EXPECT_EQ(true, poc.boolValue["bool"]);
        }
        if (poc.stringArrayValue.find("strA") != poc.stringArrayValue.end()) {
            EXPECT_EQ("street", poc.stringArrayValue["strA"][0]);
        }
        if (poc.intArrayValue.find("intA") != poc.intArrayValue.end()) {
            EXPECT_EQ(2, poc.intArrayValue["intA"][1]);
        }
        if (poc.longArrayValue.find("longA") != poc.longArrayValue.end()) {
            EXPECT_EQ(2147499999, poc.longArrayValue["longA"][2]);
        }
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
        EXPECT_NE(result, TELEPHONY_ERR_SUCCESS);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccAdnDiallingNumbers_0100
 * @tc.name     Query ADN dialling numbers
 * @tc.desc     Function test
 */
void QueryIccAdnDiallingNumbersTestFunc(CoreServiceTestHelper &helper)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    CoreServiceClient::GetInstance().QueryIccDiallingNumbers(
        SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumbers);
    helper.NotifyAll();
}

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
void QueryIccAdnDiallingNumbersTestFunc1(CoreServiceTestHelper &helper)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    CoreServiceClient::GetInstance().QueryIccDiallingNumbers(
        SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumbers);
    helper.NotifyAll();
}

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
void QueryIccFdnDiallingNumbersTestFunc(CoreServiceTestHelper &helper)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    CoreServiceClient::GetInstance().QueryIccDiallingNumbers(
        SimTest::slotId_, DiallingNumbersInfo::SIM_FDN, diallingNumbers);
    helper.NotifyAll();
}

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
void QueryIccFdnDiallingNumbersTestFunc1(CoreServiceTestHelper &helper)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    CoreServiceClient::GetInstance().QueryIccDiallingNumbers(
        SimTest::slotId1_, DiallingNumbersInfo::SIM_FDN, diallingNumbers);
    helper.NotifyAll();
}

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
void SetLockStateTestFunc(CoreServiceTestHelper &helper)
{
    LockInfo testInfo;
    testInfo.lockType = LockType::PIN_LOCK;
    testInfo.password = Str8ToStr16("1234");
    testInfo.lockState = LockState::LOCK_OFF;
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().SetLockState(SimTest::slotId_, testInfo, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void SetLockStateTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    LockInfo testInfo;
    testInfo.lockType = LockType::PIN_LOCK;
    testInfo.password = Str8ToStr16("1234");
    testInfo.lockState = LockState::LOCK_OFF;
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().SetLockState(SimTest::slotId1_, testInfo, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void SetFDNStateTestFunc(CoreServiceTestHelper &helper)
{
    LockInfo testInfo;
    testInfo.lockType = LockType::FDN_LOCK;
    testInfo.password = Str8ToStr16("1234");
    testInfo.lockState = LockState::LOCK_OFF;
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().SetLockState(SimTest::slotId_, testInfo, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void SetFDNStateTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    LockInfo testInfo;
    testInfo.lockType = LockType::FDN_LOCK;
    testInfo.password = Str8ToStr16("1234");
    testInfo.lockState = LockState::LOCK_OFF;
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().SetLockState(SimTest::slotId1_, testInfo, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void GetLockStateTestFunc(CoreServiceTestHelper &helper)
{
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType = LockType::PIN_LOCK;
    int32_t result = CoreServiceClient::GetInstance().GetLockState(SimTest::slotId_, lockType, lockState);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void GetLockStateTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType = LockType::PIN_LOCK;
    int32_t result = CoreServiceClient::GetInstance().GetLockState(SimTest::slotId1_, lockType, lockState);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void GetFDNStateTestFunc(CoreServiceTestHelper &helper)
{
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType = LockType::FDN_LOCK;
    int32_t result = CoreServiceClient::GetInstance().GetLockState(SimTest::slotId_, lockType, lockState);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void GetFDNStateTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType = LockType::FDN_LOCK;
    int32_t result = CoreServiceClient::GetInstance().GetLockState(SimTest::slotId1_, lockType, lockState);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockPinTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin = Str8ToStr16("1234");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPin(SimTest::slotId_, pin, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockPinTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string pin = Str8ToStr16("1234");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPin(SimTest::slotId1_, pin, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockPukTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin = Str8ToStr16("1234");
    const std::u16string puk = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPuk(SimTest::slotId_, pin, puk, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockPukTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string pin = Str8ToStr16("1234");
    const std::u16string puk = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPuk(SimTest::slotId1_, pin, puk, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void AlterPinTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string newpin = Str8ToStr16("1234");
    const std::u16string oldpin = Str8ToStr16("4321");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().AlterPin(SimTest::slotId_, newpin, oldpin, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void AlterPinTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string newpin = Str8ToStr16("1234");
    const std::u16string oldpin = Str8ToStr16("4321");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().AlterPin(SimTest::slotId1_, newpin, oldpin, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockPin2TestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin2 = Str8ToStr16("12345678");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPin2(SimTest::slotId_, pin2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockPin2TestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string pin2 = Str8ToStr16("12345678");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPin2(SimTest::slotId1_, pin2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockPuk2TestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin2 = Str8ToStr16("12345678");
    const std::u16string puk2 = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPuk2(SimTest::slotId_, pin2, puk2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockPuk2TestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string pin2 = Str8ToStr16("12345678");
    const std::u16string puk2 = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPuk2(SimTest::slotId1_, pin2, puk2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void AlterPin2TestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string newpin2 = Str8ToStr16("12345678");
    const std::u16string oldpin2 = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().AlterPin2(SimTest::slotId_, newpin2, oldpin2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void AlterPin2TestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string newpin2 = Str8ToStr16("12345678");
    const std::u16string oldpin2 = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().AlterPin2(SimTest::slotId1_, newpin2, oldpin2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
 * @tc.number   Telephony_Sim_SetActiveSim_0100
 * @tc.name     Set current sim active state
 * @tc.desc     Function test
 */
void SetActiveSimTestFunc(CoreServiceTestHelper &helper)
{
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSim(SimTest::slotId_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void SetActiveSimTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSim(SimTest::slotId1_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void ReSetActiveSimTestFunc(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSim(SimTest::slotId_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void ReSetActiveSimTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSim(SimTest::slotId1_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
 * @tc.number   Telephony_Sim_HasOperatorPrivileges_0100
 * @tc.name     Whether has operator privileges
 * @tc.desc     Function test
 */
void HasOperatorPrivileges(CoreServiceTestHelper &helper)
{
    constexpr int32_t slotId = 0;
    bool hasOperatorPrivileges = false;
    int32_t result = CoreServiceClient::GetInstance().HasOperatorPrivileges(slotId, hasOperatorPrivileges);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void HasOperatorPrivileges1(CoreServiceTestHelper &helper)
{
    constexpr int32_t slotId = 1;
    bool hasOperatorPrivileges = false;
    int32_t result = CoreServiceClient::GetInstance().HasOperatorPrivileges(slotId, hasOperatorPrivileges);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockSimLockTestFunc(CoreServiceTestHelper &helper)
{
    PersoLockInfo lockInfo;
    lockInfo.lockType = PersoLockType::PN_PIN_LOCK;
    lockInfo.password = Str8ToStr16("1234");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockSimLock(SimTest::slotId_, lockInfo, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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
void UnlockSimLockTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    PersoLockInfo lockInfo;
    lockInfo.lockType = PersoLockType::PN_PIN_LOCK;
    lockInfo.password = Str8ToStr16("1234");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockSimLock(SimTest::slotId1_, lockInfo, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

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

void SimAuthenticationTestFunc(CoreServiceTestHelper &helper)
{
    SimAuthenticationResponse response = { 0 };
    std::string aid = "aa";
    std::string authData = "1234";
    int32_t result = CoreServiceClient::GetInstance().SimAuthentication(SimTest::slotId_, aid, authData, response);
    helper.SetBoolResult(result == 0);
    helper.NotifyAll();
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

void SimAuthenticationTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    SimAuthenticationResponse response = { 0 };
    std::string aid = "aa";
    std::string authData = "1234";
    int32_t result = CoreServiceClient::GetInstance().SimAuthentication(SimTest::slotId1_, aid, authData, response);
    helper.SetBoolResult(result == 0);
    helper.NotifyAll();
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

void SendTerminalResponseCmdTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    std::string cmd = "send terminal response";
    int32_t result = CoreServiceClient::GetInstance().SendTerminalResponseCmd(slotId, cmd);
    helper.SetIntResult(result);
    helper.NotifyAll();
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

void SendTerminalResponseCmdTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int32_t slotId = 1;
    std::string cmd = "send terminal response";
    int32_t result = CoreServiceClient::GetInstance().SendTerminalResponseCmd(slotId, cmd);
    helper.SetIntResult(result);
    helper.NotifyAll();
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

void SendEnvelopeCmdTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    std::string cmd = "send envelope";
    int32_t result = CoreServiceClient::GetInstance().SendEnvelopeCmd(slotId, cmd);
    helper.SetIntResult(result);
    helper.NotifyAll();
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

void SendEnvelopeCmdTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int32_t slotId = 1;
    std::string cmd = "send envelope";
    int32_t result = CoreServiceClient::GetInstance().SendEnvelopeCmd(slotId, cmd);
    helper.SetIntResult(result);
    helper.NotifyAll();
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

void SendCallSetupRequestResultTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    bool accept = true;
    int32_t result = CoreServiceClient::GetInstance().SendCallSetupRequestResult(slotId, accept);
    helper.SetIntResult(result);
    helper.NotifyAll();
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

void SendCallSetupRequestResultTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int32_t slotId = 1;
    bool accept = true;
    int32_t result = CoreServiceClient::GetInstance().SendCallSetupRequestResult(slotId, accept);
    helper.SetIntResult(result);
    helper.NotifyAll();
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

void SetVoiceMailInfoTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string mailName = Str8ToStr16("张三");
    const std::u16string mailnumber = Str8ToStr16("13123456789");
    int32_t result = CoreServiceClient::GetInstance().SetVoiceMailInfo(SimTest::slotId_, mailName, mailnumber);
    helper.SetIntResult(result);
    helper.NotifyAll();
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

void SetVoiceMailInfoTestFunc1(CoreServiceTestHelper &helper)
{
    const std::u16string mailName = Str8ToStr16("张三");
    const std::u16string mailnumber = Str8ToStr16("13123456789");
    int32_t result = CoreServiceClient::GetInstance().SetVoiceMailInfo(SimTest::slotId1_, mailName, mailnumber);
    helper.SetIntResult(result);
    helper.NotifyAll();
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
 * @tc.number   Telephony_Sim_GetNrOptionMode_0100
 * @tc.name     get nr option mode
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetNrOptionMode_0100, Function | MediumTest | Level3)
{
    if (!SimTest::HasSimCard(slotId_)) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card or Nr not supported");
    } else {
        NrMode nrMode = NrMode::NR_MODE_UNKNOWN;
        int result = CoreServiceClient::GetInstance().GetNrOptionMode(slotId_, nrMode);
        ASSERT_TRUE(result == TELEPHONY_ERR_SUCCESS);
        ASSERT_GT(static_cast<int>(nrMode), -1);
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
 * @tc.number   Telephony_Sim_TestEnumCovert_0100
 * @tc.name     Enum_Covert
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestEnumCovert_0100, Function | MediumTest | Level3)
{
    int32_t errorSimState = 7;
    int32_t errorCallState = 9;
    int32_t errorTelephonyCardType = 1;
    EXPECT_EQ(GetBoolValue(0), "FALSE");
    EXPECT_EQ(GetBoolValue(1), "TRUE");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_UNKNOWN)), "SIM_STATE_UNKNOWN");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_NOT_PRESENT)), "SIM_STATE_NOT_PRESENT");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_LOCKED)), "SIM_STATE_LOCKED");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_NOT_READY)), "SIM_STATE_NOT_READY");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_READY)), "SIM_STATE_READY");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_LOADED)), "SIM_STATE_LOADED");
    EXPECT_EQ(GetSimState(errorSimState), "");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_ACTIVE)), "CALL_STATUS_ACTIVE");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_HOLDING)), "CALL_STATUS_HOLDING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_DIALING)), "CALL_STATUS_DIALING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_ALERTING)), "CALL_STATUS_ALERTING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_INCOMING)), "CALL_STATUS_INCOMING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_WAITING)), "CALL_STATUS_WAITING");
    EXPECT_EQ(
        GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_DISCONNECTED)), "CALL_STATUS_DISCONNECTED");
    EXPECT_EQ(
        GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_DISCONNECTING)), "CALL_STATUS_DISCONNECTING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_IDLE)), "CALL_STATUS_IDLE");
    EXPECT_EQ(GetCallState(errorCallState), "CALL_STATUS_IDLE");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::UNKNOWN_CARD)), "UNKNOWN_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::SINGLE_MODE_SIM_CARD)), "SINGLE_MODE_SIM_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::SINGLE_MODE_USIM_CARD)), "SINGLE_MODE_USIM_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::SINGLE_MODE_RUIM_CARD)), "SINGLE_MODE_RUIM_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::DUAL_MODE_CG_CARD)), "DUAL_MODE_CG_CARD");
    EXPECT_EQ(
        GetCardType(static_cast<int32_t>(TelephonyCardType::CT_NATIONAL_ROAMING_CARD)), "CT_NATIONAL_ROAMING_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::CU_DUAL_MODE_CARD)), "CU_DUAL_MODE_CARD");
    EXPECT_EQ(
        GetCardType(static_cast<int32_t>(TelephonyCardType::DUAL_MODE_TELECOM_LTE_CARD)), "DUAL_MODE_TELECOM_LTE_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::DUAL_MODE_UG_CARD)), "DUAL_MODE_UG_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::SINGLE_MODE_ISIM_CARD)), "SINGLE_MODE_ISIM_CARD");
    EXPECT_EQ(GetCardType(errorTelephonyCardType), "");
}

/**
 * @tc.number   Telephony_Sim_TestEnumCovert_0200
 * @tc.name     Enum_Covert
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestEnumCovert_0200, Function | MediumTest | Level3)
{
    int32_t errorTelephonyCellDataFlowType = 5;
    int32_t errorDataConnectStatus = 13;
    EXPECT_EQ(GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_NONE)),
        "DATA_FLOW_TYPE_NONE");
    EXPECT_EQ(GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_DOWN)),
        "DATA_FLOW_TYPE_DOWN");
    EXPECT_EQ(
        GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_UP)), "DATA_FLOW_TYPE_UP");
    EXPECT_EQ(GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_UP_DOWN)),
        "DATA_FLOW_TYPE_UP_DOWN");
    EXPECT_EQ(GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_DORMANT)),
        "DATA_FLOW_TYPE_DORMANT");
    EXPECT_EQ(GetCellularDataFlow(errorTelephonyCellDataFlowType), "");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_UNKNOWN)),
        "RADIO_TECHNOLOGY_UNKNOWN");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_GSM)),
        "RADIO_TECHNOLOGY_GSM");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_1XRTT)),
        "RADIO_TECHNOLOGY_1XRTT");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_WCDMA)),
        "RADIO_TECHNOLOGY_WCDMA");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_HSPA)),
        "RADIO_TECHNOLOGY_HSPA");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_HSPAP)),
        "RADIO_TECHNOLOGY_HSPAP");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_TD_SCDMA)),
        "RADIO_TECHNOLOGY_TD_SCDMA");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_EVDO)),
        "RADIO_TECHNOLOGY_EVDO");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_EHRPD)),
        "RADIO_TECHNOLOGY_EHRPD");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_LTE)),
        "RADIO_TECHNOLOGY_LTE");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_LTE_CA)),
        "RADIO_TECHNOLOGY_LTE_CA");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_IWLAN)),
        "RADIO_TECHNOLOGY_IWLAN");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_NR)),
        "RADIO_TECHNOLOGY_NR");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(errorDataConnectStatus), "");
}

/**
 * @tc.number   Telephony_Sim_TestEnumCovert_0300
 * @tc.name     Enum_Covert
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestEnumCovert_0300, Function | MediumTest | Level3)
{
    int32_t errorTelephonyLockReason = 13;
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_NONE)), "SIM_NONE");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PIN)), "SIM_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PUK)), "SIM_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PN_PIN)), "SIM_PN_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PN_PUK)), "SIM_PN_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PU_PIN)), "SIM_PU_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PU_PUK)), "SIM_PU_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PP_PIN)), "SIM_PP_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PP_PUK)), "SIM_PP_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PC_PIN)), "SIM_PC_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PC_PUK)), "SIM_PC_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_SIM_PIN)), "SIM_SIM_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_SIM_PUK)), "SIM_SIM_PUK");
    EXPECT_EQ(GetLockReason(errorTelephonyLockReason), "");
}

/**
 * @tc.number   Telephony_Sim_TestStrCovert_0100
 * @tc.name     Enum_Covert
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestStrCovert_0100, Function | MediumTest | Level3)
{
    std::string testU8Str = "test";
    std::u16string testU16Str = u"test";
    std::u32string testU32Str = U"test";
    std::wstring testWstr = L"test";
    EXPECT_EQ(ToUtf16(testU8Str), testU16Str);
    EXPECT_EQ(ToUtf8(testU16Str), testU8Str);
    EXPECT_EQ(ToUtf32(testU8Str), testU32Str);
    EXPECT_EQ(ToUtf8(testU32Str), testU8Str);
    EXPECT_EQ(ToUtf8(testWstr), testU8Str);
}

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
    EXPECT_NE(mCoreService->GetMeid(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetUniqueDeviceId(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    NrMode mNrMode;
    EXPECT_NE(mCoreService->GetNrOptionMode(0, mNrMode), TELEPHONY_ERR_SUCCESS);
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
    mCoreService->SetPrimarySlotId(0);
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
    EXPECT_NE(mCoreService->SimAuthentication(0, "", "", mSimAuthenticationResponse), TELEPHONY_ERR_SUCCESS);
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
    EXPECT_NE(mCoreService->GetMeid(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(mCoreService->GetUniqueDeviceId(0, testU16Str), TELEPHONY_ERR_SUCCESS);
    NrMode mNrMode;
    EXPECT_NE(mCoreService->GetNrOptionMode(0, mNrMode), TELEPHONY_ERR_SUCCESS);
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
    mCoreService->SetPrimarySlotId(0);
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
    EXPECT_NE(mCoreService->SimAuthentication(0, "", "", mSimAuthenticationResponse), TELEPHONY_ERR_SUCCESS);
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
 * @tc.number   Telephony_Sim_CoreService_0600
 * @tc.name    CoreService
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_CoreService_0600, Function | MediumTest | Level3)
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
 * @tc.number   Telephony_Sim_TestDump_0100
 * @tc.name    TestDump
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestDump_0100, Function | MediumTest | Level3)
{
    std::vector<std::u16string> emptyArgs = {};
    std::vector<std::u16string> args = { u"test", u"test1" };
    EXPECT_EQ(DelayedSingleton<CoreService>::GetInstance()->Dump(-1, args), TELEPHONY_ERR_ARGUMENT_INVALID);
    EXPECT_EQ(DelayedSingleton<CoreService>::GetInstance()->Dump(0, emptyArgs), 0);
    EXPECT_EQ(DelayedSingleton<CoreService>::GetInstance()->Dump(0, args), 0);
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
