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

#include "sim_test.h"

#include <string>
#include <unistd.h>

#include "core_manager_inner.h"
#include "core_service_client.h"
#include "core_service_test_helper.h"
#include "iservice_registry.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_operator_brocast_test.h"
#include "sim_state_type.h"
#include "string_ex.h"
#include "system_ability_definition.h"
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
 * @tc.number  Telephony_Sim_ParseOperatorConf_0100
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 * @tc.require: issueI5J919
 */
HWTEST_F(SimTest, Telephony_Sim_ParseOperatorConf_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGE("Telephony_Sim_ParseOperatorConf_0100 TelephonyTestService Remote service is null");
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
    OperatorConfigCache ofpc(nullptr, nullptr, SimTest::slotId_);
    OperatorFileParser ofp;
    OperatorConfig poc;
    const std::string iccid = Str16ToStr8(SimTest::telephonyService_->GetSimIccId(SimTest::slotId_));
    std::string filename = ofpc.EncryptIccId(iccid) + ".json";
    ofp.WriteOperatorConfigJson(filename, root);
    Json::Value ret;
    ofp.ParseOperatorConfigFromFile(poc, filename, ret);
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
 * @tc.number  Telephony_Sim_ParseOperatorConf_0200
 * @tc.name  ParseOperatorConf
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_Sim_ParseOperatorConf_0200, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGE("Telephony_Sim_ParseOperatorConf_0200 TelephonyTestService Remote service is null");
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
    OperatorConfigCache ofpc(nullptr, nullptr, SimTest::slotId1_);
    OperatorFileParser ofp;
    OperatorConfig poc;
    const std::string iccid = Str16ToStr8(SimTest::telephonyService_->GetSimIccId(SimTest::slotId1_));
    std::string filename = ofpc.EncryptIccId(iccid) + ".json";
    ofp.WriteOperatorConfigJson(filename, root);
    Json::Value ret;
    ofp.ParseOperatorConfigFromFile(poc, filename, ret);
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
    if (!(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGE("Telephony_Sim_GetOperatorConf_0200 TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        TELEPHONY_LOGI("Telephony_Sim_GetOperatorConf_0200 TelephonyTestService Remote service start");
        SimTest::telephonyService_->GetOperatorConfigs(SimTest::slotId_, poc);
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
    if (!(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGE("Telephony_Sim_GetOperatorConf_0400 TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        TELEPHONY_LOGI("Telephony_Sim_GetOperatorConf_0400 TelephonyTestService Remote service start");
        SimTest::telephonyService_->GetOperatorConfigs(SimTest::slotId1_, poc);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetSimState(SimTest::slotId_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetSimState(SimTest::slotId1_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->HasSimCard(SimTest::slotId_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->HasSimCard(SimTest::slotId1_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetISOCountryCodeForSim(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetISOCountryCodeForSim(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimSpn_0100
 * @tc.name     Get sim service privode name
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimSpn_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "testresult";
        result = Str16ToStr8(SimTest::telephonyService_->GetSimSpn(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "testresult");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimSpn_0200
 * @tc.name     Get sim service privode name
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimSpn_0200, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "testresult";
        result = Str16ToStr8(SimTest::telephonyService_->GetSimSpn(SimTest::slotId1_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimIccId(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimIccId(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimOperatorNumeric_0100
 * @tc.name     Get sim operator numeric
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimOperatorNumeric_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimOperatorNumeric(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimOperatorNumeric(SimTest::slotId1_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetIMSI(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetIMSI(SimTest::slotId1_));
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
        result = Str16ToStr8(SimTest::telephonyService_->GetLocaleFromDefaultSim());
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimGid1(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimGid1(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "");
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimGid2(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetSimGid2(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0100
 * @tc.name     Get sim telephony number
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTelephoneNumber_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(TelephoneNumber)
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetSimTelephoneNumber(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(TelephoneNumber)
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetSimTelephoneNumber(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetSimTelephoneNumber_0100
 * @tc.name     Get sim telephony number identifier
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimTeleNumberIdentifier_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
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
 * @tc.number   Telephony_Sim_GetVoiceMailIdentifier_0100
 * @tc.name     Get voicemail identifier
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailIdentifier_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailIdentifier)
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetVoiceMailIdentifier(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailIdentifier)
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetVoiceMailIdentifier(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_Sim_GetVoiceMailNumber_0100
 * @tc.name     Get sim voice mail number
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetVoiceMailNumber_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailNumber)
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetVoiceMailNumber(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        // Interface may return empty string, as sim file has not information(VoiceMailNumber)
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetVoiceMailNumber(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "test");
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
        int32_t result = SimTest::telephonyService_->GetDefaultVoiceSlotId();
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        bool result = SimTest::telephonyService_->SetDefaultVoiceSlotId(SimTest::slotId_);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_SetDefaultVoiceSlotId_0200
 * @tc.name     Set default voice sim slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetDefaultVoiceSlotId_0200, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        bool result = SimTest::telephonyService_->SetDefaultVoiceSlotId(SimTest::slotId1_);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_RefreshSimState_0100
 * @tc.name     Refresh sim state
 * @tc.desc     Function test
HWTEST_F(SimTest, Telephony_Sim_RefreshSimState_0100, Function | MediumTest | Level0)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->RefreshSimState(SimTest::slotId_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->RefreshSimState(SimTest::slotId1_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        OperatorConfig oc;
        SimTest::telephonyService_->GetOperatorConfigs(SimTest::slotId_, oc);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_GetOperatorConfig_0200
 * @tc.name     Get operator configs
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOperatorConfig_0200, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        OperatorConfig oc;
        SimTest::telephonyService_->GetOperatorConfigs(SimTest::slotId1_, oc);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_GetActiveSimAccountInfoList_0100
 * @tc.name     Get active sim accountInfoList
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetActiveSimAccountInfoList_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<IccAccountInfo> iccAccountInfoList;
        bool result = SimTest::telephonyService_->GetActiveSimAccountInfoList(iccAccountInfoList);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_GetActiveSimAccountInfoList_0200
 * @tc.name     Get active sim accountInfoList
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetActiveSimAccountInfoList_0200, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<IccAccountInfo> iccAccountInfoList;
        bool result = SimTest::telephonyService_->GetActiveSimAccountInfoList(iccAccountInfoList);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccAdnDiallingNumbers_0100
 * @tc.name     Query ADN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
            SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId_, DiallingNumbersInfo::SIM_ADN);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccAdnDiallingNumbers_0200
 * @tc.name     Query ADN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccAdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
            SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0100
 * @tc.name     Add icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        bool result = SimTest::telephonyService_->AddIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0200
 * @tc.name     Add icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    bool flag = false;
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("电话卡");
        diallingNumber->number_ = Str8ToStr16("00000000000");
        SimTest::telephonyService_->AddIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
            SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId_, DiallingNumbersInfo::SIM_ADN);
        std::u16string name = u"电话卡";
        for (size_t i = 0; i < diallingNumbers.size(); i++) {
            if (diallingNumbers[i] == nullptr) {
                continue;
            }
            if (diallingNumbers[i]->name_.compare(name) == 0) {
                TELEPHONY_LOGE("Telephony_Sim_AddIccAdnDiallingNumbers_0200 true");
                flag = true;
            } else {
                TELEPHONY_LOGE("Telephony_Sim_AddIccAdnDiallingNumbers_0200 failed");
            }
        }
        EXPECT_TRUE(flag);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0300
 * @tc.name     Add icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0300, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        bool result = SimTest::telephonyService_->AddIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccAdnDiallingNumbers_0400
 * @tc.name     Add icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccAdnDiallingNumbers_0400, Function | MediumTest | Level3)
{
    bool flag = false;
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_ADN, 0);
        diallingNumber->name_ = Str8ToStr16("电话卡");
        diallingNumber->number_ = Str8ToStr16("00000000000");
        SimTest::telephonyService_->AddIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
            SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN);
        std::u16string name = u"电话卡";
        for (size_t i = 0; i < diallingNumbers.size(); i++) {
            if (diallingNumbers[i] == nullptr) {
                continue;
            }
            if (diallingNumbers[i]->name_.compare(name) == 0) {
                TELEPHONY_LOGI("Telephony_Sim_AddIccAdnDiallingNumbers_0400 name matched");
                flag = true;
            }
        }
        EXPECT_TRUE(flag);
    }
}

/**
 * @tc.number   Telephony_Sim_UpdateIccAdnDiallingNumbers_0100
 * @tc.name     Update icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UpdateIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        diallingNumber->index_ = index;
        bool result = SimTest::telephonyService_->UpdateIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_UpdateIccAdnDiallingNumbers_0200
 * @tc.name     Update icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_UpdateIccAdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        diallingNumber->index_ = index;
        bool result = SimTest::telephonyService_->UpdateIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_DelIccAdnDiallingNumbers_0100
 * @tc.name     Delete icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_DelIccAdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->index_ = index;
        bool result = SimTest::telephonyService_->DelIccDiallingNumbers(
            SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_DelIccAdnDiallingNumbers_0200
 * @tc.name     Delete icc dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_DelIccAdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->index_ = index;
        bool result = SimTest::telephonyService_->DelIccDiallingNumbers(
            SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccFdnDiallingNumbers_0100
 * @tc.name     Query FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccFdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
            SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId_, DiallingNumbersInfo::SIM_FDN);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_QueryIccFdnDiallingNumbers_0200
 * @tc.name     Query FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_QueryIccFdnDiallingNumbers_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
            SimTest::telephonyService_->QueryIccDiallingNumbers(SimTest::slotId1_, DiallingNumbersInfo::SIM_FDN);
        EXPECT_TRUE(true);
    }
}

/**
 * @tc.number   Telephony_Sim_AddIccFdnDiallingNumbers_0100
 * @tc.name     Add icc FDN dialling numbers
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_AddIccFdnDiallingNumbers_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_FDN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        diallingNumber->pin2_ = Str8ToStr16("1234");
        SimTest::telephonyService_->AddIccDiallingNumbers(
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber =
            std::make_shared<DiallingNumbersInfo>(DiallingNumbersInfo::SIM_FDN, 0);
        diallingNumber->name_ = Str8ToStr16("SimAdnZhang");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        diallingNumber->pin2_ = Str8ToStr16("1234");
        SimTest::telephonyService_->AddIccDiallingNumbers(
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        diallingNumber->pin2_ = Str8ToStr16("1234");
        diallingNumber->index_ = index;
        SimTest::telephonyService_->UpdateIccDiallingNumbers(
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        int index = 1; // Index start from 1
        diallingNumber->name_ = Str8ToStr16("SimAdnLi");
        diallingNumber->number_ = Str8ToStr16("17789145956");
        diallingNumber->pin2_ = Str8ToStr16("1234");
        diallingNumber->index_ = index;
        SimTest::telephonyService_->UpdateIccDiallingNumbers(
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->pin2_ = Str8ToStr16("1234");
        diallingNumber->index_ = index;
        SimTest::telephonyService_->DelIccDiallingNumbers(
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int index = 1; // Index start from 1
        std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>();
        diallingNumber->pin2_ = Str8ToStr16("1234");
        diallingNumber->index_ = index;
        SimTest::telephonyService_->DelIccDiallingNumbers(
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string cardName = Str8ToStr16("SimNameZhang");
        bool result = SimTest::telephonyService_->SetShowName(SimTest::slotId_, cardName);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_SetShowName_0200
 * @tc.name     Set a show name for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowName_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string cardName = Str8ToStr16("SimNameZhang");
        bool result = SimTest::telephonyService_->SetShowName(SimTest::slotId1_, cardName);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_getShowName_0100
 * @tc.name     Get show name of the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowName_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetShowName(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = Str16ToStr8(SimTest::telephonyService_->GetShowName(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "");
    }
}

/**
 * @tc.number   Telephony_Sim_getShowNumber_0100
 * @tc.name     Get show number of the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_getShowNumber_0100, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetShowNumber(SimTest::slotId_));
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "test";
        result = Str16ToStr8(SimTest::telephonyService_->GetShowNumber(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "test");
    }
}

/**
 * @tc.number   Telephony_SetShowNumber_0100
 * @tc.name     Set a show number for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowNumber_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string cardNumber = Str8ToStr16("SimNumber17789145956");
        bool result = SimTest::telephonyService_->SetShowNumber(SimTest::slotId_, cardNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_SetShowNumber_0200
 * @tc.name     Set a show number for the current card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetShowNumber_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string cardNumber = Str8ToStr16("SimNumber17789145956");
        bool result = SimTest::telephonyService_->SetShowNumber(SimTest::slotId1_, cardNumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_IsSimActive_0100
 * @tc.name     Get sim active state
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_IsSimActive_0100, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->IsSimActive(SimTest::slotId_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->IsSimActive(SimTest::slotId1_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        IccAccountInfo info;
        bool result = SimTest::telephonyService_->GetSimAccountInfo(SimTest::slotId_, info);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_GetSimAccountInfo_0200
 * @tc.name     Get sim accountInfo
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetSimAccountInfo_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        IccAccountInfo info;
        bool result = SimTest::telephonyService_->GetSimAccountInfo(SimTest::slotId1_, info);
        EXPECT_TRUE(result);
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
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->SetLockState(SimTest::slotId_, testInfo, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_SetLockState_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetLockStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    LockInfo testInfo;
    testInfo.lockType = LockType::PIN_LOCK;
    testInfo.password = Str8ToStr16("1234");
    testInfo.lockState = LockState::LOCK_OFF;
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->SetLockState(SimTest::slotId1_, testInfo, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_SetLockState_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetLockStateTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
#endif
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
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->SetLockState(SimTest::slotId_, testInfo, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_SetFDNState_0100, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetFDNStateTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    LockInfo testInfo;
    testInfo.lockType = LockType::FDN_LOCK;
    testInfo.password = Str8ToStr16("1234");
    testInfo.lockState = LockState::LOCK_OFF;
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->SetLockState(SimTest::slotId1_, testInfo, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_SetFDNState_0200, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetFDNStateTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    LockType lockType = LockType::PIN_LOCK;
    int32_t result = SimTest::telephonyService_->GetLockState(SimTest::slotId_, lockType);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_GetLockState_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
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
    LockType lockType = LockType::PIN_LOCK;
    int32_t result = SimTest::telephonyService_->GetLockState(SimTest::slotId1_, lockType);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_GetLockState_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
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
 * @tc.number   Telephony_GetFDNState_0100
 * @tc.name     Get sim FDN lock state
 * @tc.desc     Function test
 */
void GetFDNStateTestFunc(CoreServiceTestHelper &helper)
{
    LockType lockType = LockType::FDN_LOCK;
    int32_t result = SimTest::telephonyService_->GetLockState(SimTest::slotId_, lockType);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_GetFDNState_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
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
    LockType lockType = LockType::FDN_LOCK;
    int32_t result = SimTest::telephonyService_->GetLockState(SimTest::slotId1_, lockType);
    helper.SetIntResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_GetFDNState_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
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
 * @tc.number   Telephony_Sim_UnlockPin_0100
 * @tc.name     Unlock sim PIN lock
 * @tc.desc     Function test
 */
void UnlockPinTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin = Str8ToStr16("1234");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPin(SimTest::slotId_, pin, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockPin_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPinTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    const std::u16string pin = Str8ToStr16("1234");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPin(SimTest::slotId1_, pin, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockPin_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPinTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
#endif
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
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPuk(SimTest::slotId_, pin, puk, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockPuk_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPukTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    const std::u16string pin = Str8ToStr16("1234");
    const std::u16string puk = Str8ToStr16("42014264");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPuk(SimTest::slotId1_, pin, puk, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockPuk_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPukTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
#endif
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
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId_, newpin, oldpin, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_AlterPin_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPinTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    const std::u16string newpin = Str8ToStr16("1234");
    const std::u16string oldpin = Str8ToStr16("4321");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId1_, newpin, oldpin, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_AlterPin_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPinTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_UnlockPin2_0100
 * @tc.name     Unlock sim PIN2 lock
 * @tc.desc     Function test
 */
void UnlockPin2TestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin2 = Str8ToStr16("12345678");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPin2(SimTest::slotId_, pin2, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockPin2_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPin2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    const std::u16string pin2 = Str8ToStr16("12345678");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPin2(SimTest::slotId1_, pin2, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockPin2_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPin2TestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
#endif
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
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId_, pin2, puk2, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockPuk2_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPuk2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    const std::u16string pin2 = Str8ToStr16("12345678");
    const std::u16string puk2 = Str8ToStr16("42014264");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId1_, pin2, puk2, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockPuk2_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockPuk2TestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
#endif
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
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId_, newpin2, oldpin2, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_AlterPin2_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPin2TestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    const std::u16string newpin2 = Str8ToStr16("12345678");
    const std::u16string oldpin2 = Str8ToStr16("42014264");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockPuk2(SimTest::slotId1_, newpin2, oldpin2, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_AlterPin2_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(AlterPin2TestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_SetActiveSim_0100
 * @tc.name     Set current sim active state
 * @tc.desc     Function test
 */
void SetActiveSimTestFunc(CoreServiceTestHelper &helper)
{
    int enable = 1;
    bool result = SimTest::telephonyService_->SetActiveSim(SimTest::slotId_, enable);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_SetActiveSim_0100, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetActiveSimTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    int enable = 1;
    bool result = SimTest::telephonyService_->SetActiveSim(SimTest::slotId1_, enable);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_SetActiveSim_0200, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SetActiveSimTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    int enable = 1;
    bool result = SimTest::telephonyService_->SetActiveSim(SimTest::slotId_, enable);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_ReSetActiveSim_0100, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(ReSetActiveSimTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    int enable = 1;
    bool result = SimTest::telephonyService_->SetActiveSim(SimTest::slotId1_, enable);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_ReSetActiveSim_0200, Function | MediumTest | Level2)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(ReSetActiveSimTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
        int32_t result = SimTest::telephonyService_->GetMaxSimCount();
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "testresult";
        result = Str16ToStr8(SimTest::telephonyService_->GetOpKey(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "testresult");
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpKey_0200
 * @tc.name     Get opkey for current sim card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpKey_0200, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "testresult";
        result = Str16ToStr8(SimTest::telephonyService_->GetOpKey(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "testresult");
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "testresult";
        result = Str16ToStr8(SimTest::telephonyService_->GetOpKeyExt(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "testresult");
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpKeyExt_0200
 * @tc.name     Get opkey for current sim card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpKeyExt_0200, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "testresult";
        result = Str16ToStr8(SimTest::telephonyService_->GetOpKeyExt(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "testresult");
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "testresult";
        result = Str16ToStr8(SimTest::telephonyService_->GetOpName(SimTest::slotId_));
        EXPECT_STRNE(result.c_str(), "testresult");
    }
}

/**
 * @tc.number   Telephony_Sim_GetOpName_0200
 * @tc.name     Get opname for current sim card
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetOpName_0200, Function | MediumTest | Level1)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        std::string result = "testresult";
        result = Str16ToStr8(SimTest::telephonyService_->GetOpName(SimTest::slotId1_));
        EXPECT_STRNE(result.c_str(), "testresult");
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
    bool result = SimTest::telephonyService_->HasOperatorPrivileges(slotId);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_HasOperatorPrivileges_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_)) ||
        (SimTest::telephonyService_->GetSimState(SimTest::slotId_) !=
            static_cast<int32_t>(SimState::SIM_STATE_READY))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(HasOperatorPrivileges, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    bool result = SimTest::telephonyService_->HasOperatorPrivileges(slotId);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_HasOperatorPrivileges_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_)) ||
        (SimTest::telephonyService_->GetSimState(SimTest::slotId1_) !=
            static_cast<int32_t>(SimState::SIM_STATE_READY))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(HasOperatorPrivileges1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetCardType(SimTest::slotId_);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetCardType(SimTest::slotId1_);
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
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockSimLock(SimTest::slotId_, lockInfo, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockSimLock_0100, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockSimLockTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    PersoLockInfo lockInfo;
    lockInfo.lockType = PersoLockType::PN_PIN_LOCK;
    lockInfo.password = Str8ToStr16("1234");
    LockStatusResponse response = { 0 };
    bool result = SimTest::telephonyService_->UnlockSimLock(SimTest::slotId1_, lockInfo, response);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_UnlockSimLock_0200, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(UnlockSimLockTestFunc1, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
#endif
}

/**
 * @tc.number   Telephony_Sim_SimAuthentication_0100
 * @tc.name     Sim authentication
 * @tc.desc     Function test
 */
void SimAuthenticationTestFunc(CoreServiceTestHelper &helper)
{
    SimAuthenticationResponse response = { 0 };
    std::string aid = "aa";
    std::string authData = "1234";
    int32_t result = SimTest::telephonyService_->SimAuthentication(SimTest::slotId_, aid, authData, response);
    helper.SetBoolResult(result == 0);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_SimAuthentication_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
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
void SimAuthenticationTestFunc1(CoreServiceTestHelper &helper)
{
    SimAuthenticationResponse response = { 0 };
    std::string aid = "aa";
    std::string authData = "1234";
    int32_t result = SimTest::telephonyService_->SimAuthentication(SimTest::slotId1_, aid, authData, response);
    helper.SetBoolResult(result == 0);
    helper.NotifyAll();
}

HWTEST_F(SimTest, Telephony_Sim_SimAuthentication_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
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
 * @tc.number   Telephony_Sim_SetPrimarySlotId_0100
 * @tc.name     Set primary slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetPrimarySlotId_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        bool result = SimTest::telephonyService_->SetPrimarySlotId(SimTest::slotId_);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_SetPrimarySlotId_0200
 * @tc.name     Set primary slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetPrimarySlotId_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        bool result = SimTest::telephonyService_->SetPrimarySlotId(SimTest::slotId1_);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_GetPrimarySlotId_0100
 * @tc.name     Get primary slotId
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_GetPrimarySlotId_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        int32_t result = SimTest::telephonyService_->GetPrimarySlotId();
        EXPECT_GT(result, -1);
    }
}

void SendTerminalResponseCmdTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    std::string cmd = "send terminal response";
    bool result = SimTest::telephonyService_->SendTerminalResponseCmd(slotId, cmd);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

/**
 * @tc.number   Telephony_Sim_SendTerminalResponseCmd_0100
 * @tc.name     Send Terminal Response Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendTerminalResponseCmd_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendTerminalResponseCmdTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
}

void SendEnvelopeCmdTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    std::string cmd = "send envelope";
    bool result = SimTest::telephonyService_->SendEnvelopeCmd(slotId, cmd);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

/**
 * @tc.number   Telephony_Sim_SendEnvelopeCmd_0100
 * @tc.name     Send Envelope Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendEnvelopeCmd_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendEnvelopeCmdTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
        }
    }
}

void SendCallSetupRequestResultTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    bool accept = true;
    bool result = SimTest::telephonyService_->SendCallSetupRequestResult(slotId, accept);
    helper.SetBoolResult(result);
    helper.NotifyAll();
}

/**
 * @tc.number   Telephony_Sim_SendCallSetupRequestResult_0100
 * @tc.name     Send Call Setup Request Result Command
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SendCallSetupRequestResult_0100, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        CoreServiceTestHelper helper;
        if (!helper.Run(SendCallSetupRequestResultTestFunc, std::ref(helper))) {
            TELEPHONY_LOGI("Interface out of time");
            EXPECT_TRUE(true);
        } else {
            bool result = helper.GetBoolResult();
            EXPECT_TRUE(result);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string mailName = Str8ToStr16("张三");
        const std::u16string mailnumber = Str8ToStr16("13123456789");
        bool result = SimTest::telephonyService_->SetVoiceMailInfo(SimTest::slotId_, mailName, mailnumber);
        EXPECT_TRUE(result);
    }
}

/**
 * @tc.number   Telephony_Sim_SetVoiceMailInfo_0200
 * @tc.name     Set voice mail info
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_SetVoiceMailInfo_0200, Function | MediumTest | Level3)
{
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId1_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    } else {
        const std::u16string mailName = Str8ToStr16("张三");
        const std::u16string mailnumber = Str8ToStr16("13123456789");
        bool result = SimTest::telephonyService_->SetVoiceMailInfo(SimTest::slotId1_, mailName, mailnumber);
        EXPECT_TRUE(result);
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
    if (SimTest::telephonyService_ == nullptr || !(SimTest::telephonyService_->HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService Remote service is null");
        SimTest::telephonyService_ = GetProxy();
    }
    EXPECT_TRUE(true);
}

#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
