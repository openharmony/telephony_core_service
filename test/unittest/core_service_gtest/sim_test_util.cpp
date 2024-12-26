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
#include "sim_test_util.h"

#include "iservice_registry.h"
#include "sim_operator_brocast_test.h"
#include "system_ability_definition.h"
#include "tel_ril_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
sptr<ICoreService> SimTest::telephonyService_ = nullptr;
std::shared_ptr<SimOperatorBrocastTest> subscriber_;

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
    subscriber_ = std::make_shared<SimOperatorBrocastTest>(subscribeInfo);
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
    SimOperatorBrocastTest::telephonyService_ = telephonyService_;
}

void SimTest::TearDownTestCase()
{
    TELEPHONY_LOGI("----------Sim gtest end ------------");
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
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

bool SimTest::ParseOperatorConf(int32_t slotId)
{
    AccessToken token;
    if (SimTest::telephonyService_ == nullptr) {
        TELEPHONY_LOGE("ParseOperatorConf TelephonyTestService Remote service is null");
        return false;
    }
    const std::string rawJson = R"({ "string": "JSON中国", "long": 2147483699, "int": 88, "bool": true,
        "strA": ["street", "city", "country"], "longA": [ 2147483699, 2147483900, 2147499999],
        "intA": [1, 2, 3]})";
    cJSON *root = cJSON_Parse(rawJson.c_str());
    if (root == nullptr) {
        TELEPHONY_LOGE("SimTest::ParseOperatorConf root is error!\n");
        return false;
    }
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo,
        std::weak_ptr<ITelRilManager>(telRilManager), std::weak_ptr<SimStateManager>(simStateManager));
    OperatorConfigCache ofpc(std::weak_ptr<SimFileManager>(simFileManager), slotId);
    OperatorFileParser ofp;
    OperatorConfig poc;
    std::u16string result;
    CoreServiceClient::GetInstance().GetSimIccId(slotId, result);
    const std::string iccid = Str16ToStr8(result);
    std::string filename = ofpc.EncryptIccId(iccid) + ".json";
    if (slotId == SimTest::slotIdErr_) {
        filename = "";
        EXPECT_TRUE(true);
        return false;
    }
    ofp.WriteOperatorConfigJson(filename, root);
    cJSON_Delete(root);
    cJSON *ret = nullptr;
    ofp.ParseOperatorConfigFromFile(poc, filename, ret);
    CompareOperatorConfProcess(poc);
    root = nullptr;
    ret = nullptr;
    return true;
}

void SimTest::CompareOperatorConfProcess(OperatorConfig poc)
{
    const int64_t TEST_LONG_KEY_VALUE = 2147483699;
    const int64_t TEST_LONGA_KEY_THIRD_VALUE = 2147499999;
    const int32_t TEST_INT_KEY_VLAUE = 88;
    const int32_t TEST_INTA_KEY_SECOND_VLAUE = 2;
    const int32_t TEST_INDEX_ZERO = 0;
    const int32_t TEST_INDEX_ONE = 1;
    const int32_t TEST_INDEX_TWO = 2;
    if (poc.stringArrayValue.find("string") != poc.stringArrayValue.end()) {
        EXPECT_EQ("JSON中国", poc.stringValue["string"]);
    }
    if (poc.stringArrayValue.find("long") != poc.stringArrayValue.end()) {
        EXPECT_EQ(TEST_LONG_KEY_VALUE, poc.longValue["long"]);
    }
    if (poc.stringArrayValue.find("int") != poc.stringArrayValue.end()) {
        EXPECT_EQ(TEST_INT_KEY_VLAUE, poc.intValue["int"]);
    }
    if (poc.stringArrayValue.find("bool") != poc.stringArrayValue.end()) {
        EXPECT_EQ(true, poc.boolValue["bool"]);
    }
    if (poc.stringArrayValue.find("strA") != poc.stringArrayValue.end()) {
        EXPECT_EQ("street", poc.stringArrayValue["strA"][TEST_INDEX_ZERO]);
    }
    if (poc.intArrayValue.find("intA") != poc.intArrayValue.end()) {
        EXPECT_EQ(TEST_INTA_KEY_SECOND_VLAUE, poc.intArrayValue["intA"][TEST_INDEX_ONE]);
    }
    if (poc.longArrayValue.find("longA") != poc.longArrayValue.end()) {
        EXPECT_EQ(TEST_LONGA_KEY_THIRD_VALUE, poc.longArrayValue["longA"][TEST_INDEX_TWO]);
    }
}

void SimTest::QueryIccAdnDiallingNumbersTestFunc(CoreServiceTestHelper &helper)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    CoreServiceClient::GetInstance().QueryIccDiallingNumbers(
        SimTest::slotId_, DiallingNumbersInfo::SIM_ADN, diallingNumbers);
    helper.NotifyAll();
}
void SimTest::QueryIccAdnDiallingNumbersTestFunc1(CoreServiceTestHelper &helper)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    CoreServiceClient::GetInstance().QueryIccDiallingNumbers(
        SimTest::slotId1_, DiallingNumbersInfo::SIM_ADN, diallingNumbers);
    helper.NotifyAll();
}
void SimTest::QueryIccFdnDiallingNumbersTestFunc(CoreServiceTestHelper &helper)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    CoreServiceClient::GetInstance().QueryIccDiallingNumbers(
        SimTest::slotId_, DiallingNumbersInfo::SIM_FDN, diallingNumbers);
    helper.NotifyAll();
}
void SimTest::QueryIccFdnDiallingNumbersTestFunc1(CoreServiceTestHelper &helper)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers;
    CoreServiceClient::GetInstance().QueryIccDiallingNumbers(
        SimTest::slotId1_, DiallingNumbersInfo::SIM_FDN, diallingNumbers);
    helper.NotifyAll();
}
void SimTest::SetLockStateTestFunc(CoreServiceTestHelper &helper)
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
void SimTest::SetLockStateTestFunc1(CoreServiceTestHelper &helper)
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
void SimTest::SetFDNStateTestFunc(CoreServiceTestHelper &helper)
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
void SimTest::SetFDNStateTestFunc1(CoreServiceTestHelper &helper)
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
void SimTest::GetLockStateTestFunc(CoreServiceTestHelper &helper)
{
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType = LockType::PIN_LOCK;
    int32_t result = CoreServiceClient::GetInstance().GetLockState(SimTest::slotId_, lockType, lockState);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::GetLockStateTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType = LockType::PIN_LOCK;
    int32_t result = CoreServiceClient::GetInstance().GetLockState(SimTest::slotId1_, lockType, lockState);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::GetFDNStateTestFunc(CoreServiceTestHelper &helper)
{
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType = LockType::FDN_LOCK;
    int32_t result = CoreServiceClient::GetInstance().GetLockState(SimTest::slotId_, lockType, lockState);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::GetFDNStateTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    LockState lockState = LockState::LOCK_ERROR;
    LockType lockType = LockType::FDN_LOCK;
    int32_t result = CoreServiceClient::GetInstance().GetLockState(SimTest::slotId1_, lockType, lockState);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockPinTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin = Str8ToStr16("1234");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPin(SimTest::slotId_, pin, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockPinTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string pin = Str8ToStr16("1234");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPin(SimTest::slotId1_, pin, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockPukTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin = Str8ToStr16("1234");
    const std::u16string puk = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPuk(SimTest::slotId_, pin, puk, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockPukTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string pin = Str8ToStr16("1234");
    const std::u16string puk = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPuk(SimTest::slotId1_, pin, puk, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::AlterPinTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string newpin = Str8ToStr16("1234");
    const std::u16string oldpin = Str8ToStr16("4321");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().AlterPin(SimTest::slotId_, newpin, oldpin, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::AlterPinTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string newpin = Str8ToStr16("1234");
    const std::u16string oldpin = Str8ToStr16("4321");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().AlterPin(SimTest::slotId1_, newpin, oldpin, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockPin2TestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin2 = Str8ToStr16("12345678");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPin2(SimTest::slotId_, pin2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockPin2TestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string pin2 = Str8ToStr16("12345678");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPin2(SimTest::slotId1_, pin2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockPuk2TestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string pin2 = Str8ToStr16("12345678");
    const std::u16string puk2 = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPuk2(SimTest::slotId_, pin2, puk2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockPuk2TestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string pin2 = Str8ToStr16("12345678");
    const std::u16string puk2 = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockPuk2(SimTest::slotId1_, pin2, puk2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::AlterPin2TestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string newpin2 = Str8ToStr16("12345678");
    const std::u16string oldpin2 = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().AlterPin2(SimTest::slotId_, newpin2, oldpin2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::AlterPin2TestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    const std::u16string newpin2 = Str8ToStr16("12345678");
    const std::u16string oldpin2 = Str8ToStr16("42014264");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().AlterPin2(SimTest::slotId1_, newpin2, oldpin2, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SetActiveSimTestFunc(CoreServiceTestHelper &helper)
{
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSim(SimTest::slotId_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SetActiveSimTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSim(SimTest::slotId1_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::ReSetActiveSimTestFunc(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSim(SimTest::slotId_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::ReSetActiveSimTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSim(SimTest::slotId1_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SetActiveSimSatelliteTestFunc(CoreServiceTestHelper &helper)
{
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSimSatellite(SimTest::slotId_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SetActiveSimSatelliteTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSimSatellite(SimTest::slotId1_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::ReSetActiveSimSatelliteTestFunc(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSimSatellite(SimTest::slotId_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::ReSetActiveSimSatelliteTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int enable = 1;
    int32_t result = CoreServiceClient::GetInstance().SetActiveSimSatellite(SimTest::slotId1_, enable);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::HasOperatorPrivileges(CoreServiceTestHelper &helper)
{
    constexpr int32_t slotId = 0;
    bool hasOperatorPrivileges = false;
    int32_t result = CoreServiceClient::GetInstance().HasOperatorPrivileges(slotId, hasOperatorPrivileges);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::HasOperatorPrivileges1(CoreServiceTestHelper &helper)
{
    constexpr int32_t slotId = 1;
    bool hasOperatorPrivileges = false;
    int32_t result = CoreServiceClient::GetInstance().HasOperatorPrivileges(slotId, hasOperatorPrivileges);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockSimLockTestFunc(CoreServiceTestHelper &helper)
{
    PersoLockInfo lockInfo;
    lockInfo.lockType = PersoLockType::PN_PIN_LOCK;
    lockInfo.password = Str8ToStr16("1234");
    LockStatusResponse response = { UNLOCK_FAIL, TELEPHONY_ERROR };
    int32_t result = CoreServiceClient::GetInstance().UnlockSimLock(SimTest::slotId_, lockInfo, response);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::UnlockSimLockTestFunc1(CoreServiceTestHelper &helper)
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
void SimTest::SimAuthenticationTestFunc(CoreServiceTestHelper &helper)
{
    SimAuthenticationResponse response = { 0 };
    AuthType authType = AuthType::SIM_AUTH_EAP_SIM_TYPE;
    std::string authData = "1234";
    int32_t result = CoreServiceClient::GetInstance().SimAuthentication(SimTest::slotId_, authType, authData, response);
    helper.SetBoolResult(result == 0);
    helper.NotifyAll();
}
void SimTest::SimAuthenticationTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    SimAuthenticationResponse response = { 0 };
    AuthType authType = AuthType::SIM_AUTH_EAP_SIM_TYPE;
    std::string authData = "1234";
    int32_t result =
        CoreServiceClient::GetInstance().SimAuthentication(SimTest::slotId1_, authType, authData, response);
    helper.SetBoolResult(result == 0);
    helper.NotifyAll();
}
void SimTest::SimAuthenticationTestFunc2(CoreServiceTestHelper &helper)
{
    SimAuthenticationResponse response = { 0 };
    AuthType authType = AuthType::SIM_AUTH_EAP_AKA_TYPE;
    std::string authData = "1234";
    int32_t result = CoreServiceClient::GetInstance().SimAuthentication(SimTest::slotId_, authType, authData, response);
    helper.SetBoolResult(result == 0);
    helper.NotifyAll();
}
void SimTest::SimAuthenticationTestFunc3(CoreServiceTestHelper &helper)
{
    SimAuthenticationResponse response = { 0 };
    AuthType authType = static_cast<AuthType>(0);
    std::string authData = "1234";
    int32_t result = CoreServiceClient::GetInstance().SimAuthentication(SimTest::slotId_, authType, authData, response);
    helper.SetBoolResult(result == 0);
    helper.NotifyAll();
}
void SimTest::SendTerminalResponseCmdTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    std::string cmd = "send terminal response";
    int32_t result = CoreServiceClient::GetInstance().SendTerminalResponseCmd(slotId, cmd);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SendTerminalResponseCmdTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int32_t slotId = 1;
    std::string cmd = "send terminal response";
    int32_t result = CoreServiceClient::GetInstance().SendTerminalResponseCmd(slotId, cmd);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SendEnvelopeCmdTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    std::string cmd = "send envelope";
    int32_t result = CoreServiceClient::GetInstance().SendEnvelopeCmd(slotId, cmd);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SendEnvelopeCmdTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int32_t slotId = 1;
    std::string cmd = "send envelope";
    int32_t result = CoreServiceClient::GetInstance().SendEnvelopeCmd(slotId, cmd);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SendCallSetupRequestResultTestFunc(CoreServiceTestHelper &helper)
{
    int32_t slotId = 0;
    bool accept = true;
    int32_t result = CoreServiceClient::GetInstance().SendCallSetupRequestResult(slotId, accept);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SendCallSetupRequestResultTestFunc1(CoreServiceTestHelper &helper)
{
    AccessToken token;
    int32_t slotId = 1;
    bool accept = true;
    int32_t result = CoreServiceClient::GetInstance().SendCallSetupRequestResult(slotId, accept);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SetVoiceMailInfoTestFunc(CoreServiceTestHelper &helper)
{
    const std::u16string mailName = Str8ToStr16("张三");
    const std::u16string mailnumber = Str8ToStr16("13123456789");
    int32_t result = CoreServiceClient::GetInstance().SetVoiceMailInfo(SimTest::slotId_, mailName, mailnumber);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
void SimTest::SetVoiceMailInfoTestFunc1(CoreServiceTestHelper &helper)
{
    const std::u16string mailName = Str8ToStr16("张三");
    const std::u16string mailnumber = Str8ToStr16("13123456789");
    int32_t result = CoreServiceClient::GetInstance().SetVoiceMailInfo(SimTest::slotId1_, mailName, mailnumber);
    helper.SetIntResult(result);
    helper.NotifyAll();
}
std::shared_ptr<OperatorConfigCache> SimTest::CreateOperatorConfigCache(int32_t slotId)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo,
                                                           std::weak_ptr<ITelRilManager>(telRilManager),
                                                           std::weak_ptr<SimStateManager>(simStateManager));
    return std::make_shared<OperatorConfigCache>(std::weak_ptr<SimFileManager>(simFileManager), slotId);
}
} // namespace Telephony
} // namespace OHOS
