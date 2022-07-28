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

#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>

#include "common_event_test.h"
#include "core_service_client.h"
#include "common_event_manager.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "want.h"
#include "sim_account_manager.h"
#include "sim_state_type.h"

using namespace std;
using namespace OHOS::Telephony;
namespace OHOS {
namespace Telephony {
using CmdProcessFunc = bool (*)();
static sptr<ICoreService> g_telephonyService = nullptr;
std::unique_ptr<Telephony::SimAccountManager> g_simAccountManager = nullptr;

const int32_t SLOT_ID = DEFAULT_SIM_SLOT_ID;
const int32_t DEFAULT_VALUE = 0;
const int32_t FIX_DAILING = 2;
static bool g_simDiallingNumbersRead = false;

enum class InputCmd {
    INPUT_HASSIMCARD = 0,
    INPUT_GETSIMSTATE = 1,
    INPUT_GETISOCOUNTRYCODE = 2,
    INPUT_GETSPN = 3,
    INPUT_GETICCID = 4,
    INPUT_GETIMSI = 5,
    INPUT_ISSIMACTIVE = 6,
    INPUT_GETSIMOPERATOR = 7,
    INPUT_GETGID1 = 8,
    INPUT_GETGID2 = 9,
    INPUT_GETSIMSUB = 10,
    INPUT_SETDEFAULTCALL = 11,
    INPUT_GETDEFAULTCALL = 12,
    INPUT_GETSIMEONS = 13,
    INPUT_UNLOCK_PIN = 21,
    INPUT_UNLOCK_PUK = 22,
    INPUT_ALTER_PIN = 23,
    INPUT_CHECK_LOCK = 24,
    INPUT_ENABLE_LOCK = 25,
    INPUT_REFRESHSIMSTATE = 26,
    INPUT_UNLOCK_PIN2 = 31,
    INPUT_UNLOCK_PUK2 = 32,
    INPUT_ALTER_PIN2 = 33,
    INPUT_SET_ACTIVE_SIM = 34,
    INPUT_SETSHOWNUMBER = 42,
    INPUT_GETSHOWNUMBER = 43,
    INPUT_SETSHOWNAME = 44,
    INPUT_GETSHOWNAME = 45,
    INPUT_GETACTIVEACCOUNTLIST = 46,
    INPUT_GETOPERATORCONFIG = 47,
    INPUT_GET_VOICEMAIL_NAME = 49,
    INPUT_GET_VOICEMAIL_NUMBER = 50,
    INPUT_DIALLING_NUMBERS_GET = 51,
    INPUT_DIALLING_NUMBERS_INSERT = 52,
    INPUT_DIALLING_NUMBERS_DELETE = 53,
    INPUT_DIALLING_NUMBERS_UPDATE = 54,
    INPUT_SET_VOICEMAIL = 55,
    INPUT_GET_MAX_SIM_COUNT = 56,
    INPUT_STK_CMD_FROM_APP = 57,
    INPUT_STK_TERMINAL_RESPONSE = 58,
    INPUT_STK_CALL_SETUP_REQUEST_RESULT_FROM_APP = 59,
    INPUT_GET_OPKEY = 60,
    INPUT_GET_PHONENUMBER = 61,
    INPUT_GET_SIM_TELENUMBER_IDENTIFIER = 62,
    INPUT_GET_CARD_TYPE = 63,
    INPUT_UNLOCK_SIMLOCK = 64,
    INPUT_SET_PRIMARY_SLOTID = 65,
    INPUT_GET_PRIMARY_SLOTID = 66,
    INPUT_GET_OPNAME = 67,
    INPUT_GET_OPKEY_EXT = 68,
    INPUT_HAS_OPERATOR_PRIVILEGES = 70,
    INPUT_QUIT = 100,
};

enum class PinWordSize {
    PIN_MIN_SIZE = 4,
    PIN_MAX_SIZE = 8,
};

enum class PinLockEnable {
    PIN_LOCK_RESET = 0,
    PIN_LOCK_SET,
};

enum class LockTypeTest {
    PIN_LOCK_TYPE = 1,
    FDN_LOCK_TTPE,
};

enum class PersoLockTypeTest {
    SIM_PN_PIN_TYPE, // Network Personalization (refer 3GPP TS 22.022 [33])
    SIM_PN_PUK_TYPE,
    SIM_PU_PIN_TYPE, // network sUbset Personalization (refer 3GPP TS 22.022 [33])
    SIM_PU_PUK_TYPE,
    SIM_PP_PIN_TYPE, // service supplier Personalization (refer 3GPP TS 22.022 [33])
    SIM_PP_PUK_TYPE,
    SIM_PC_PIN_TYPE, // Corporate Personalization (refer 3GPP TS 22.022 [33])
    SIM_PC_PUK_TYPE,
    SIM_SIM_PIN_TYPE, // SIM/USIM personalisation (refer 3GPP TS 22.022 [33])
    SIM_SIM_PUK_TYPE,
};

static std::map<InputCmd, CmdProcessFunc> g_funcMap;

static sptr<ICoreService> GetProxy()
{
    std::cout << "TelephonyTestService GetProxy ... " << std::endl;
    sptr<ISystemAbilityManager> systemAbilityMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        std::cout << "TelephonyTestService Get ISystemAbilityManager failed ... " << std::endl;
        return nullptr;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote) {
        sptr<ICoreService> telephonyService = iface_cast<ICoreService>(remote);
        std::cout << "TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID success ... " << std::endl;
        return telephonyService;
    } else {
        std::cout << "TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail ... " << std::endl;
        return nullptr;
    }
}

static bool Among(int mid, PinWordSize min, PinWordSize max)
{
    int minValue = static_cast<int>(min);
    int maxValue = static_cast<int>(max);
    return ((mid >= minValue) && (mid <= maxValue));
}

static bool AmongLock(int mid, PinLockEnable min, PinLockEnable max)
{
    int minValue = static_cast<int>(min);
    int maxValue = static_cast<int>(max);
    return ((mid >= minValue) && (mid <= maxValue));
}

static bool TestHasSimCard()
{
    bool result = g_telephonyService->HasSimCard(SLOT_ID);
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote HasSimCard result [" << result << "] " << expect << std::endl;
    return true;
}

static bool AmongLockType(int mid, LockTypeTest min, LockTypeTest max)
{
    int minValue = static_cast<int>(min);
    int maxValue = static_cast<int>(max);
    return ((mid >= minValue) && (mid <= maxValue));
}

static bool AmongPersoLockType(int mid, PersoLockTypeTest min, PersoLockTypeTest max)
{
    int minValue = static_cast<int>(min);
    int maxValue = static_cast<int>(max);
    return ((mid >= minValue) && (mid <= maxValue));
}

static bool TestGetSimState()
{
    const int simReady = 4;
    int32_t result = static_cast<int32_t>(g_telephonyService->GetSimState(SLOT_ID));
    string expect = (result == simReady) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetSimState result [" << result << "] " << expect << std::endl;
    return true;
}

static bool TestGetCardType()
{
    int32_t result = static_cast<int32_t>(g_telephonyService->GetCardType(SLOT_ID));
    std::cout << "TelephonyTestService Remote GetCardType result [" << result << "] " << std::endl;
    return true;
}

static bool TestSetPrimarySlotId()
{
    static int32_t testDefaultPrimarySlot = SLOT_ID;
    std::cout << "please input Primary Slot Id" << std::endl;
    std::cin >> testDefaultPrimarySlot;
    bool result = g_telephonyService->SetPrimarySlotId(testDefaultPrimarySlot);
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote SetPrimarySlotId result [" << result << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetPrimarySlotId()
{
    int32_t result = g_telephonyService->GetPrimarySlotId();
    string expect = (result >= INVALID_VALUE) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetPrimarySlotId result [" << result << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetISOCountryCodeForSim()
{
    std::u16string result = g_telephonyService->GetISOCountryCodeForSim(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetISOCountryCodeForSim result [" << str << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetSimSpn()
{
    std::u16string result  = u"test";
    result = g_telephonyService->GetSimSpn(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = strcmp(str.c_str(), "test") ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetSimSpn result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimIccId()
{
    int32_t slotId = 0;
    std::cout << "please input soltid:"<<std::endl;
    std::cin >> slotId;
    std::u16string result = g_telephonyService->GetSimIccId(slotId);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimIccId result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimEons()
{
    int32_t slotId = 0;
    std::cout << "please input soltId:"<< std::endl;
    std::cin >> slotId;
    std::string plmn = "46001";
    std::cout << "please input plmn:"<< std::endl;
    std::cin >> plmn;
    int32_t lac = 1;
    std::cout << "please input lac:"<< std::endl;
    std::cin >> lac;
    bool longNameRequired = true;
    std::cout << "please input longNameRequired:"<< std::endl;
    std::cin >> longNameRequired;
    std::u16string result = g_telephonyService->GetSimEons(slotId, plmn, lac, longNameRequired);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimEons result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimOperatorNumeric()
{
    std::u16string result = g_telephonyService->GetSimOperatorNumeric(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimOperatorNumeric result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetIMSI()
{
    std::u16string result = g_telephonyService->GetIMSI(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetIMSI result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestIsSimActive()
{
    std::cout << "please input slot Id" << std::endl;
    int testSim = DEFAULT_VALUE;
    std::cin >> testSim;
    bool result = g_telephonyService->IsSimActive(testSim);
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote IsSimActive result [" << result << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimGid1()
{
    std::u16string result = g_telephonyService->GetSimGid1(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimGid1 result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimGid2()
{
    std::u16string result = g_telephonyService->GetSimGid2(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimGid2 result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimTelephoneNumber()
{
    std::u16string result = g_telephonyService->GetSimTelephoneNumber(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimTelephoneNumber result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimTeleNumberIdentifier()
{
    std::u16string result = g_telephonyService->GetSimTeleNumberIdentifier(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote getSimTeleNumberIdentifier result [" << str << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetVoiceMailIdentifier()
{
    std::u16string result = g_telephonyService->GetVoiceMailIdentifier(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetVoiceMailIdentifier result [" << str << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetVoiceMailNumber()
{
    std::u16string result = g_telephonyService->GetVoiceMailNumber(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetVoiceMailNumber result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestQueryIccDiallingNumbers()
{
    int testType = 0;
    int type = DiallingNumbersInfo::SIM_ADN;
    std::cout << "please select type: 1.public dialling numbers 2.fix dialing numbers" << std::endl;
    std::cin >> testType;
    if (testType == FIX_DAILING) {
        type = DiallingNumbersInfo::SIM_FDN;
    }
    std::cout << "TestQueryIccDiallingNumbers loading " << testType << std::endl;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
        g_telephonyService->QueryIccDiallingNumbers(SLOT_ID, type);
    g_simDiallingNumbersRead = true;
    if (diallingNumbers.empty()) {
        std::cout << "no dialling numbers in sim" << std::endl;
        return true;
    }
    int id = 0;
    for (std::vector<std::shared_ptr<DiallingNumbersInfo>>::iterator it = diallingNumbers.begin();
         it != diallingNumbers.end(); it++) {
        std::shared_ptr<DiallingNumbersInfo> item = *it;
        std::string name = Str16ToStr8(item->GetName());
        std::string number = Str16ToStr8(item->GetNumber());
        int index = item->GetIndex();
        int diallingNumbertype = item->GetFileId();
        std::cout << ++id << "  " << index << " " << name << "  " << number << "  " << diallingNumbertype
                  << std::endl;
    }
    return true;
}

static bool TestAddIccDiallingNumbers()
{
    if (!g_simDiallingNumbersRead) {
        std::cout << "you need run QueryIccDiallingNumbers once at least" << std::endl;
        return true;
    }
    std::string name = "";
    std::string number = "";
    std::string pin2 = "";
    int type = 0;
    std::cout << "input name:" << std::endl;
    std::cin >> name;
    std::cout << "input number:" << std::endl;
    std::cin >> number;
    std::cout << "please select type: 1.public dialling numbers 2.fix dialing numbers" << std::endl;
    std::cin >> type;
    if (type == FIX_DAILING) {
        type = DiallingNumbersInfo::SIM_FDN;
        std::cout << "input pin2:" << std::endl;
        std::cin >> pin2;
    } else {
        type = DiallingNumbersInfo::SIM_ADN;
    }

    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>(type, 0);
    diallingNumber->name_ = Str8ToStr16(name);
    diallingNumber->number_ = Str8ToStr16(number);
    diallingNumber->pin2_ = Str8ToStr16(pin2);
    std::cout << "start insert " << Str16ToStr8(diallingNumber->name_) << " "
              << Str16ToStr8(diallingNumber->number_) << std::endl;
    bool result = g_telephonyService->AddIccDiallingNumbers(SLOT_ID, type, diallingNumber);
    std::cout << "TelephonyTestService Remote TestAddIccDiallingNumbers result [" << result << "] " << std::endl;
    return true;
}

static bool TestDelIccDiallingNumbers()
{
    if (!g_simDiallingNumbersRead) {
        std::cout << "you need run QueryIccDiallingNumbers once at least" << std::endl;
        return true;
    }
    int type = 0;
    int index = 0;
    std::string pin2 = "";
    std::cout << "select id:" << std::endl;
    std::cin >> index;
    std::cout << "please select type: 1.public dialling numbers 2.fix dialing numbers" << std::endl;
    std::cin >> type;
    if (type == FIX_DAILING) {
        type = DiallingNumbersInfo::SIM_FDN;
        std::cout << "input pin2:" << std::endl;
        std::cin >> pin2;
    } else {
        type = DiallingNumbersInfo::SIM_ADN;
    }

    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>(type, 0);
    diallingNumber->index_ = index;
    diallingNumber->pin2_ = Str8ToStr16(pin2);
    bool result = g_telephonyService->DelIccDiallingNumbers(SLOT_ID, type, diallingNumber);
    std::cout << "TelephonyTestService Remote DelIccDiallingNumbers result [" << result << "] " << std::endl;
    return true;
}

static bool TestUpdateIccDiallingNumbers()
{
    if (!g_simDiallingNumbersRead) {
        std::cout << "you need run QueryIccDiallingNumbers once at least" << std::endl;
        return true;
    }
    std::string name = "";
    std::string number = "";
    std::string pin2 = "";
    int type = 0;
    int index = 0;
    std::cout << "select id:" << std::endl;
    std::cin >> index;
    std::cout << "input name:" << std::endl;
    std::cin >> name;
    std::cout << "input number:" << std::endl;
    std::cin >> number;
    std::cout << "please select type: 1.public dialling numbers 2.fix dialing numbers" << std::endl;
    std::cin >> type;
    if (type == FIX_DAILING) {
        type = DiallingNumbersInfo::SIM_FDN;
        std::cout << "input pin2:" << std::endl;
        std::cin >> pin2;
    } else {
        type = DiallingNumbersInfo::SIM_ADN;
    }

    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>(type, 0);
    diallingNumber->name_ = Str8ToStr16(name);
    diallingNumber->number_ = Str8ToStr16(number);
    diallingNumber->pin2_ = Str8ToStr16(pin2);
    diallingNumber->index_ = index;
    bool result = g_telephonyService->UpdateIccDiallingNumbers(SLOT_ID, type, diallingNumber);
    std::cout << "TelephonyTestService Remote UpdateIccDiallingNumbers result [" << result << "] " << std::endl;
    return true;
}

static bool TestSetVoiceMailInfo()
{
    std::string name = "";
    std::string number = "";
    std::cout << "input name:" << std::endl;
    std::cin >> name;
    std::cout << "input number:" << std::endl;
    std::cin >> number;
    std::u16string mailName = Str8ToStr16(name);
    std::u16string mailNumber = Str8ToStr16(number);
    bool result = g_telephonyService->SetVoiceMailInfo(SLOT_ID, mailName, mailNumber);
    std::cout << "TelephonyTestService Remote SetVoiceMailInfo result [" << result << "] " << std::endl;
    return true;
}

static bool TestGetSimSubscriptionInfo()
{
    const std::u16string defaultName = u"testShowName";
    const std::u16string defaultNumber = u"testShowNumber";
    std::cout << "please input Sub Id" << std::endl;
    int testSim = DEFAULT_VALUE;
    std::cin >> testSim;
    IccAccountInfo iccAccountInfo;
    iccAccountInfo.Init(SLOT_ID, SLOT_ID);
    iccAccountInfo.showName = defaultName;
    iccAccountInfo.showNumber = defaultNumber;
    bool result = g_telephonyService->GetSimAccountInfo(testSim, iccAccountInfo);
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetSimAccountInfo result [" << result << "] " << expect << std::endl
              << "receive slotIndex = [" << iccAccountInfo.slotIndex << "]" << std::endl
              << "receive showName = [" << Str16ToStr8(iccAccountInfo.showName) << "]" << std::endl
              << "receive showNumber = [" << Str16ToStr8(iccAccountInfo.showNumber) << "]" << std::endl
              << "receive simId = [" << iccAccountInfo.simId << "]" << std::endl
              << "receive isEsim = [" << iccAccountInfo.isEsim << "]" << std::endl
              << "receive isActive = [" << iccAccountInfo.isActive << "]" << std::endl
              << "receive iccId = [" << Str16ToStr8(iccAccountInfo.iccId) << "]" << std::endl;
    return true;
}

static bool TestSetDefaultVoiceSlotId()
{
    static int32_t testDefaultVoiceSlot = SLOT_ID;
    std::cout << "please input Default Voice Slot Id" << std::endl;
    std::cin >> testDefaultVoiceSlot;
    bool result = g_telephonyService->SetDefaultVoiceSlotId(testDefaultVoiceSlot);
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote SetDefaultVoiceSlotId result [" << result << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetDefaultVoiceSlotId()
{
    int32_t result = g_telephonyService->GetDefaultVoiceSlotId();
    string expect = (result >= INVALID_VALUE) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetDefaultVoiceSlotId result [" << result << "] " << expect
              << std::endl;
    return true;
}

static bool TestSetShowNumber()
{
    int32_t slot;
    std::cout << "please input Slot Id" << std::endl;
    std::cin >> slot;
    std::string showNumber;
    std::cout << "please input showNumber" << std::endl;
    std::cin >> showNumber;
    bool result = g_telephonyService->SetShowNumber(slot, Str8ToStr16(showNumber));
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote SetShowNumber result [" << result << "] " << expect << std::endl;
    return true;
}

static bool TestSetShowName()
{
    int32_t slot;
    std::cout << "please input Slot Id" << std::endl;
    std::cin >> slot;
    std::string showName;
    std::cout << "please input showName" << std::endl;
    std::cin >> showName;
    bool result = g_telephonyService->SetShowName(slot, Str8ToStr16(showName));
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote SetShowName result [" << result << "] " << expect << std::endl;
    return true;
}

static bool TestGetShowNumber()
{
    int32_t slot;
    std::cout << "please input Slot Id" << std::endl;
    std::cin >> slot;
    std::u16string result = g_telephonyService->GetShowNumber(slot);
    string expect = (!result.empty()) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote SetShowNumber result [" << Str16ToStr8(result) << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetShowName()
{
    int32_t slot;
    std::cout << "please input Slot Id" << std::endl;
    std::cin >> slot;
    std::u16string result = g_telephonyService->GetShowName(slot);
    string expect = (!result.empty()) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetShowName result [" << Str16ToStr8(result) << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetActiveSimAccountInfoList()
{
    std::vector<IccAccountInfo> iccAccountInfoList;
    bool result = g_telephonyService->GetActiveSimAccountInfoList(iccAccountInfoList);
    string expect = result ? "success" : "fail";
    int i = 1;
    std::cout << "TelephonyTestService Remote GetActiveSimAccountInfoList result [" << result << "] " << expect
              << std::endl;
    for (IccAccountInfo iccAccountInfo : iccAccountInfoList) {
        std::cout << i << ". receive slotIndex = [" << iccAccountInfo.slotIndex << "]" << std::endl
                  << i << ". receive showName = [" << Str16ToStr8(iccAccountInfo.showName) << "]" << std::endl
                  << i << ". receive showNumber = [" << Str16ToStr8(iccAccountInfo.showNumber) << "]" << std::endl
                  << i << ". receive simId = [" << iccAccountInfo.simId << "]" << std::endl
                  << i << ". receive isEsim = [" << iccAccountInfo.isEsim << "]" << std::endl
                  << i << ". receive isActive = [" << iccAccountInfo.isActive << "]" << std::endl
                  << i << ". receive iccId = [" << Str16ToStr8(iccAccountInfo.iccId) << "]" << std::endl;
        i++;
    }
    return true;
}

static bool TestGetOperatorConfig()
{
    OperatorConfig oc;
    bool result = g_telephonyService->GetOperatorConfigs(DEFAULT_SIM_SLOT_ID, oc);
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetOperatorConfigs result [" << result << "] " << expect << std::endl;
    std::map<std::u16string, std::u16string>::iterator valueIt = oc.configValue.begin();
    while (valueIt != oc.configValue.end()) {
        std::cout << "configValue key = " << Str16ToStr8(valueIt->first).c_str() << std::endl
                  << "configValue value = " << Str16ToStr8(valueIt->second).c_str() << std::endl;
        valueIt++;
    }
    return true;
}

static bool TestUnlockPin()
{
    LockStatusResponse response = {0};
    std::string pin = " ";
    int size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Unlock pin start, Please input pin \n";
        std::cin >> pin;
        size = pin.size();
    }
    std::cout << "Unlock pin: pin = " << pin << endl;
    g_telephonyService->UnlockPin(SLOT_ID, Str8ToStr16(pin.c_str()), response);
    std::cout << "Unlock pin complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestUnlockPuk()
{
    LockStatusResponse response = {0};
    std::string newPin = " ";
    std::string puk = " ";
    int size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Unlock puk start, Please input new pin \n";
        std::cin >> newPin;
        size = newPin.size();
    }
    size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Unlock puk start, Please input puk \n";
        std::cin >> puk;
        size = puk.size();
    }
    std::cout << "Unlock puk: newPin = " << newPin << "  puk = " << puk << endl;
    g_telephonyService->UnlockPuk(SLOT_ID, Str8ToStr16(newPin.c_str()), Str8ToStr16(puk.c_str()), response);
    std::cout << "Unlock puk complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestAlterPin()
{
    LockStatusResponse response = {0};
    std::string oldPin = " ";
    std::string newPin = " ";
    int size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Alter pin start, Please input old pin \n";
        std::cin >> oldPin;
        size = oldPin.size();
    }
    size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Alter pin start, Please input new pin \n";
        std::cin >> newPin;
        size = newPin.size();
    }
    std::cout << "Unlock pin: oldPin = " << oldPin << "  newPin = " << newPin << endl;
    g_telephonyService->AlterPin(SLOT_ID, Str8ToStr16(newPin.c_str()), Str8ToStr16(oldPin.c_str()), response);
    std::cout << "Alter pin complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestUnlockPin2()
{
    LockStatusResponse response = {0};
    std::string pin2 = " ";
    int size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Unlock pin2 start, Please input pin2 \n";
        std::cin >> pin2;
        size = pin2.size();
    }
    std::cout << "Unlock pin2: pin2 = " << pin2 << endl;
    g_telephonyService->UnlockPin2(SLOT_ID, Str8ToStr16(pin2.c_str()), response);
    std::cout << "Unlock pin2 complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestUnlockPuk2()
{
    LockStatusResponse response = {0};
    std::string newPin2 = " ";
    std::string puk2 = " ";
    int size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Unlock puk2 start, Please input new pin2 \n";
        std::cin >> newPin2;
        size = newPin2.size();
    }
    size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Unlock puk2 start, Please input puk2 \n";
        std::cin >> puk2;
        size = puk2.size();
    }
    std::cout << "Unlock puk2: newPin2 = " << newPin2 << "  puk2 = " << puk2 << endl;
    g_telephonyService->UnlockPuk2(SLOT_ID, Str8ToStr16(newPin2.c_str()), Str8ToStr16(puk2.c_str()), response);
    std::cout << "Unlock puk complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestAlterPin2()
{
    LockStatusResponse response = {0};
    std::string oldPin2 = " ";
    std::string newPin2 = " ";
    int size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Alter pin2 start, Please input old pin2 \n";
        std::cin >> oldPin2;
        size = oldPin2.size();
    }
    size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Alter pin2 start, Please input new pin2 \n";
        std::cin >> newPin2;
        size = newPin2.size();
    }
    std::cout << "Unlock pin2: oldPin2 = " << oldPin2 << "  newPin2 = " << newPin2 << endl;
    g_telephonyService->AlterPin2(SLOT_ID, Str8ToStr16(newPin2.c_str()), Str8ToStr16(oldPin2.c_str()), response);
    std::cout << "Alter pin2 complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestSetLockState()
{
    LockStatusResponse response = {0};
    int32_t testType = -1;
    std::string testPin = " ";
    int32_t mode = -1;
    int32_t size = 0;
    while (!AmongLockType(testType, LockTypeTest::PIN_LOCK_TYPE, LockTypeTest::FDN_LOCK_TTPE)) {
        std::cout << "\n Set lock switch, Please input lock type (1. PIN_LOCK  2. FDN_LOCK)\n";
        std::cin >> testType;
    }
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        if (static_cast<int32_t>(LockTypeTest::PIN_LOCK_TYPE) == testType) {
            std::cout << "\n Set pin lock switch, Please input pin \n";
        } else {
            std::cout << "\n Set pin lock switch, Please input pin2 \n";
        }
        std::cin >> testPin;
        size = testPin.size();
    }
    size = 0;
    while (!AmongLock(mode, PinLockEnable::PIN_LOCK_RESET, PinLockEnable::PIN_LOCK_SET)) {
        std::cout << "\n Set lock switch, Please input switch (0. RESET  1. SET)\n";
        std::cin >> mode;
    }
    std::cout << "SetLockState: pin = " << testPin << "  mode = " << mode << endl;
    LockInfo testInfo;
    testInfo.password = Str8ToStr16(testPin);
    testInfo.lockState = static_cast<LockState>(mode);
    testInfo.lockType = static_cast<LockType>(testType);
    g_telephonyService->SetLockState(SLOT_ID, testInfo, response);
    std::cout << "Set Lock complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestGetLockState()
{
    int32_t testType = -1;
    while (!AmongLockType(testType, LockTypeTest::PIN_LOCK_TYPE, LockTypeTest::FDN_LOCK_TTPE)) {
        std::cout << "\n Set lock switch, Please input lock type (1. PIN_LOCK  2. FDN_LOCK)\n";
        std::cin >> testType;
    }
    LockType lockType = static_cast<LockType>(testType);
    int32_t ret = g_telephonyService->GetLockState(SLOT_ID, lockType);
    std::cout << "TestGetLockState()" << ret << endl;
    return true;
}

static bool TestRefreshSimState()
{
    int32_t ret = g_telephonyService->RefreshSimState(SLOT_ID);
    std::cout << "TestRefreshSimState()" << ret << endl;
    return true;
}

static bool TestSetActiveSim()
{
    int32_t enable = ACTIVE;
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::cout << "please input sim Id" << endl;
    std::cin >> slotId;
    std::cout << "\n Set active sim enable, Please input enable \n";
    std::cin >> enable;

    bool result = g_telephonyService->SetActiveSim(slotId, enable);
    std::cout << "TestSetActiveSim(), result = " << result << endl;
    return true;
}

static bool TestGetMaxSimCount()
{
    int32_t result = g_telephonyService->GetMaxSimCount();
    string expect = (result != INVALID_VALUE) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetMaxSimCount result [" << result << "] " << expect << std::endl;
    return true;
}

static bool TestGetOpKey()
{
    std::u16string result = g_telephonyService->GetOpKey(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TestGetOpKey Remote GetOpKey result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetOpName()
{
    std::u16string result = g_telephonyService->GetOpName(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TestGetOpName Remote GetOpName result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetOpKeyExt()
{
    std::u16string result = g_telephonyService->GetOpKeyExt(SLOT_ID);
    std::string str = Str16ToStr8(result);
    std::cout << "TestGetOpKeyExt Remote GetOpKeyExt result [" << str << "] " << std::endl;
    return true;
}

static int32_t GetSimLockType()
{
    int32_t testType = -1;
    while (!AmongPersoLockType(testType, PersoLockTypeTest::SIM_PN_PIN_TYPE,
        PersoLockTypeTest::SIM_SIM_PUK_TYPE)) {
        std::cout << "\n Set lock switch, Please input lock type number(\n"
                     " 0. Network Personalization PIN\n"
                     " 1. Network Personalization PUK\n"
                     " 2. Network sub Personalization PIN\n"
                     " 3. Network sub Personalization PUK\n"
                     " 4. service supplier Personalization PIN\n"
                     " 5. service supplier Personalization PUK\n"
                     " 6. Corporate Personalization PIN\n"
                     " 7. Corporate Personalization PUK\n"
                     " 8. SIM/USIM Personalization PIN\n"
                     " 9. SIM/USIM Personalization PUK)\n";
        std::cin >> testType;
    }
    return testType;
}

static std::string GetSimLockPassword(int32_t testType)
{
    std::string password = "";
    int size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        PersoLockTypeTest lockType = static_cast<PersoLockTypeTest>(testType);
        switch (lockType) {
            case PersoLockTypeTest::SIM_PN_PIN_TYPE:
                std::cout << "\n select 0. Please input Network Personalization PIN \n";
                break;
            case PersoLockTypeTest::SIM_PN_PUK_TYPE:
                std::cout << "\n select 1. Please input Network Personalization PUK \n";
                break;
            case PersoLockTypeTest::SIM_PU_PIN_TYPE:
                std::cout << "\n select 2. Please input Network sub Personalization PIN \n";
                break;
            case PersoLockTypeTest::SIM_PU_PUK_TYPE:
                std::cout << "\n select 3. Please input Network sub Personalization PUK \n";
                break;
            case PersoLockTypeTest::SIM_PP_PIN_TYPE:
                std::cout << "\n select 4. Please input service supplier Personalization PIN \n";
                break;
            case PersoLockTypeTest::SIM_PP_PUK_TYPE:
                std::cout << "\n select 5. Please input service supplier Personalization PUK \n";
                break;
            case PersoLockTypeTest::SIM_PC_PIN_TYPE:
                std::cout << "\n select 6. Please input Corporate Personalization PIN \n";
                break;
            case PersoLockTypeTest::SIM_PC_PUK_TYPE:
                std::cout << "\n select 7. Please input Corporate Personalization PUK \n";
                break;
            case PersoLockTypeTest::SIM_SIM_PIN_TYPE:
                std::cout << "\n select 8. Please input SIM/USIM personalisation PIN \n";
                break;
            case PersoLockTypeTest::SIM_SIM_PUK_TYPE:
                std::cout << "\n select 9. Please input SIM/USIM personalisation PUK \n";
                break;
            default:
                break;
        }
        std::cin >> password;
        size = password.size();
    }
    return password;
}

static bool TestUnlockSimLock()
{
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    std::cout << "please input sim Id" << endl;
    std::cin >> slotId;
    if (slotId != DEFAULT_SIM_SLOT_ID) {
        std::cout << "incorrect slot ID" << endl;
        return true;
    }
    LockStatusResponse response = {0};
    PersoLockInfo lockInfo;
    int32_t testType = GetSimLockType();
    std::string password = GetSimLockPassword(testType);
    std::cout << "UnlockSimLock: password = " << password << endl;
    lockInfo.password =  Str8ToStr16(password);
    lockInfo.lockType = static_cast<PersoLockType>(testType);
    g_telephonyService->UnlockSimLock(slotId, lockInfo, response);
    std::cout << "UnlockSimLock complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestHasOperatorPrivileges()
{
    std::cout << "input slotId:" << std::endl;
    int32_t slotId = 0;
    std::cin >> slotId;
    bool result = g_telephonyService->HasOperatorPrivileges(slotId);
    std::cout << "TelephonyTestService Remote TestHasOperatorPrivileges result [" << result << "] " << std::endl;
    return true;
}

static bool TestQuit()
{
    std::cout << "exit..." << std::endl;
    g_funcMap.clear();
    return false;
}

static void Prompt()
{
    std::cout << "\n start \nusage:please input a cmd num:\n"
                 "0:HasSimCard\n1:GetSimState\n"
                 "2:GetISOCountryCodeForSim\n3:GetSimSpn\n"
                 "4:GetSimIccId\n5:GetIMSI\n"
                 "6:IsSimActive\n7:GetSimOperatorNumeric\n"
                 "8:GetSimGid1\n9:GetSimGid2\n"
                 "10:GetSimAccountInfo\n11:SetDefaultVoiceSlotId\n"
                 "12:GetDefaultVoiceSlotId\n"
                 "13:GetSimEons\n"
                 "21:UnlockPin\n"
                 "22:UnlockPuk\n"
                 "23:AlterPin\n"
                 "24:GetLockState\n"
                 "25:SetLockState\n"
                 "26:RefreshSimState\n"
                 "31:UnlockPin2\n"
                 "32:UnlockPuk2\n"
                 "33:AlterPin2\n"
                 "34:SetActiveSim\n"
                 "42:SetShowNumber\n"
                 "43:GetShowNumber\n"
                 "44:SetShowName\n"
                 "45:GetShowName\n"
                 "46:GetActiveSimAccountInfoList\n"
                 "47:GetOperatorConfigs\n"
                 "49:GetVoiceMailIdentifier\n"
                 "50:GetVoiceMailNumber\n"
                 "51:QueryIccDiallingNumbers\n"
                 "52:AddIccDiallingNumbers\n"
                 "53:DelIccDiallingNumbers\n"
                 "54:UpdateIccDiallingNumbers\n"
                 "55:SetVoiceMailInfo\n"
                 "56:GetMaxSimCount\n"
                 "57:TestSendEnvelopeCmd\n"
                 "58:TestSendTerminalResponseCmd\n"
                 "59:TestSendCallSetupRequestResult\n"
                 "60:GetOpKey\n"
                 "61:GetSimTelephoneNumber\n"
                 "62:GetSimTeleNumberIdentifier\n"
                 "63:GetCardType\n"
                 "64:UnlockSimLock\n"
                 "65:SetPrimarySlotId\n"
                 "66:GetPrimarySlotId\n"
                 "67:GetOpName\n"
                 "68:GetOpKeyExt\n"
                 "70:HasOperatorPrivileges\n"
                 "100:exit\n"
              << std::endl;
}

static void InitFuncMap()
{
    g_funcMap[InputCmd::INPUT_HASSIMCARD] = TestHasSimCard;
    g_funcMap[InputCmd::INPUT_GETSIMSTATE] = TestGetSimState;
    g_funcMap[InputCmd::INPUT_GETISOCOUNTRYCODE] = TestGetISOCountryCodeForSim;
    g_funcMap[InputCmd::INPUT_GETSPN] = TestGetSimSpn;
    g_funcMap[InputCmd::INPUT_GETICCID] = TestGetSimIccId;
    g_funcMap[InputCmd::INPUT_GETSIMEONS] = TestGetSimEons;
    g_funcMap[InputCmd::INPUT_ISSIMACTIVE] = TestIsSimActive;
    g_funcMap[InputCmd::INPUT_GETSIMOPERATOR] = TestGetSimOperatorNumeric;
    g_funcMap[InputCmd::INPUT_GETGID1] = TestGetSimGid1;
    g_funcMap[InputCmd::INPUT_GETGID2] = TestGetSimGid2;
    g_funcMap[InputCmd::INPUT_GETSIMSUB] = TestGetSimSubscriptionInfo;
    g_funcMap[InputCmd::INPUT_SET_ACTIVE_SIM] = TestSetActiveSim;
    g_funcMap[InputCmd::INPUT_GETACTIVEACCOUNTLIST] = TestGetActiveSimAccountInfoList;
    g_funcMap[InputCmd::INPUT_REFRESHSIMSTATE] = TestRefreshSimState;
    g_funcMap[InputCmd::INPUT_GET_MAX_SIM_COUNT] = TestGetMaxSimCount;
    g_funcMap[InputCmd::INPUT_GET_PHONENUMBER] = TestGetSimTelephoneNumber;
    g_funcMap[InputCmd::INPUT_GET_SIM_TELENUMBER_IDENTIFIER] = TestGetSimTeleNumberIdentifier;
    g_funcMap[InputCmd::INPUT_UNLOCK_SIMLOCK] = TestUnlockSimLock;
}

static void InitFuncMapExt()
{
    g_funcMap[InputCmd::INPUT_GETIMSI] = TestGetIMSI;
    g_funcMap[InputCmd::INPUT_SETDEFAULTCALL] = TestSetDefaultVoiceSlotId;
    g_funcMap[InputCmd::INPUT_GETDEFAULTCALL] = TestGetDefaultVoiceSlotId;
    g_funcMap[InputCmd::INPUT_UNLOCK_PIN] = TestUnlockPin;
    g_funcMap[InputCmd::INPUT_UNLOCK_PUK] = TestUnlockPuk;
    g_funcMap[InputCmd::INPUT_ALTER_PIN] = TestAlterPin;
    g_funcMap[InputCmd::INPUT_SETSHOWNAME] = TestSetShowName;
    g_funcMap[InputCmd::INPUT_SETSHOWNUMBER] = TestSetShowNumber;
    g_funcMap[InputCmd::INPUT_CHECK_LOCK] = TestGetLockState;
    g_funcMap[InputCmd::INPUT_ENABLE_LOCK] = TestSetLockState;
    g_funcMap[InputCmd::INPUT_UNLOCK_PIN2] = TestUnlockPin2;
    g_funcMap[InputCmd::INPUT_UNLOCK_PUK2] = TestUnlockPuk2;
    g_funcMap[InputCmd::INPUT_ALTER_PIN2] = TestAlterPin2;
    g_funcMap[InputCmd::INPUT_GETSHOWNUMBER] = TestGetShowNumber;
    g_funcMap[InputCmd::INPUT_GETSHOWNAME] = TestGetShowName;
    g_funcMap[InputCmd::INPUT_GETOPERATORCONFIG] = TestGetOperatorConfig;
    g_funcMap[InputCmd::INPUT_GET_VOICEMAIL_NAME] = TestGetVoiceMailIdentifier;
    g_funcMap[InputCmd::INPUT_GET_VOICEMAIL_NUMBER] = TestGetVoiceMailNumber;
    g_funcMap[InputCmd::INPUT_DIALLING_NUMBERS_GET] = TestQueryIccDiallingNumbers;
    g_funcMap[InputCmd::INPUT_DIALLING_NUMBERS_INSERT] = TestAddIccDiallingNumbers;
    g_funcMap[InputCmd::INPUT_DIALLING_NUMBERS_DELETE] = TestDelIccDiallingNumbers;
    g_funcMap[InputCmd::INPUT_DIALLING_NUMBERS_UPDATE] = TestUpdateIccDiallingNumbers;
    g_funcMap[InputCmd::INPUT_SET_VOICEMAIL] = TestSetVoiceMailInfo;
    g_funcMap[InputCmd::INPUT_STK_CMD_FROM_APP] = TestSendEnvelopeCmd;
    g_funcMap[InputCmd::INPUT_STK_TERMINAL_RESPONSE] = TestSendTerminalResponseCmd;
    g_funcMap[InputCmd::INPUT_STK_CALL_SETUP_REQUEST_RESULT_FROM_APP] = TestSendCallSetupRequestResult;
    g_funcMap[InputCmd::INPUT_GET_OPKEY] = TestGetOpKey;
    g_funcMap[InputCmd::INPUT_GET_OPNAME] = TestGetOpName;
    g_funcMap[InputCmd::INPUT_GET_OPKEY_EXT] = TestGetOpKeyExt;
    g_funcMap[InputCmd::INPUT_GET_CARD_TYPE] = TestGetCardType;
    g_funcMap[InputCmd::INPUT_HAS_OPERATOR_PRIVILEGES] = TestHasOperatorPrivileges;
    g_funcMap[InputCmd::INPUT_SET_PRIMARY_SLOTID] = TestSetPrimarySlotId;
    g_funcMap[InputCmd::INPUT_GET_PRIMARY_SLOTID] = TestGetPrimarySlotId;
    g_funcMap[InputCmd::INPUT_QUIT] = TestQuit;
}

static bool ProcessInput()
{
    int inputCMDKey = DEFAULT_VALUE;
    bool loopFlag = true;
    std::cin >> inputCMDKey;
    std::cout << "inputCMD is [" << inputCMDKey << "]" << std::endl;
    InputCmd inputCMD = static_cast<InputCmd>(inputCMDKey);
    auto itFunc = g_funcMap.find(inputCMD);
    if (itFunc != g_funcMap.end()) {
        auto cmdFunc = itFunc->second;
        if (cmdFunc != nullptr) {
            loopFlag = (*cmdFunc)();
        }
    } else {
        std::cout << "please input correct number..." << std::endl;
    }
    return loopFlag;
}
} // namespace Telephony
} // namespace OHOS

using namespace OHOS::Telephony;
int main()
{
    g_telephonyService = GetProxy();
    if (g_telephonyService == nullptr) {
        return 1;
    }

    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED);
    // STK
    matchingSkills.AddEvent(ACTION_SESSION_END);
    matchingSkills.AddEvent(ACTION_STK_COMMAND);
    matchingSkills.AddEvent(ACTION_ALPHA_IDENTIFIER);
    matchingSkills.AddEvent(ACTION_CARD_STATUS_INFORM);

    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(1);
    std::shared_ptr<CommonEventTest> subScriber = std::make_shared<CommonEventTest>(subscribeInfo);
    OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(subScriber);

    InitFuncMap();
    InitFuncMapExt();
    bool loopFlag = true;
    while (loopFlag) {
        Prompt();
        loopFlag = ProcessInput();
    }
    std::cout << " exit test " << std::endl;
}
