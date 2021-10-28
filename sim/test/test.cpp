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
#include "core_service_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "sim_manager.h"

#include "string_ex.h"
#include "system_ability_definition.h"

#include "want.h"

using namespace std;
using namespace OHOS::Telephony;
namespace OHOS {
namespace Telephony {
using CmdProcessFunc = bool (*)();
static sptr<ICoreService> g_telephonyService = nullptr;
std::shared_ptr<Telephony::ISimManager> g_simManager = nullptr;

const int32_t SLOT_ID = CoreManager::DEFAULT_SLOT_ID;
const int32_t DEFAULT_VALUE = 0;
static int32_t g_testDefaultVoiceSlot = SLOT_ID;
static int32_t g_testDefaultSmsSlot = SLOT_ID;
const int32_t FIX_DAILING = 2;
static bool g_simPhoneBookRead = false;

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
    INPUT_GETSIMACCOUNT = 10,
    INPUT_SETDEFAULTCALL = 11,
    INPUT_GETDEFAULTCALL = 12,
    INPUT_SETDEFAULTSMS = 13,
    INPUT_GETDEFAULTSMS = 14,
    INPUT_UNLOCK_PIN = 21,
    INPUT_UNLOCK_PUK = 22,
    INPUT_ALTER_PIN = 23,
    INPUT_CHECK_PIN = 24,
    INPUT_ENABLE_PIN = 25,
    INPUT_REFRESHSIMSTATE = 26,
    INPUT_GET_PHONENUMBER = 48,
    INPUT_GET_VOICEMAIL_NAME = 49,
    INPUT_GET_VOICEMAIL_NUMBER = 50,
    INPUT_PHONEBOOK_GET = 51,
    INPUT_PHONEBOOK_INSERT = 52,
    INPUT_PHONEBOOK_DELETE = 53,
    INPUT_PHONEBOOK_UPDATE = 54,
    INPUT_SET_VOICEMAIL = 55,
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

static bool TestGetSimState()
{
    const int simReady = 5;
    int32_t result = g_telephonyService->GetSimState(SLOT_ID);
    string expect = (result == simReady) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetSimState result [" << result << "] " << expect << std::endl;
    return true;
}

static bool TestGetIsoCountryCodeForSim()
{
    std::u16string result = g_telephonyService->GetIsoCountryCodeForSim(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetIsoCountryCodeForSim result [" << str << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetSimSpn()
{
    std::u16string result = g_telephonyService->GetSimSpn(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimSpn result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimIccId()
{
    std::u16string result = g_telephonyService->GetSimIccId(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimIccId result [" << str << "] " << expect << std::endl;
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
    bool result = g_telephonyService->IsSimActive(SLOT_ID);
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

static bool TestGetSimTelephoneNumber()
{
    std::u16string result = g_telephonyService->GetSimTelephoneNumber(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimTelephoneNumber result [" << str << "] " << expect << std::endl;
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
    int type = SimPhoneBook_Adn;
    std::cout << "please select type: 1.public phonebooks 2.fix dialing number" << std::endl;
    std::cin >> testType;
    if (testType == FIX_DAILING) {
        type = SimPhoneBook_Fdn;
    }
    std::cout << "TestQueryIccDiallingNumbers loading " << testType << std::endl;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbers =
        g_telephonyService->QueryIccDiallingNumbers(SLOT_ID, type);
    g_simPhoneBookRead = true;
    if (diallingNumbers.empty()) {
        std::cout << "no phonebooks in sim" << std::endl;
        return true;
    }
    int id = 0;
    for (std::vector<std::shared_ptr<DiallingNumbersInfo>>::iterator it = diallingNumbers.begin();
         it != diallingNumbers.end(); it++) {
        std::shared_ptr<DiallingNumbersInfo> item = *it;
        std::string name = Str16ToStr8(item->GetAlphaTag());
        std::string number = Str16ToStr8(item->GetNumber());
        int index = item->GetRecId();
        int diallingNumbertype = item->GetEfid();
        std::cout << ++id << "  " << index << " " << name << "  " << number << "  " << diallingNumbertype
                  << std::endl;
    }
    return true;
}

static bool TestAddIccDiallingNumbers()
{
    if (!g_simPhoneBookRead) {
        std::cout << "you need run QueryIccDiallingNumbers once at least" << std::endl;
        return true;
    }
    std::string name = "";
    std::string number = "";
    int type = 0;
    std::cout << "input name:" << std::endl;
    std::cin >> name;
    std::cout << "input number:" << std::endl;
    std::cin >> number;
    std::cout << "please select type: 1.public phonebooks 2.fix dialing number" << std::endl;
    std::cin >> type;
    if (type == FIX_DAILING) {
        type = SimPhoneBook_Fdn;
    } else {
        type = SimPhoneBook_Adn;
    }

    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>(type, 0);
    diallingNumber->alphaTag_ = Str8ToStr16(name);
    diallingNumber->number_ = Str8ToStr16(number);
    std::cout << "start insert " << Str16ToStr8(diallingNumber->alphaTag_) << " "
              << Str16ToStr8(diallingNumber->number_) << std::endl;
    bool result = g_telephonyService->AddIccDiallingNumbers(SLOT_ID, type, diallingNumber);
    std::cout << "TelephonyTestService Remote TestAddIccDiallingNumbers result [" << result << "] " << std::endl;
    return true;
}

static bool TestDelIccDiallingNumbers()
{
    if (!g_simPhoneBookRead) {
        std::cout << "you need run QueryIccDiallingNumbers once at least" << std::endl;
        return true;
    }
    int type = 0;
    int index = 0;
    std::cout << "select id:" << std::endl;
    std::cin >> index;
    std::cout << "please select type: 1.public phonebooks 2.fix dialing number" << std::endl;
    std::cin >> type;
    if (type == FIX_DAILING) {
        type = SimPhoneBook_Fdn;
    } else {
        type = SimPhoneBook_Adn;
    }

    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>(type, 0);
    bool result = g_telephonyService->DelIccDiallingNumbers(SLOT_ID, type, index);
    std::cout << "TelephonyTestService Remote DelIccDiallingNumbers result [" << result << "] " << std::endl;
    return true;
}

static bool TestUpdateIccDiallingNumbers()
{
    if (!g_simPhoneBookRead) {
        std::cout << "you need run QueryIccDiallingNumbers once at least" << std::endl;
        return true;
    }
    std::string name = "";
    std::string number = "";
    int type = 0;
    int index = 0;
    std::cout << "select id:" << std::endl;
    std::cin >> index;
    std::cout << "input name:" << std::endl;
    std::cin >> name;
    std::cout << "input number:" << std::endl;
    std::cin >> number;
    std::cout << "please select type: 1.public phonebooks 2.fix dialing number" << std::endl;
    std::cin >> type;
    if (type == FIX_DAILING) {
        type = SimPhoneBook_Fdn;
    } else {
        type = SimPhoneBook_Adn;
    }

    std::shared_ptr<DiallingNumbersInfo> diallingNumber = std::make_shared<DiallingNumbersInfo>(type, 0);
    diallingNumber->alphaTag_ = Str8ToStr16(name);
    diallingNumber->number_ = Str8ToStr16(number);
    bool result = g_telephonyService->UpdateIccDiallingNumbers(SLOT_ID, type, diallingNumber, index);
    std::cout << "TelephonyTestService Remote UpdateIccDiallingNumbers result [" << result << "] " << std::endl;
    return true;
}

static bool TestSetVoiceMail()
{
    std::string name = "";
    std::string number = "";
    std::cout << "input name:" << std::endl;
    std::cin >> name;
    std::cout << "input number:" << std::endl;
    std::cin >> number;
    std::u16string mailName = Str8ToStr16(name);
    std::u16string mailNumber = Str8ToStr16(number);
    bool result = g_telephonyService->SetVoiceMail(mailName, mailNumber, SLOT_ID);
    std::cout << "TelephonyTestService Remote SetVoiceMail result [" << result << "] " << std::endl;
    return true;
}

static bool TestGetSimAccountInfo()
{
    const std::u16string DEFALUT_DISPLAY_NAME = u"testDisplayName";
    const std::u16string DEFALUT_DISPLAY_NUMBER = u"testDisplayNumber";
    std::cout << "please input Sub Id" << std::endl;
    int testSim = DEFAULT_VALUE;
    std::cin >> testSim;
    IccAccountInfo iccAccountInfo;
    iccAccountInfo.Init(SLOT_ID);
    iccAccountInfo.displayName = DEFALUT_DISPLAY_NAME;
    iccAccountInfo.displayNumber = DEFALUT_DISPLAY_NUMBER;
    bool result = g_telephonyService->GetSimAccountInfo(testSim, iccAccountInfo);
    string expect = result ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetSimAccountInfo result [" << result << "] " << expect << std::endl
              << "receive slotIndex = [" << iccAccountInfo.slotIndex << "]" << std::endl
              << "receive displayName = [" << Str16ToStr8(iccAccountInfo.displayName) << "]" << std::endl
              << "receive displayNumber = [" << Str16ToStr8(iccAccountInfo.displayNumber) << "]" << std::endl;
    return true;
}

static bool TestSetDefaultVoiceSlotId()
{
    static int32_t oldTestDefaultVoiceSlot = SLOT_ID;
    std::cout << "please input Default Voice Slot Id" << std::endl;
    std::cin >> g_testDefaultVoiceSlot;
    bool result = g_telephonyService->SetDefaultVoiceSlotId(g_testDefaultVoiceSlot);
    string expect = result ? "success" : "fail";
    if (!result) {
        g_testDefaultVoiceSlot = oldTestDefaultVoiceSlot;
    } else {
        oldTestDefaultVoiceSlot = g_testDefaultVoiceSlot;
    }
    std::cout << "TelephonyTestService Remote SetDefaultVoiceSlotId result [" << result << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetDefaultVoiceSlotId()
{
    int32_t result = g_telephonyService->GetDefaultVoiceSlotId();
    string expect = (result == g_testDefaultVoiceSlot) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetDefaultVoiceSlotId result [" << result << "] " << expect
              << std::endl;
    return true;
}

static bool TestSetDefaultSmsSlotId()
{
    static int32_t g_oldTestDefaultSmsSlot = SLOT_ID;
    if (g_simManager == nullptr) {
        g_simManager = std::make_shared<SimManager>();
        if (g_simManager != nullptr) {
            g_simManager->Init();
        }
    }
    std::cout << "please input Default Sms Slot Id" << std::endl;
    std::cin >> g_testDefaultSmsSlot;
    bool result = g_simManager->SetDefaultSmsSlotId(g_testDefaultSmsSlot);
    string expect = result ? "success" : "fail";
    if (!result) {
        g_testDefaultSmsSlot = g_oldTestDefaultSmsSlot;
    } else {
        g_oldTestDefaultSmsSlot = g_testDefaultSmsSlot;
    }
    std::cout << "TelephonyTestService Remote SetDefaultSmsSlotId result [" << result << "] " << expect
              << std::endl;
    return true;
}

static bool TestGetDefaultSmsSlotId()
{
    if (g_simManager == nullptr) {
        g_simManager = std::make_shared<SimManager>();
        if (g_simManager != nullptr) {
            g_simManager->Init();
        }
    }
    int32_t result = g_simManager->GetDefaultSmsSlotId();
    string expect = (result == g_testDefaultSmsSlot) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetDefaultSmsSlotId result [" << result << "] " << expect
              << std::endl;
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
    g_telephonyService->UnlockPin(Str8ToStr16(pin.c_str()), response, SLOT_ID);
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
    g_telephonyService->UnlockPuk(Str8ToStr16(newPin.c_str()), Str8ToStr16(puk.c_str()), response, SLOT_ID);
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
    g_telephonyService->AlterPin(Str8ToStr16(newPin.c_str()), Str8ToStr16(oldPin.c_str()), response, SLOT_ID);
    std::cout << "Alter pin complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestSetLockState()
{
    LockStatusResponse response = {0};
    std::string pin = " ";
    int mode = -1;
    int size = 0;
    while (!Among(size, PinWordSize::PIN_MIN_SIZE, PinWordSize::PIN_MAX_SIZE)) {
        std::cout << "\n Set pin lock switch, Please input pin \n";
        std::cin >> pin;
        size = pin.size();
    }
    size = 0;
    while (!AmongLock(mode, PinLockEnable::PIN_LOCK_RESET, PinLockEnable::PIN_LOCK_SET)) {
        std::cout << "\n Set pin lock switch, Please input switch \n";
        std::cin >> mode;
    }
    std::cout << "SetLockState: pin = " << pin << "  mode = " << mode << endl;
    g_telephonyService->SetLockState(Str8ToStr16(pin.c_str()), mode, response, SLOT_ID);
    std::cout << "Set Lock complete:" << response.result << " " << response.remain << std::endl;
    return true;
}

static bool TestGetLockState()
{
    int32_t ret = g_telephonyService->GetLockState(SLOT_ID);
    std::cout << "TestGetLockState()" << ret << endl;
    return true;
}

static bool TestRefreshSimState()
{
    int32_t ret = g_telephonyService->RefreshSimState(SLOT_ID);
    std::cout << "TestRefreshSimState()" << ret << endl;
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
    std::cout << "\n start \n"
                 "usage:please input a cmd num:\n"
                 "0:HasSimCard\n"
                 "1:GetSimState\n"
                 "2:GetIsoCountryCodeForSim\n"
                 "3:GetSimSpn\n"
                 "4:GetSimIccId\n"
                 "5:GetIMSI\n"
                 "6:IsSimActive\n"
                 "7:GetSimOperatorNumeric\n"
                 "8:GetSimGid1\n"
                 "10:GetSimAccountInfo\n"
                 "11:SetDefaultVoiceSlotId\n"
                 "12:GetDefaultVoiceSlotId\n"
                 "13:SetDefaultSmsSlotId\n"
                 "14:GetDefautlSmsSlotId\n"
                 "21:UnlockPin\n"
                 "22:UnlockPuk\n"
                 "23:AlterPin\n"
                 "24:GetLockState\n"
                 "25:SetLockState\n"
                 "26:RefreshSimState\n"
                 "27:SimRdbTest\n"
                 "48:GetSimTelephoneNumber\n"
                 "49:GetVoiceMailIdentifier\n"
                 "50:GetVoiceMailNumber\n"
                 "51:QueryIccDiallingNumbers\n"
                 "52:AddIccDiallingNumbers\n"
                 "53:DelIccDiallingNumbers\n"
                 "54:UpdateIccDiallingNumbers\n"
                 "55:SetVoiceMail\n"
                 "100:exit\n"
              << std::endl;
}

static void InitFuncMap()
{
    g_funcMap[InputCmd::INPUT_HASSIMCARD] = TestHasSimCard;
    g_funcMap[InputCmd::INPUT_GETSIMSTATE] = TestGetSimState;
    g_funcMap[InputCmd::INPUT_GETISOCOUNTRYCODE] = TestGetIsoCountryCodeForSim;
    g_funcMap[InputCmd::INPUT_GETSPN] = TestGetSimSpn;
    g_funcMap[InputCmd::INPUT_GETICCID] = TestGetSimIccId;
    g_funcMap[InputCmd::INPUT_GETIMSI] = TestGetIMSI;
    g_funcMap[InputCmd::INPUT_ISSIMACTIVE] = TestIsSimActive;
    g_funcMap[InputCmd::INPUT_GETSIMOPERATOR] = TestGetSimOperatorNumeric;
    g_funcMap[InputCmd::INPUT_GETGID1] = TestGetSimGid1;
    g_funcMap[InputCmd::INPUT_GETSIMACCOUNT] = TestGetSimAccountInfo;
    g_funcMap[InputCmd::INPUT_SETDEFAULTCALL] = TestSetDefaultVoiceSlotId;
    g_funcMap[InputCmd::INPUT_GETDEFAULTCALL] = TestGetDefaultVoiceSlotId;
    g_funcMap[InputCmd::INPUT_SETDEFAULTSMS] = TestSetDefaultSmsSlotId;
    g_funcMap[InputCmd::INPUT_GETDEFAULTSMS] = TestGetDefaultSmsSlotId;
    g_funcMap[InputCmd::INPUT_REFRESHSIMSTATE] = TestRefreshSimState;
    g_funcMap[InputCmd::INPUT_GET_PHONENUMBER] = TestGetSimTelephoneNumber;
    g_funcMap[InputCmd::INPUT_GET_VOICEMAIL_NAME] = TestGetVoiceMailIdentifier;
    g_funcMap[InputCmd::INPUT_GET_VOICEMAIL_NUMBER] = TestGetVoiceMailNumber;
    g_funcMap[InputCmd::INPUT_PHONEBOOK_GET] = TestQueryIccDiallingNumbers;
    g_funcMap[InputCmd::INPUT_PHONEBOOK_INSERT] = TestAddIccDiallingNumbers;
    g_funcMap[InputCmd::INPUT_PHONEBOOK_DELETE] = TestDelIccDiallingNumbers;
    g_funcMap[InputCmd::INPUT_PHONEBOOK_UPDATE] = TestUpdateIccDiallingNumbers;
    g_funcMap[InputCmd::INPUT_SET_VOICEMAIL] = TestSetVoiceMail;
    g_funcMap[InputCmd::INPUT_QUIT] = TestQuit;
}

static bool ProcessInput()
{
    int inputCMDKey = DEFAULT_VALUE;
    bool loopFlag = true;
    std::cin >> inputCMDKey;
    std::cout << "inputCMD is [" << inputCMDKey << "]" << std::endl;
    InputCmd inputCMD = static_cast<InputCmd>(inputCMDKey);
    if (inputCMD == InputCmd::INPUT_UNLOCK_PIN) {
        return TestUnlockPin();
    } else if (inputCMD == InputCmd::INPUT_UNLOCK_PUK) {
        return TestUnlockPuk();
    } else if (inputCMD == InputCmd::INPUT_ALTER_PIN) {
        return TestAlterPin();
    } else if (inputCMD == InputCmd::INPUT_ENABLE_PIN) {
        return TestSetLockState();
    } else if (inputCMD == InputCmd::INPUT_CHECK_PIN) {
        return TestGetLockState();
    }
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

    // create common Event subscriber
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(SIM_STATE_CHANGE_ACTION);
    matchingSkills.AddEvent(DEFAULT_VOICE_SLOTID_CHANGE_ACTION);
    matchingSkills.AddEvent(DEFAULT_SMS_SLOTID_CHANGE_ACTION);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(1);
    std::shared_ptr<CommonEventTest> subScriber = std::make_shared<CommonEventTest>(subscribeInfo);
    OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(subScriber);

    InitFuncMap();
    bool loopFlag = true;
    while (loopFlag) {
        Prompt();
        loopFlag = ProcessInput();
    }
    std::cout << " exit test " << std::endl;
}
