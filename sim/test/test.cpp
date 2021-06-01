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

#include "core_service_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

using namespace std;
namespace OHOS {
namespace SIM {
using CmdProcessFunc = bool (*)();
static sptr<ICoreService> g_telephonyService = nullptr;
static std::map<int, CmdProcessFunc> g_funcMap;
const int32_t SLOT_ID = 1;
const int32_t SIM_READY = 5;

enum InputCmd {
    INPUT_HASSIMCARD = 0,
    INPUT_GETSIMSTATE = 1,
    INPUT_GETISOCOUNTRYCODE = 2,
    INPUT_GETSPN = 3,
    INPUT_GETICCID = 4,
    INPUT_GETIMSI = 5,
    INPUT_ISSIMACTIVE = 6,
    INPUT_GETSIMOPERATOR = 7,
    INPUT_QUIT = 11,
};

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
        std::cout << "TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID succ ... " << std::endl;
        return telephonyService;
    } else {
        std::cout << "TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail ... " << std::endl;
        return nullptr;
    }
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
    int32_t result = g_telephonyService->GetSimState(SLOT_ID);
    string expect = (result == SIM_READY) ? "success" : "fail";
    std::cout << "TelephonyTestService Remote GetSimState result [" << result << "] " << expect << std::endl;
    return true;
}

static bool TestGetIsoCountryCode()
{
    std::u16string result = g_telephonyService->GetIsoCountryCode(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetIsoCountryCode result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSpn()
{
    std::u16string result = g_telephonyService->GetSpn(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSpn result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetIccId()
{
    std::u16string result = g_telephonyService->GetIccId(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetIccId result [" << str << "] " << expect << std::endl;
    return true;
}

static bool TestGetSimOperator()
{
    std::u16string result = g_telephonyService->GetSimOperator(SLOT_ID);
    std::string str = Str16ToStr8(result);
    string expect = str.empty() ? "fail" : "success";
    std::cout << "TelephonyTestService Remote GetSimOperator result [" << str << "] " << expect << std::endl;
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

static bool TestQuit()
{
    std::cout << "exit..." << std::endl;
    g_funcMap.clear();
    return false;
}

static void Prompt()
{
    printf(
        "\n-----------start--------------\n"
        "usage:please input a cmd num:\n"
        "0:HasSimCard\n"
        "1:GetSimState\n"
        "2:GetIsoCountryCode\n"
        "3:GetSpn\n"
        "4:GetIccId\n"
        "5:GetIMSI\n"
        "6:IsSimActive\n"
        "7:GetSimOperator\n"
        "11:exit\n");
}

static void InitFuncMap()
{
    g_funcMap[INPUT_HASSIMCARD] = TestHasSimCard;
    g_funcMap[INPUT_GETSIMSTATE] = TestGetSimState;
    g_funcMap[INPUT_GETISOCOUNTRYCODE] = TestGetIsoCountryCode;
    g_funcMap[INPUT_GETSPN] = TestGetSpn;
    g_funcMap[INPUT_GETICCID] = TestGetIccId;
    g_funcMap[INPUT_GETIMSI] = TestGetIMSI;
    g_funcMap[INPUT_ISSIMACTIVE] = TestIsSimActive;
    g_funcMap[INPUT_GETSIMOPERATOR] = TestGetSimOperator;
    g_funcMap[INPUT_QUIT] = TestQuit;
}

static bool ProcessInput()
{
    int inputCMD = 0;
    bool loopFlag = true;
    std::cin >> inputCMD;
    std::cout << "inputCMD is [" << inputCMD << "]" << std::endl;
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
} // namespace SIM
} // namespace OHOS

using namespace OHOS::SIM;
int main()
{
    g_telephonyService = GetProxy();
    if (g_telephonyService == nullptr) {
        return 1;
    }
    InitFuncMap();
    bool loopFlag = true;
    while (loopFlag) {
        Prompt();
        loopFlag = ProcessInput();
    }
    std::cout << "...exit test..." << std::endl;
}
