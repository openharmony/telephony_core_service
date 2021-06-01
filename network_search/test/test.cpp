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
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <string>

#include "core_service_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
sptr<ICoreService> g_telephonyService = nullptr;
const int32_t INPUT_GET_PS_RADIO_TECH = 0;
const int32_t INPUT_GET_CS_RADIO_TECH = 1;
const int32_t INPUT_GET_OPERATOR_NUMERIC = 2;
const int32_t INPUT_GET_NETWORK_STATE = 3;
const int32_t INPUT_GET_OPERATOR_NAME = 4;
const int32_t INPUT_GET_SIGNAL_INFO_LIST = 5;
const int32_t INPUT_SET_RADIO_STATE = 6;
const int32_t INPUT_GET_RADIO_STATE = 7;
const int32_t INPUT_NOTIFY_NETWORK_CHANGE = 8;
const int32_t INPUT_QUIT = 1000;

sptr<ICoreService> GetProxy()
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

void TestGetNetworkState()
{
    printf("TelephonyTestService Remote GetNetworkStatus \n");
    sptr<NetworkState> result = g_telephonyService->GetNetworkStatus(1);
    if (result == nullptr) {
        printf("result is null\n");
    } else {
        std::cout << "CoreServiceProxy::GetNetworkStatus return" << std::endl;
        std::cout << "GetRegStatus() : " << result->GetRegStatus() << std::endl;
        std::cout << "GetLongOperatorName() : " << result->GetLongOperatorName() << std::endl;
        std::cout << "GetShortOperatorName() : " << result->GetShortOperatorName() << std::endl;
        std::cout << "GetPlmnNumeric() : " << result->GetPlmnNumeric() << std::endl;
    }
}

void TestGetPsRadioTech()
{
    int32_t result = g_telephonyService->GetPsRadioTech(1);
    std::cout << "TelephonyTestService Remote GetPsRadioTech result [" << result << "]" << std::endl;
}

void TestGetCsRadioTech()
{
    int32_t result = g_telephonyService->GetCsRadioTech(1);
    std::cout << "TelephonyTestService Remote GetCsRadioTech result [" << result << "]" << std::endl;
}

void TestGetOperatorNumeric()
{
    std::u16string result = g_telephonyService->GetOperatorNumeric(1);
    std::string str = Str16ToStr8(result);
    std::cout << "TelephonyTestService Remote GetOperatorNumeric result [" << str << "]" << std::endl;
}

void TestGetOperatorName()
{
    std::u16string result = g_telephonyService->GetOperatorName(1);
    std::string str = Str16ToStr8(result);
    std::cout << "TelephonyTestService Remote GetOperatorName result [" << str << "]" << std::endl;
}

void TestGsmSignalInformation(const GsmSignalInformation &gsm)
{
    std::cout << "TelephonyTestService Remote GsmSignalInformation ToString[" << Str16ToStr8(gsm.ToString()) << "]"
              << std::endl;
    std::cout << "TelephonyTestService Remote GsmSignalInformation GetRssi[" << gsm.GetRssi() << "]" << std::endl;
    std::cout << "TelephonyTestService Remote GsmSignalInformation GetSignalLevel[" << gsm.GetSignalLevel() << "]"
              << std::endl;
    std::cout << "TelephonyTestService Remote GsmSignalInformation GetTimeAdvance[" << gsm.GetTimeAdvance() << "]"
              << std::endl;
    std::cout << "TelephonyTestService Remote GsmSignalInformation GetNetworkType[GSM]" << std::endl;
    std::cout << "\n" << std::endl;
}

void TestCdmaSignalInformation(const CdmaSignalInformation &cdma)
{
    std::cout << "TelephonyTestService Remote CdmaSignalInformation ToString[" << Str16ToStr8(cdma.ToString())
              << "]" << std::endl;
    std::cout << "TelephonyTestService Remote CdmaSignalInformation GetCdmaRssi[" << cdma.GetCdmaRssi() << "]"
              << std::endl;
    std::cout << "TelephonyTestService Remote CdmaSignalInformation GetSignalLevel[" << cdma.GetSignalLevel()
              << "]" << std::endl;
    std::cout << "TelephonyTestService Remote CdmaSignalInformation GetNetworkTypeid[CDMA]" << std::endl;
    std::cout << "\n" << std::endl;
}

void TestGetSignalInfoList()
{
    auto result = g_telephonyService->GetSignalInfoList(1);
    SignalInformation::NetworkType type;
    for (const auto &v : result) {
        type = v->GetNetworkType();
        std::cout << "TelephonyTestService Remote SignalInformation result NetworkTypeId["
                  << static_cast<int32_t>(type) << "]" << std::endl;

        if (type == SignalInformation::NetworkType::GSM) {
            GsmSignalInformation *gsm = reinterpret_cast<GsmSignalInformation *>(v.GetRefPtr());
            TestGsmSignalInformation(*gsm);
        } else if (type == SignalInformation::NetworkType::CDMA) {
            CdmaSignalInformation *cdma = reinterpret_cast<CdmaSignalInformation *>(v.GetRefPtr());
            TestCdmaSignalInformation(*cdma);
        }
    }
    std::cout << "TelephonyTestService Remote TestGetSignalInfoList size [" << result.size() << "]" << std::endl;
}

void TestSetHRilRadioState()
{
    std::cout << "please input radio state off(0) or on(1) " << std::endl;
    int inputState = 0;
    std::cin >> inputState;
    bool isOn = true;
    if (inputState == 0) {
        isOn = false;
    }
    std::cout << "radio off(N) or on(Y) [" << isOn << "]" << std::endl;
    g_telephonyService->SetHRilRadioState(1, isOn);
    std::cout << "TelephonyTestService Remote SetHRilRadioState result [" << inputState << "]" << std::endl;
}

void TestGetHRilRadioState()
{
    int32_t result = g_telephonyService->GetRadioState(1);
    std::cout << "TelephonyTestService Remote GetRadioState result [" << result << "]" << std::endl;
}
void TestNotifyNetworkStateChange()
{
    TestGetCsRadioTech();
    sleep(5);
    TestGetOperatorNumeric();
    g_telephonyService->SetHRilRadioState(1, 1);
}

void Prompt()
{
    printf(
        "\n-----------start test remote api--------------\n"
        "usage:please input a cmd num:\n"
        "0:GetPsRadioTech\n"
        "1:GetCsRadioTech\n"
        "2:GetOperatorNumeric\n"
        "3:GetNetworkStatus\n"
        "4:GetOperatorName\n"
        "5:GetSignalInfoList\n"
        "6:SetHRilRadioState\n"
        "7:GetRadioState\n"
        "8:NotifyNetworkStateChange\n"
        "1000:exit \n");
}

void ProcessInput(bool &loopFlag)
{
    int inputCMD = 0;
    std::cin >> inputCMD;
    std::cout << "inputCMD is [" << inputCMD << "]" << std::endl;
    switch (inputCMD) {
        case INPUT_GET_PS_RADIO_TECH:
            TestGetPsRadioTech();
            break;
        case INPUT_GET_CS_RADIO_TECH:
            TestGetCsRadioTech();
            break;
        case INPUT_GET_OPERATOR_NUMERIC:
            TestGetOperatorNumeric();
            break;
        case INPUT_GET_NETWORK_STATE:
            TestGetNetworkState();
            break;
        case INPUT_GET_OPERATOR_NAME:
            TestGetOperatorName();
            break;
        case INPUT_GET_SIGNAL_INFO_LIST:
            TestGetSignalInfoList();
            break;
        case INPUT_SET_RADIO_STATE:
            TestSetHRilRadioState();
            break;
        case INPUT_GET_RADIO_STATE:
            TestGetHRilRadioState();
            break;
        case INPUT_NOTIFY_NETWORK_CHANGE:
            TestNotifyNetworkStateChange();
            break;
        case INPUT_QUIT:
            loopFlag = false;
            std::cout << "exit..." << std::endl;
            break;
        default:
            std::cout << "please input correct number..." << std::endl;
            break;
    }
}
} // namespace OHOS

using namespace OHOS;
int main()
{
    g_telephonyService = GetProxy();
    if (g_telephonyService == nullptr) {
        return 1;
    }
    bool loopFlag = true;
    while (loopFlag) {
        Prompt();
        ProcessInput(loopFlag);
    }
    std::cout << "...exit test..." << std::endl;
}
