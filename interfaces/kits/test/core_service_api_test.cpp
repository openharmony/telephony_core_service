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

#include <codecvt>
#include <iostream>
#include <locale>
#include <memory>
#include <sstream>
#include <string>

#include "network_state.h"
#include "radio_network_manager.h"
#include "str_convert.h"

using namespace OHOS;
using namespace OHOS::Telephony;
namespace {
const int CMD_GET_CS_RADIO_TECH = 0;
const int CMD_GET_PS_RADIO_TECH = 1;
const int CMD_GET_OPERATOR_NAME = 2;
const int CMD_GET_OPERATOR_NUMERIC = 3;
const int CMD_GET_SIGNAL_INFO_LIST = 4;
const int CMD_GET_NETWORK_STATE = 5;
const int CMD_EXIT = 1000;
} // namespace

static void TestGetCsRadioTech(const std::unique_ptr<RadioNetworkManager> &radioNetworkManager)
{
    int32_t csRadioTech = radioNetworkManager->GetCsRadioTech(1);
    std::cout << "csRadioTech = " << csRadioTech << std::endl;
}

static void TestGetPsRadioTech(const std::unique_ptr<RadioNetworkManager> &radioNetworkManager)
{
    int32_t psRadioTech = radioNetworkManager->GetPsRadioTech(1);
    std::cout << "psRadioTech = " << psRadioTech << std::endl;
}

static void TestGetOperatorName(const std::unique_ptr<RadioNetworkManager> &radioNetworkManager)
{
    std::u16string operatorName = radioNetworkManager->GetOperatorName(1);
    std::cout << "operatorName = " << ToUtf8(operatorName) << std::endl;
}

static void TestGetOperatorNumeric(const std::unique_ptr<RadioNetworkManager> &radioNetworkManager)
{
    std::u16string operatorNumeric = radioNetworkManager->GetOperatorNumeric(1);
    std::cout << "operatorNumeric = " << ToUtf8(operatorNumeric) << std::endl;
}

static void TestGetSignalInfoList(const std::unique_ptr<RadioNetworkManager> &radioNetworkManager)
{
    std::vector<sptr<SignalInformation>> signalList = radioNetworkManager->GetSignalInfoList(1);
    int size = signalList.size();
    std::cout << "signalList size = " << size << std::endl;
}

static void TestGetNetworkState(const std::unique_ptr<RadioNetworkManager> &radioNetworkManager)
{
    sptr<NetworkState> networkState = radioNetworkManager->GetNetworkState(1);
    std::cout << "networkState->GetLongOperatorName() " << networkState->GetLongOperatorName() << std::endl;
    std::cout << "networkState->GetShortOperatorName() " << networkState->GetShortOperatorName() << std::endl;
    std::cout << "networkState->GetPlmnNumeric() " << networkState->GetPlmnNumeric() << std::endl;
    std::cout << "networkState->GetRegStatus() " << networkState->GetRegStatus() << std::endl;
    std::cout << "networkState->IsEmergency() " << networkState->IsEmergency() << std::endl;
    std::cout << "networkState->IsRoaming() " << networkState->IsRoaming() << std::endl;
}

static void TestCase(const int inputCMD, const std::unique_ptr<RadioNetworkManager> &radioNetworkManager)
{
    switch (inputCMD) {
        case CMD_GET_CS_RADIO_TECH: {
            TestGetCsRadioTech(radioNetworkManager);
            break;
        }
        case CMD_GET_PS_RADIO_TECH: {
            TestGetPsRadioTech(radioNetworkManager);
            break;
        }
        case CMD_GET_OPERATOR_NAME: {
            TestGetOperatorName(radioNetworkManager);
            break;
        }
        case CMD_GET_OPERATOR_NUMERIC: {
            TestGetOperatorNumeric(radioNetworkManager);
            break;
        }
        case CMD_GET_SIGNAL_INFO_LIST: {
            TestGetSignalInfoList(radioNetworkManager);
            break;
        }
        case CMD_GET_NETWORK_STATE: {
            TestGetNetworkState(radioNetworkManager);
            break;
        }
        case CMD_EXIT: {
            std::cout << "exit..." << std::endl;
            break;
        }
        default: {
            std::cout << "please input correct number..." << std::endl;
            break;
        }
    }
}

int main()
{
    std::unique_ptr<RadioNetworkManager> radioNetworkManager = std::make_unique<RadioNetworkManager>();
    int inputCMD = CMD_GET_CS_RADIO_TECH;
    while (inputCMD != CMD_EXIT) {
        printf(
            "\n-----------menu--------------\n"
            "please input a cmd num:\n"
            "0:GetCsRadioTech\n"
            "1:GetPsRadioTech\n"
            "2:GetOperatorName\n"
            "3:GetOperatorNumeric\n"
            "4:GetSignalInfoList\n"
            "5:GetNetworkStatus\n"
            "1000:exit\n");
        std::cin >> inputCMD;
        std::cout << "inputCMD is [" << inputCMD << "]" << std::endl;
        TestCase(inputCMD, radioNetworkManager);
    }
    return 0;
}