/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <iostream>
#include <memory>
#include <securec.h>
#include <stack>
#include <string_ex.h>
#include <vector>

#define private public

#include "accesstoken_kit.h"
#include "cellular_data_client.h"
#include "core_service_client.h"
#include "core_service_test_code.h"
#include "ims_reg_info_callback_gtest.h"
#include "state_registry_observer.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_observer_client.h"
#include "token_setproc.h"

namespace OHOS {
namespace Telephony {
using namespace OHOS::Security::AccessToken;
using OHOS::Security::AccessToken::AccessTokenID;
constexpr int16_t SIM1_SLOTID = 0;
constexpr int16_t DEFAULT_VALUE = 0;

enum class CallManagerInterfaceType {
    REGISTER_CALLBACK_TYPE = 1,
    INTERFACE_BLUETOOTH_CALL_TYPE,
};

CoreServiceClient &g_coreServiceClientPtr = CoreServiceClient::GetInstance();
CellularDataClient &g_cellularDataClient = CellularDataClient::GetInstance();
TelephonyObserverClient &g_observerDataClient = TelephonyObserverClient::GetInstance();
using CoreServiceFunc = void (*)();
std::map<uint32_t, CoreServiceFunc> g_memberFuncMap;
std::vector<AccessTokenIDEx> simAccountCallbackTokenIDVec_;
std::vector<AccessTokenIDEx> imsCallbackTokenIDVec_;
std::vector<AccessTokenIDEx> stateObserverTokenIDVec_;
AccessTokenID currentThreadTokenId_ = 0;
AccessTokenIDEx currentTokenIDEx_;

HapInfoParams testInfoParams = {
    .userID = 1,
    .bundleName = "tel_core_service_ui_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true,
};

PermissionDef testPermSetTelephonyStateDef = {
    .permissionName = "ohos.permission.SET_TELEPHONY_STATE",
    .bundleName = "tel_core_service_ui_test",
    .grantMode = 1, // SYSTEM_GRANT
    .availableLevel = APL_SYSTEM_BASIC,
    .label = "label",
    .labelId = 1,
    .description = "Test call maneger",
    .descriptionId = 1,
};

PermissionStateFull testSetTelephonyState = {
    .permissionName = "ohos.permission.SET_TELEPHONY_STATE",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 2 }, // PERMISSION_USER_SET
};

PermissionDef testPermGetTelephonyStateDef = {
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .bundleName = "tel_core_service_ui_test",
    .grantMode = 1, // SYSTEM_GRANT
    .availableLevel = APL_SYSTEM_BASIC,
    .label = "label",
    .labelId = 1,
    .description = "Test call maneger",
    .descriptionId = 1,
};

PermissionStateFull testGetTelephonyState = {
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 2 }, // PERMISSION_USER_SET
};

PermissionDef testNetPermGetNetworkInfoDef = {
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .bundleName = "tel_state_registry_test",
    .grantMode = 1, // SYSTEM_GRANT
    .availableLevel = APL_SYSTEM_BASIC,
    .label = "label",
    .labelId = 1,
    .description = "Test state registry",
    .descriptionId = 1,
};

PermissionStateFull testNetPermGetNetworkInfo = {
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 2 }, // PERMISSION_USER_SET
};

HapPolicyParams testPolicyParams = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = { testPermSetTelephonyStateDef, testPermGetTelephonyStateDef, testNetPermGetNetworkInfoDef },
    .permStateList = { testSetTelephonyState, testGetTelephonyState, testNetPermGetNetworkInfo },
};

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        currentThreadTokenId_ = currentID_;
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParams, testPolicyParams);
        accessID_ = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(tokenIdEx.tokenIDEx);
        std::cout << "Current tokenId is: " << accessID_ << std::endl;
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
        std::cout << "currentID_ tokenId is: " << currentID_ << std::endl;
    }

private:
    AccessTokenID currentID_ = 0;
    AccessTokenID accessID_ = 0;
};

void RegisterSimAccountCallback()
{
    g_cellularDataClient.RegisterSimAccountCallback();
    std::cout << "RegisterSimAccountCallback success!" << std::endl;
    g_cellularDataClient.registerStatus_ = false;
    simAccountCallbackTokenIDVec_.push_back(currentTokenIDEx_);
}

void UnRegisterSimAccountCallback()
{
    if (simAccountCallbackTokenIDVec_.empty()) {
        std::cout << "no callback need to unregister!";
        return;
    }
    std::cout << "Callback list: \n";
    for (int32_t i = 0; i < simAccountCallbackTokenIDVec_.size(); i++) {
        SetSelfTokenID(simAccountCallbackTokenIDVec_[i].tokenIDEx);
        std::cout << i << ": tokenId is " << GetSelfTokenID() << "\n";
    }
    std::cout << "Please select tokeId which you need unregister...\n";
    int32_t index = 0;
    std::cin >> index;
    AccessTokenIDEx currentIDEx = simAccountCallbackTokenIDVec_[index];
    SetSelfTokenID(currentIDEx.tokenIDEx);
    std::cout << "Selected tokenId is " << GetSelfTokenID() << std::endl;
    g_cellularDataClient.UnregisterSimAccountCallback();
    simAccountCallbackTokenIDVec_.erase(simAccountCallbackTokenIDVec_.begin() + index);
    AccessTokenKit::DeleteToken(currentIDEx.tokenIdExStruct.tokenID);
    SetSelfTokenID(currentThreadTokenId_);
    std::cout << "UnRegisterSimAccountCallback success!" << std::endl;
}

void RegisterImsRegInfoCallback()
{
    int32_t ret = TELEPHONY_SUCCESS;
    sptr<ImsRegInfoCallback> imsRegInfoCallback = new ImsRegInfoCallbackGtest();
    ret = g_coreServiceClientPtr.RegisterImsRegInfoCallback(
        SIM1_SLOTID, ImsServiceType::TYPE_VOICE, imsRegInfoCallback);
    if (ret == TELEPHONY_SUCCESS) {
        std::cout << "RegisterImsRegInfoCallback success!" << std::endl;
        imsCallbackTokenIDVec_.push_back(currentTokenIDEx_);
        return;
    }
    std::cout << "RegisterImsRegInfoCallback fail!" << std::endl;
}

void UnRegisterImsRegInfoCallback()
{
    if (imsCallbackTokenIDVec_.empty()) {
        std::cout << "no callback need to unregister!";
        return;
    }
    int32_t ret = TELEPHONY_SUCCESS;
    std::cout << "Callback list: \n";
    for (int32_t i = 0; i < imsCallbackTokenIDVec_.size(); i++) {
        SetSelfTokenID(imsCallbackTokenIDVec_[i].tokenIDEx);
        std::cout << i << ": tokenId is " << GetSelfTokenID() << "\n";
    }
    std::cout << "Please select tokeId which you need unregister...\n";
    int32_t index = 0;
    std::cin >> index;
    AccessTokenIDEx currentIDEx = imsCallbackTokenIDVec_[index];
    SetSelfTokenID(currentIDEx.tokenIDEx);
    std::cout << "Selected tokenId is " << GetSelfTokenID() << std::endl;
    ret = g_coreServiceClientPtr.UnregisterImsRegInfoCallback(SIM1_SLOTID, ImsServiceType::TYPE_VOICE);
    if (ret == TELEPHONY_SUCCESS) {
        imsCallbackTokenIDVec_.erase(imsCallbackTokenIDVec_.begin() + index);
        AccessTokenKit::DeleteToken(currentIDEx.tokenIdExStruct.tokenID);
        SetSelfTokenID(currentThreadTokenId_);
        std::cout << "UnRegisterImsRegInfoCallback success!" << std::endl;
        return;
    }
    std::cout << "UnRegisterImsRegInfoCallback fail!" << std::endl;
}

void AddStateObserver()
{
    int32_t ret = TELEPHONY_SUCCESS;
    sptr<StateRegistryObserver> telephonyObserver = std::make_unique<StateRegistryObserver>().release();
    ret = g_observerDataClient.AddStateObserver(
        telephonyObserver, SIM1_SLOTID, Telephony::TelephonyObserverBroker::OBSERVER_MASK_NETWORK_STATE, true);
    if (ret == TELEPHONY_SUCCESS) {
        std::cout << "AddStateObserver success!" << std::endl;
        stateObserverTokenIDVec_.push_back(currentTokenIDEx_);
        return;
    }
    std::cout << "AddStateObserver fail!" << std::endl;
}

void RemoveStateObserver()
{
    if (stateObserverTokenIDVec_.empty()) {
        std::cout << "no callback need to unregister!";
        return;
    }
    int32_t ret = TELEPHONY_SUCCESS;
    std::cout << "Callback list: \n";
    for (int32_t i = 0; i < stateObserverTokenIDVec_.size(); i++) {
        SetSelfTokenID(stateObserverTokenIDVec_[i].tokenIDEx);
        std::cout << i << ": tokenId is " << GetSelfTokenID() << "\n";
    }
    std::cout << "Please select tokeId which you need unregister...\n";
    int32_t index = 0;
    std::cin >> index;
    AccessTokenIDEx currentIDEx = stateObserverTokenIDVec_[index];
    SetSelfTokenID(currentIDEx.tokenIDEx);
    std::cout << "Selected tokenId is " << GetSelfTokenID() << std::endl;
    ret = g_observerDataClient.RemoveStateObserver(
        SIM1_SLOTID, Telephony::TelephonyObserverBroker::OBSERVER_MASK_NETWORK_STATE);
    if (ret == TELEPHONY_SUCCESS) {
        stateObserverTokenIDVec_.erase(stateObserverTokenIDVec_.begin() + index);
        AccessTokenKit::DeleteToken(currentIDEx.tokenIdExStruct.tokenID);
        SetSelfTokenID(currentThreadTokenId_);
        std::cout << "RemoveStateObserver success!" << std::endl;
        return;
    }
    std::cout << "RemoveStateObserver fail!" << std::endl;
}

void InitCallBasicPower()
{
    g_memberFuncMap[static_cast<int32_t>(CoreServiceTestCode::REGISTER_SIM_ACCOUNT_CODE)] =
        &OHOS::Telephony::RegisterSimAccountCallback;
    g_memberFuncMap[static_cast<int32_t>(CoreServiceTestCode::UNREGISTER_SIM_ACCOUNT_CODE)] =
        &OHOS::Telephony::UnRegisterSimAccountCallback;
    g_memberFuncMap[static_cast<int32_t>(CoreServiceTestCode::REGISTER_IMS_REG_CODE)] =
        &OHOS::Telephony::RegisterImsRegInfoCallback;
    g_memberFuncMap[static_cast<int32_t>(CoreServiceTestCode::UNREGISTER_IMS_REG_CODE)] =
        &OHOS::Telephony::UnRegisterImsRegInfoCallback;
    g_memberFuncMap[static_cast<int32_t>(CoreServiceTestCode::ADD_STATE_OBSERVER)] = &OHOS::Telephony::AddStateObserver;
    g_memberFuncMap[static_cast<int32_t>(CoreServiceTestCode::REMOVE_STATE_OBSERVER)] =
        &OHOS::Telephony::RemoveStateObserver;
}

int32_t Init()
{
    if (g_coreServiceClientPtr.GetProxy() == nullptr) {
        std::cout << "\n--- telephonyService == nullptr\n" << std::endl;
        return 0;
    }
    if (g_cellularDataClient.GetProxy() == nullptr) {
        std::cout << "\n--- telephonyService == nullptr\n" << std::endl;
        return 0;
    }
    if (g_observerDataClient.GetProxy() == nullptr) {
        std::cout << "\n--- telephonyService == nullptr\n" << std::endl;
        return 0;
    }
    InitCallBasicPower();
    return TELEPHONY_SUCCESS;
}

void PrintfCallBasisInterface()
{
    std::cout << "\n\n-----------start--------------\n"
              << "usage:please input a cmd num:\n"
              << "1:register sim account callback\n"
              << "2:unregister sim account callback\n"
              << "3:register ims reg callback\n"
              << "4:unregister ims reg callback\n"
              << "5:add state observer\n"
              << "6:remove state observer\n";
}

void PrintfUsage()
{
    PrintfCallBasisInterface();
    std::cout << "1000:exit\n";
}

int32_t MainExit()
{
    if (!simAccountCallbackTokenIDVec_.empty()) {
        std::vector<AccessTokenIDEx>::iterator it = simAccountCallbackTokenIDVec_.begin();
        while (it != simAccountCallbackTokenIDVec_.end()) {
            simAccountCallbackTokenIDVec_.erase(it++);
        }
    }
    if (!imsCallbackTokenIDVec_.empty()) {
        std::vector<AccessTokenIDEx>::iterator it = imsCallbackTokenIDVec_.begin();
        while (it != imsCallbackTokenIDVec_.end()) {
            imsCallbackTokenIDVec_.erase(it++);
        }
    }
    if (!stateObserverTokenIDVec_.empty()) {
        std::vector<AccessTokenIDEx>::iterator it = stateObserverTokenIDVec_.begin();
        while (it != stateObserverTokenIDVec_.end()) {
            stateObserverTokenIDVec_.erase(it++);
        }
    }
    OHOS::Telephony::g_memberFuncMap.clear();
    std::cout << "exit success" << std::endl;
    return OHOS::Telephony::TELEPHONY_SUCCESS;
}

int32_t RunTest()
{
    std::cout << "coreService test start...." << std::endl;
    int32_t interfaceNum = DEFAULT_VALUE;
    const int32_t exitNumber = 1000;
    if (Init() != TELEPHONY_SUCCESS) {
        std::cout << "coreService test init failed!" << std::endl;
        return TELEPHONY_SUCCESS;
    }
    AccessToken token;
    while (true) {
        PrintfUsage();
        std::cin >> interfaceNum;
        if (interfaceNum == static_cast<int32_t>(CoreServiceTestCode::REGISTER_SIM_ACCOUNT_CODE) ||
            interfaceNum == static_cast<int32_t>(CoreServiceTestCode::REGISTER_IMS_REG_CODE) ||
            interfaceNum == static_cast<int32_t>(CoreServiceTestCode::ADD_STATE_OBSERVER)) {
            std::cout << "Please input instIndex..." << std::endl;
            int32_t index = DEFAULT_VALUE;
            std::cin >> index;
            testInfoParams.instIndex = index;
            std::cout << "Please input userId..." << std::endl;
            int32_t userId = DEFAULT_VALUE;
            std::cin >> userId;
            testInfoParams.userID = userId;
            AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParams, testPolicyParams);
            currentTokenIDEx_ = tokenIdEx;
            SetSelfTokenID(tokenIdEx.tokenIDEx);
            std::cout << "Current userId is: " << testInfoParams.userID << std::endl
                      << "bundleName is: " << testInfoParams.bundleName << std::endl
                      << "instIndex is: " << testInfoParams.instIndex << std::endl
                      << "tokenId is: " << GetSelfTokenID() << std::endl;
        }
        if (interfaceNum == exitNumber) {
            std::cout << "start to exit now...." << std::endl;
            break;
        }
        auto itFunc = g_memberFuncMap.find(interfaceNum);
        if (itFunc != g_memberFuncMap.end() && itFunc->second != nullptr) {
            auto memberFunc = itFunc->second;
            (*memberFunc)();
            continue;
        }
        std::cout << "err: invalid input!" << std::endl;
        break;
    }
    return MainExit();
}
} // namespace Telephony
} // namespace OHOS

int32_t main()
{
    int32_t code = OHOS::Telephony::DEFAULT_VALUE;
    const int32_t exitCode = 1000;
    std::cout << "Please select test type...." << std::endl;
    while (true) {
        std::cout << "1: Register callback\n"
                  << "1000:exit\n";
        std::cin >> code;
        if (code == static_cast<int32_t>(OHOS::Telephony::CallManagerInterfaceType::REGISTER_CALLBACK_TYPE)) {
            OHOS::Telephony::RunTest();
            OHOS::Telephony::MainExit();
        } else if (code == exitCode) {
            break;
        }
        std::cout << "err: invalid input!" << std::endl;
    }
    return OHOS::Telephony::TELEPHONY_SUCCESS;
}
