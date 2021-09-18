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

#include <unistd.h>

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "core_service_proxy.h"
#include "core_manager.h"
#include "test_broadcast.h"
#include "network_search_test_callback_stub.h"

namespace OHOS {
namespace Telephony {
using namespace OHOS::EventFwk;
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
const int32_t INPUT_GET_NETWORK_SEARCH_RESULT = 9;
const int32_t INPUT_GET_NETWORK_SELECTION_MODE = 10;
const int32_t INPUT_SET_NETWORK_SELECTION_MODE = 11;
const int32_t INPUT_GET_IOS_COUNTRY_CODE = 14;
const int32_t INPUT_QUIT = 100;
const int32_t SLEEP_TIME = 5;
using NsTestFunc = void (*)();
std::map<int32_t, NsTestFunc> memberFuncMap_;
std::shared_ptr<TestBroadCast> subscriber = nullptr;
sptr<ICoreService> GetProxy()
{
    TELEPHONY_LOGI("TelephonyTestService GetProxy ... ");
    sptr<ISystemAbilityManager> systemAbilityMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGE("TelephonyTestService Get ISystemAbilityManager failed ... ");
        return nullptr;
    }

    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote) {
        sptr<ICoreService> telephonyService = iface_cast<ICoreService>(remote);
        TELEPHONY_LOGI("TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID success ... ");
        return telephonyService;
    } else {
        TELEPHONY_LOGE("TelephonyTestService Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail ... ");
        return nullptr;
    }
}

void TestGetNetworkState()
{
    TELEPHONY_LOGI("TelephonyTestService Remote GetNetworkState");
    sptr<NetworkState> result = g_telephonyService->GetNetworkState(CoreManager::DEFAULT_SLOT_ID);
    if (result == nullptr) {
        TELEPHONY_LOGE("result is null");
    } else {
        TELEPHONY_LOGI("CoreServiceProxy::GetNetworkState return");
        TELEPHONY_LOGI("GetRegStatus():%{public}d", result->GetRegStatus());
        TELEPHONY_LOGI("GetLongOperatorName():%{public}s", result->GetLongOperatorName().c_str());
        TELEPHONY_LOGI("GetShortOperatorName():%{public}s", result->GetShortOperatorName().c_str());
        TELEPHONY_LOGI("GetPlmnNumeric():%{public}s", result->GetPlmnNumeric().c_str());
        TELEPHONY_LOGI("GetPsRoamingStatus():%{public}d", result->GetPsRoamingStatus());
        TELEPHONY_LOGI("GetCsRoamingStatus():%{public}d", result->GetCsRoamingStatus());
    }
}

void TestGetPsRadioTech()
{
    int32_t result = g_telephonyService->GetPsRadioTech(CoreManager::DEFAULT_SLOT_ID);
    TELEPHONY_LOGI("TelephonyTestService Remote GetPsRadioTech result:%{public}d", result);
}

void TestGetCsRadioTech()
{
    int32_t result = g_telephonyService->GetCsRadioTech(CoreManager::DEFAULT_SLOT_ID);
    TELEPHONY_LOGI("TelephonyTestService Remote GetCsRadioTech result:%{public}d", result);
}

void TestGetOperatorNumeric()
{
    std::u16string result = g_telephonyService->GetOperatorNumeric(CoreManager::DEFAULT_SLOT_ID);
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("TelephonyTestService Remote GetOperatorNumeric result:%{public}s", str.c_str());
}

void TestGetOperatorName()
{
    std::u16string result = g_telephonyService->GetOperatorName(CoreManager::DEFAULT_SLOT_ID);
    std::string str = Str16ToStr8(result);
    TELEPHONY_LOGI("TelephonyTestService Remote GetOperatorName result:%{public}s", str.c_str());
}

void TestGsmSignalInformation(const GsmSignalInformation &gsm)
{
    TELEPHONY_LOGD("TelephonyTestService Remote GsmSignalInformation ToString:%{public}s", gsm.ToString().c_str());
    TELEPHONY_LOGD("TelephonyTestService Remote GsmSignalInformation GetRssi:%{public}d", gsm.GetRssi());
    TELEPHONY_LOGD(
        "TelephonyTestService Remote GsmSignalInformation GetSignalLevel:%{public}d", gsm.GetSignalLevel());
    TELEPHONY_LOGD("TelephonyTestService Remote GsmSignalInformation GetBitErrorRate:%{public}d", gsm.GetGsmBer());
    TELEPHONY_LOGD("TelephonyTestService Remote GsmSignalInformation GetNetworkType[GSM] \n");
}

void TestCdmaSignalInformation(const CdmaSignalInformation &cdma)
{
    TELEPHONY_LOGD(
        "TelephonyTestService Remote CdmaSignalInformation ToString:%{public}s", cdma.ToString().c_str());
    TELEPHONY_LOGD("TelephonyTestService Remote CdmaSignalInformation GetCdmaRssi:%{public}d", cdma.GetCdmaRssi());
    TELEPHONY_LOGD(
        "TelephonyTestService Remote CdmaSignalInformation GetSignalLevel:%{public}d", cdma.GetSignalLevel());
    TELEPHONY_LOGD("TelephonyTestService Remote CdmaSignalInformation GetNetworkType[CDMA] \n");
}

void TestLteSignalInformation(const LteSignalInformation &lte)
{
    TELEPHONY_LOGD("TelephonyTestService Remote LteSignalInformation ToString:%{public}s", lte.ToString().c_str());
    TELEPHONY_LOGD("TelephonyTestService Remote LteSignalInformation GetLteRsrp:%{public}d", lte.GetRsrp());
    TELEPHONY_LOGD("TelephonyTestService Remote LteSignalInformation GetLteRxlev:%{public}d", lte.GetRxlev());
    TELEPHONY_LOGD("TelephonyTestService Remote LteSignalInformation GetLteRsrq:%{public}d", lte.GetRsrq());
    TELEPHONY_LOGD("TelephonyTestService Remote LteSignalInformation GetLteSnr:%{public}d", lte.GetSnr());
    TELEPHONY_LOGD(
        "TelephonyTestService Remote LteSignalInformation GetSignalLevel:%{public}d", lte.GetSignalLevel());
    TELEPHONY_LOGD("TelephonyTestService Remote LteSignalInformation GetNetworkType[LTE] \n");
}

void TestWcdmaSignalInformation(const WcdmaSignalInformation &wcdma)
{
    TELEPHONY_LOGD(
        "TelephonyTestService Remote WcdmaSignalInformation ToString:%{public}s", wcdma.ToString().c_str());
    TELEPHONY_LOGD("TelephonyTestService Remote WcdmaSignalInformation GetwcdmaRscp:%{public}d", wcdma.GetRscp());
    TELEPHONY_LOGD("TelephonyTestService Remote WcdmaSignalInformation GetRxlev:%{public}d", wcdma.GetRxlev());
    TELEPHONY_LOGD("TelephonyTestService Remote WcdmaSignalInformation GetwcdmaEcio:%{public}d", wcdma.GetEcno());
    TELEPHONY_LOGD("TelephonyTestService Remote WcdmaSignalInformation GetwcdmaBer:%{public}d", wcdma.GetBer());
    TELEPHONY_LOGD(
        "TelephonyTestService Remote WcdmaSignalInformation GetSignalLevel:%{public}d", wcdma.GetSignalLevel());
    TELEPHONY_LOGD("TelephonyTestService Remote WcdmaSignalInformation GetNetworkType[WCDMA] \n");
}

void TestGetSignalInfoList()
{
    auto result = g_telephonyService->GetSignalInfoList(CoreManager::DEFAULT_SLOT_ID);
    SignalInformation::NetworkType type;
    for (const auto &v : result) {
        type = v->GetNetworkType();
        TELEPHONY_LOGI("TelephonyTestService Remote SignalInformation result NetworkTypeId:%{public}d",
            static_cast<int32_t>(type));
        if (type == SignalInformation::NetworkType::GSM) {
            GsmSignalInformation *gsm = reinterpret_cast<GsmSignalInformation *>(v.GetRefPtr());
            TestGsmSignalInformation(*gsm);
        } else if (type == SignalInformation::NetworkType::CDMA) {
            CdmaSignalInformation *cdma = reinterpret_cast<CdmaSignalInformation *>(v.GetRefPtr());
            TestCdmaSignalInformation(*cdma);
        } else if (type == SignalInformation::NetworkType::LTE) {
            LteSignalInformation *lte = reinterpret_cast<LteSignalInformation *>(v.GetRefPtr());
            TestLteSignalInformation(*lte);
        } else if (type == SignalInformation::NetworkType::WCDMA) {
            WcdmaSignalInformation *wcdma = reinterpret_cast<WcdmaSignalInformation *>(v.GetRefPtr());
            TestWcdmaSignalInformation(*wcdma);
        }
    }
    TELEPHONY_LOGI("TelephonyTestService Remote TestGetSignalInfoList size:%{public}zu", result.size());
}

void TestSetRadioState()
{
    std::cout << "please input radio state off(0) or on(1)" << std::endl;
    int inputState = 0;
    std::cin >> inputState;
    bool isOn = true;
    if (inputState == 0) {
        isOn = false;
    }
    TELEPHONY_LOGD("radio off(N) or on(Y) :%{public}d", isOn);
    OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    bool result = g_telephonyService->SetRadioState(isOn, callback);
    TELEPHONY_LOGD("TelephonyTestService Remote SetRadioState result:%{public}d", inputState);
    TELEPHONY_LOGI("TelephonyTestService::TestSetRadioState result:%{public}d", result);
}

void TestGetRadioState()
{
    OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    int32_t result = g_telephonyService->GetRadioState(callback);
    TELEPHONY_LOGI("TelephonyTestService Remote GetRadioState result:%{public}d", result);
}

void TestNotifyNetworkStateChange()
{
    TestGetCsRadioTech();
    sleep(SLEEP_TIME);
    TestGetOperatorNumeric();
    bool isOn = true;
    OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
    g_telephonyService->SetRadioState(isOn, callback);
}

void TestGetNetworkSearchResult()
{
    if (g_telephonyService != nullptr) {
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool result = g_telephonyService->GetNetworkSearchResult(CoreManager::DEFAULT_SLOT_ID, callback);
        TELEPHONY_LOGI("TelephonyTestService::TestGetNetworkSearchResult result:%{public}d", result);
    }
}

void TestGetNetworkSelectionMode()
{
    if (g_telephonyService != nullptr) {
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool result = g_telephonyService->GetNetworkSelectionMode(CoreManager::DEFAULT_SLOT_ID, callback);
        TELEPHONY_LOGI("TelephonyTestService::TestGetNetworkSelectionMode result:%{public}d", result);
    }
}

void TestSetNetworkSelectionMode()
{
    if (g_telephonyService != nullptr) {
        sptr<NetworkInformation> networkInfo = new (std::nothrow) NetworkInformation();
        int32_t selectionMode = 1;
        bool isUpdateDatabase = true;
        std::cout << "please enter the selectionMode (0:Automatic mode , 1:Manual mode) :";
        std::cin >> selectionMode;
        networkInfo->SetOperateInformation(
            "CHINA MOBILE", "CMCC", "46000", NETWORK_PLMN_STATE_AVAILABLE, NETWORK_LTE);
        OHOS::sptr<NetworkSearchTestCallbackStub> callback(new NetworkSearchTestCallbackStub());
        bool result = g_telephonyService->SetNetworkSelectionMode(
            CoreManager::DEFAULT_SLOT_ID, selectionMode, networkInfo, isUpdateDatabase, callback);
        TELEPHONY_LOGI("TelephonyTestService::TestSetNetworkSelectionMode result:%{public}d", result);
    }
}

void TestGetIsoCountryCodeForNetwork()
{
    if (g_telephonyService != nullptr) {
        std::u16string result = g_telephonyService->GetIsoCountryCodeForNetwork(CoreManager::DEFAULT_SLOT_ID);
        std::string str = Str16ToStr8(result);
        TELEPHONY_LOGI("TestGetIsoCountryCodeForNetwork result:%{public}s", str.c_str());
    }
}

void Prompt()
{
    printf(
        "\n-----------start test remote api--------------\n"
        "usage:please input a cmd num:\n"
        "0:GetPsRadioTech\n"
        "1:GetCsRadioTech\n"
        "2:GetOperatorNumeric\n"
        "3:GetNetworkState\n"
        "4:GetOperatorName\n"
        "5:GetSignalInfoList\n"
        "6:SetRadioState\n"
        "7:GetRadioState\n"
        "8:NotifyNetworkStateChange\n"
        "9:GetNetworkSearchResult\n"
        "10:GetNetworkSelectionMode\n"
        "11:SetNetworkSelectionMode\n"
        "14:GetIsoCountryCodeForNetwork\n"
        "100:exit \n");
}

void ProcessInput(bool &loopFlag)
{
    int inputCMD = 0;
    std::cin >> inputCMD;
    while (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore();
        TELEPHONY_LOGI("Input error, please input again\n");
        std::cin >> inputCMD;
    }
    auto itFunc = memberFuncMap_.find(inputCMD);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (*memberFunc)();
            return;
        }
    }
    TELEPHONY_LOGI("inputCMD is:[%{public}d]", inputCMD);
    switch (inputCMD) {
        case INPUT_QUIT: {
            loopFlag = false;
            TELEPHONY_LOGI("exit...");
            break;
        }
        default:
            TELEPHONY_LOGI("please input correct number...");
            break;
    }
}

void TestInputQuit(bool &loopFlag)
{
    loopFlag = false;
}

void Init()
{
    memberFuncMap_[INPUT_GET_PS_RADIO_TECH] = TestGetPsRadioTech;
    memberFuncMap_[INPUT_GET_CS_RADIO_TECH] = TestGetCsRadioTech;
    memberFuncMap_[INPUT_GET_OPERATOR_NUMERIC] = TestGetOperatorNumeric;
    memberFuncMap_[INPUT_GET_NETWORK_STATE] = TestGetNetworkState;
    memberFuncMap_[INPUT_GET_OPERATOR_NAME] = TestGetOperatorName;
    memberFuncMap_[INPUT_GET_SIGNAL_INFO_LIST] = TestGetSignalInfoList;
    memberFuncMap_[INPUT_SET_RADIO_STATE] = TestSetRadioState;
    memberFuncMap_[INPUT_GET_RADIO_STATE] = TestGetRadioState;
    memberFuncMap_[INPUT_NOTIFY_NETWORK_CHANGE] = TestNotifyNetworkStateChange;
    memberFuncMap_[INPUT_GET_NETWORK_SEARCH_RESULT] = TestGetNetworkSearchResult;
    memberFuncMap_[INPUT_GET_NETWORK_SELECTION_MODE] = TestGetNetworkSelectionMode;
    memberFuncMap_[INPUT_SET_NETWORK_SELECTION_MODE] = TestSetNetworkSelectionMode;
    memberFuncMap_[INPUT_GET_IOS_COUNTRY_CODE] = TestGetIsoCountryCodeForNetwork;
}

void InitBroadCast()
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent("usual.event.SPN_INFO_UPDATED");
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(1);
    subscriber = std::make_shared<TestBroadCast>(subscribeInfo);
    CommonEventManager::SubscribeCommonEvent(subscriber);
}
} // namespace Telephony
} // namespace OHOS

using namespace OHOS::Telephony;
using namespace OHOS::EventFwk;
int main()
{
    Init();
    g_telephonyService = GetProxy();
    if (g_telephonyService == nullptr) {
        return 1;
    }
    InitBroadCast();
    bool loopFlag = true;
    while (loopFlag) {
        Prompt();
        ProcessInput(loopFlag);
    }
    TELEPHONY_LOGI("...exit test...");
}
