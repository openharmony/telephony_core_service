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
#ifndef OHOS_SIM_TEST_UTIL_H
#define OHOS_SIM_TEST_UTIL_H

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "core_service_client.h"
#include "core_service_test_helper.h"
#include "token_setproc.h"
#include "operator_config_cache.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

inline HapInfoParams testInfoParams = {
    .bundleName = "tel_core_service_gtest",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true,
};

inline PermissionDef testPermGetTelephonyStateDef = {
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testGetTelephonyState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .resDeviceID = { "local" },
};

inline PermissionDef testPermSetTelephonyStateDef = {
    .permissionName = "ohos.permission.SET_TELEPHONY_STATE",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testSetTelephonyState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.SET_TELEPHONY_STATE",
    .resDeviceID = { "local" },
};

inline PermissionDef testPermGetNetworkInfoDef = {
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testPermGetNetworkInfo = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .resDeviceID = { "local" },
};

inline PermissionDef testSimPermWriteContactsDef  = {
    .permissionName = "ohos.permission.WRITE_CONTACTS",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testSimPermWriteContacts = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.WRITE_CONTACTS",
    .resDeviceID = { "local" },
};

inline PermissionDef testSimPermReadContactsDef = {
    .permissionName = "ohos.permission.READ_CONTACTS",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testSimPermReadContacts = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.READ_CONTACTS",
    .resDeviceID = { "local" },
};

inline HapPolicyParams testPolicyParams = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = { testPermGetTelephonyStateDef, testPermSetTelephonyStateDef, testPermGetNetworkInfoDef,
        testSimPermWriteContactsDef, testSimPermReadContactsDef },
    .permStateList = { testGetTelephonyState, testSetTelephonyState, testPermGetNetworkInfo, testSimPermWriteContacts,
        testSimPermReadContacts },
};

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParams, testPolicyParams);
        accessID_ = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(tokenIdEx.tokenIDEx);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }

private:
    AccessTokenID currentID_ = 0;
    AccessTokenID accessID_ = 0;
};

class SimTest : public testing::Test {
public:
    // execute before first testcase
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    bool ParseOperatorConf(int32_t slotId);
    static void InitBroadCast();
    static void TearDownTestCase();
    static sptr<ICoreService> GetProxy();
    static bool HasSimCard(int32_t slotId);
    static sptr<ICoreService> telephonyService_;
    static const int32_t slotId_ = 0;
    static const int32_t slotId1_ = 1;
    static const int32_t slotIdErr_ = -1;
    static const int32_t simId = 1;

private:
    static void CompareOperatorConfProcess(OperatorConfig poc);
    static void QueryIccAdnDiallingNumbersTestFunc(CoreServiceTestHelper &helper);
    static void QueryIccAdnDiallingNumbersTestFunc1(CoreServiceTestHelper &helper);
    static void QueryIccFdnDiallingNumbersTestFunc(CoreServiceTestHelper &helper);
    static void QueryIccFdnDiallingNumbersTestFunc1(CoreServiceTestHelper &helper);
    static void SetLockStateTestFunc(CoreServiceTestHelper &helper);
    static void SetLockStateTestFunc1(CoreServiceTestHelper &helper);
    static void SetFDNStateTestFunc(CoreServiceTestHelper &helper);
    static void SetFDNStateTestFunc1(CoreServiceTestHelper &helper);
    static void GetLockStateTestFunc(CoreServiceTestHelper &helper);
    static void GetLockStateTestFunc1(CoreServiceTestHelper &helper);
    static void GetFDNStateTestFunc(CoreServiceTestHelper &helper);
    static void GetFDNStateTestFunc1(CoreServiceTestHelper &helper);
    static void UnlockPinTestFunc(CoreServiceTestHelper &helper);
    static void UnlockPinTestFunc1(CoreServiceTestHelper &helper);
    static void UnlockPukTestFunc(CoreServiceTestHelper &helper);
    static void UnlockPukTestFunc1(CoreServiceTestHelper &helper);
    static void AlterPinTestFunc(CoreServiceTestHelper &helper);
    static void AlterPinTestFunc1(CoreServiceTestHelper &helper);
    static void UnlockPin2TestFunc(CoreServiceTestHelper &helper);
    static void UnlockPin2TestFunc1(CoreServiceTestHelper &helper);
    static void UnlockPuk2TestFunc(CoreServiceTestHelper &helper);
    static void UnlockPuk2TestFunc1(CoreServiceTestHelper &helper);
    static void AlterPin2TestFunc(CoreServiceTestHelper &helper);
    static void AlterPin2TestFunc1(CoreServiceTestHelper &helper);
    static void SetActiveSimTestFunc(CoreServiceTestHelper &helper);
    static void SetActiveSimTestFunc1(CoreServiceTestHelper &helper);
    static void ReSetActiveSimTestFunc(CoreServiceTestHelper &helper);
    static void ReSetActiveSimTestFunc1(CoreServiceTestHelper &helper);
    static void SetActiveSimSatelliteTestFunc(CoreServiceTestHelper &helper);
    static void SetActiveSimSatelliteTestFunc1(CoreServiceTestHelper &helper);
    static void ReSetActiveSimSatelliteTestFunc(CoreServiceTestHelper &helper);
    static void ReSetActiveSimSatelliteTestFunc1(CoreServiceTestHelper &helper);
    static void HasOperatorPrivileges(CoreServiceTestHelper &helper);
    static void HasOperatorPrivileges1(CoreServiceTestHelper &helper);
    static void UnlockSimLockTestFunc(CoreServiceTestHelper &helper);
    static void UnlockSimLockTestFunc1(CoreServiceTestHelper &helper);
    static void SimAuthenticationTestFunc(CoreServiceTestHelper &helper);
    static void SimAuthenticationTestFunc1(CoreServiceTestHelper &helper);
    static void SimAuthenticationTestFunc2(CoreServiceTestHelper &helper);
    static void SimAuthenticationTestFunc3(CoreServiceTestHelper &helper);
    static void SendTerminalResponseCmdTestFunc(CoreServiceTestHelper &helper);
    static void SendTerminalResponseCmdTestFunc1(CoreServiceTestHelper &helper);
    static void SendEnvelopeCmdTestFunc(CoreServiceTestHelper &helper);
    static void SendEnvelopeCmdTestFunc1(CoreServiceTestHelper &helper);
    static void SendCallSetupRequestResultTestFunc(CoreServiceTestHelper &helper);
    static void SendCallSetupRequestResultTestFunc1(CoreServiceTestHelper &helper);
    static void SetVoiceMailInfoTestFunc(CoreServiceTestHelper &helper);
    static void SetVoiceMailInfoTestFunc1(CoreServiceTestHelper &helper);
    static std::shared_ptr<OperatorConfigCache> CreateOperatorConfigCache(int32_t slotId);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_TEST_UTIL_H
