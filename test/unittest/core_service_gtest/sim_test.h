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

#ifndef SIM_TEST_H
#define SIM_TEST_H

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "core_service_client.h"
#include "token_setproc.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

HapInfoParams testInfoParams = {
    .bundleName = "tel_core_service_gtest",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "test",
};

PermissionDef testPermGetTelephonyStateDef = {
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

PermissionStateFull testGetTelephonyState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .resDeviceID = { "local" },
};

PermissionDef testPermSetTelephonyStateDef = {
    .permissionName = "ohos.permission.SET_TELEPHONY_STATE",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

PermissionStateFull testSetTelephonyState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.SET_TELEPHONY_STATE",
    .resDeviceID = { "local" },
};

PermissionDef testPermGetNetworkInfoDef = {
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

PermissionStateFull testPermGetNetworkInfo = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .resDeviceID = { "local" },
};

PermissionDef testSimPermWriteContactsDef = {
    .permissionName = "ohos.permission.WRITE_CONTACTS",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

PermissionStateFull testSimPermWriteContacts = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.WRITE_CONTACTS",
    .resDeviceID = { "local" },
};

PermissionDef testSimPermReadContacts = {
    .permissionName = "ohos.permission.READ_CONTACTS",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test core service",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

PermissionStateFull testSimPermReadContacts = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.READ_CONTACTS",
    .resDeviceID = { "local" },
};

HapPolicyParams testPolicyParams = {
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
        SetSelfTokenID(accessID_);
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
    void ParseOperatorConf(int32_t slotId);
    static void InitBroadCast();
    static void TearDownTestCase();
    static sptr<ICoreService> GetProxy();
    static sptr<ICoreService> telephonyService_;
    static const int32_t slotId_ = 0;
    static const int32_t slotId1_ = 1;
    static const int32_t slotIdErr_ = -1;
    static const int32_t simId = 1;
};
} // namespace Telephony
} // namespace OHOS
#endif // SIM_TEST_H
