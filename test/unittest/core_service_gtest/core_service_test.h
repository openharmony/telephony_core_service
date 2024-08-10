/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_CORE_SERVICE_TEST_H
#define OHOS_CORE_SERVICE_TEST_H
#include "security_token.h"

#include <iostream>

#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Telephony {
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;
inline HapInfoParams testInfoParams = {
    .bundleName = "tel_core_service_gtest",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = false,
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

inline PermissionDef testSimPermWriteContactsDef = {
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

SecurityToken::SecurityToken()
{
    currentID_ = GetSelfTokenID();
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParams, testPolicyParams);
    accessID_ = tokenIdEx.tokenIdExStruct.tokenID;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

SecurityToken::~SecurityToken()
{
    AccessTokenKit::DeleteToken(accessID_);
    SetSelfTokenID(currentID_);
}
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_CORE_SERVICE_TEST_H