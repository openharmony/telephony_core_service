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

#ifndef NETWORK_SEARCH_MANAGER_TEST_H
#define NETWORK_SEARCH_MANAGER_TEST_H

#include <gtest/gtest.h>
#include <list>

#include "accesstoken_kit.h"
#include "core_service_client.h"
#include "core_manager_inner.h"
#include "token_setproc.h"

namespace OHOS {
namespace Telephony {
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

inline HapInfoParams testNetInfoParams = {
    .bundleName = "tel_core_service_gtest",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true,
};

inline PermissionDef testNetPermLocationDef = {
    .permissionName = "ohos.permission.LOCATION",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test network search",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testNetPermLocation = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.LOCATION",
    .resDeviceID = { "local" },
};

inline PermissionDef testNetPermGetTelephonyStateDef = {
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test network search",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testNetGetTelephonyState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.GET_TELEPHONY_STATE",
    .resDeviceID = { "local" },
};

inline PermissionDef testNetPermSetTelephonyStateDef = {
    .permissionName = "ohos.permission.SET_TELEPHONY_STATE",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test network search",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testNetSetTelephonyState = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.SET_TELEPHONY_STATE",
    .resDeviceID = { "local" },
};

inline PermissionDef testNetPermGetNetworkInfoDef = {
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test network search",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testNetPermGetNetworkInfo = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .resDeviceID = { "local" },
};

inline PermissionDef testPermReadContactsDef = {
    .permissionName = "ohos.permission.READ_CONTACTS",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test network search",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testPermReadContacts = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.READ_CONTACTS",
    .resDeviceID = { "local" },
};

inline PermissionDef testPermWriteContactsDef = {
    .permissionName = "ohos.permission.WRITE_CONTACTS",
    .bundleName = "tel_core_service_gtest",
    .grantMode = 1, // SYSTEM_GRANT
    .label = "label",
    .labelId = 1,
    .description = "Test network search",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

inline PermissionStateFull testPermWriteContacts = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.WRITE_CONTACTS",
    .resDeviceID = { "local" },
};

inline PermissionStateFull testPermSecureSettings = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.MANAGE_SECURE_SETTINGS",
    .resDeviceID = { "local" },
};

inline PermissionStateFull testPermManagerSettings = {
    .grantFlags = { 2 }, // PERMISSION_USER_SET
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.MANAGE_SETTINGS",
    .resDeviceID = { "local" },
};

inline HapPolicyParams testNetPolicyParams = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = { testNetPermLocationDef, testNetPermGetTelephonyStateDef, testNetPermSetTelephonyStateDef,
        testNetPermGetNetworkInfoDef, testPermReadContactsDef, testPermWriteContactsDef },
    .permStateList = { testNetPermLocation, testNetGetTelephonyState, testNetSetTelephonyState,
        testNetPermGetNetworkInfo, testPermReadContacts, testPermWriteContacts },
};

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testNetInfoParams, testNetPolicyParams);
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
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_MANAGER_TEST_H
