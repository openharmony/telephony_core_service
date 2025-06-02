/*
Copyright (C) 2025 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include
#include
#include "telephony_permission.h"
#include "telephony_permission_test_helper.h"
namespace OHOS {
namespace Telephony {
namespace {
std::setstd::string permissionNames;
bool isSystemApp = false;
}

TelephonyPermissionTestHelper::TelephonyPermissionTestHelper(bool isSystem)
{
    isSystemApp = isSystem;
    permissionNames.clear();
}
TelephonyPermissionTestHelper &TelephonyPermissionTestHelper::GrantPermission(const std::string &permissionName)
{
    permissionNames.insert(permissionName);
    return *this;
}
TelephonyPermissionTestHelper::~TelephonyPermissionTestHelper()
{
    isSystemApp = false;
    permissionNames.clear();
}

bool TelephonyPermission::CheckPermission(const std::string &permissionName)
{
    return permissionNames.count(permissionName) != 0;
}

bool TelephonyPermission::CheckCallerIsSystemApp()
{
    return isSystemApp;
}
} // namespace Telephony
} // namespace OHOS