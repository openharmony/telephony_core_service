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

#include "telephony_permission.h"

#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "permission/permission.h"
#include "permission/permission_kit.h"
#include "system_ability_definition.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Permission check by callingUid.
 * @param permissionName permission name.
 * @return Returns true on success, false on failure.
 */
bool TelephonyPermission::CheckPermission(const std::string &permissionName)
{
#ifdef IS_SUPPORT_PERMISSION
    if (permissionName.empty()) {
        TELEPHONY_LOGE("permission check failed，permission name is empty.");
        return false;
    }

    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);

    sptr<AppExecFwk::IBundleMgr> iBundleMgr = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        TELEPHONY_LOGE(" permission check failed, cannot get IBundleMgr.");
        return false;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    std::string bundleName;
    bool result = iBundleMgr->GetBundleNameForUid(uid, bundleName);
    if (!result || bundleName.empty()) {
        TELEPHONY_LOGE("permission check failed, cannot get bundle name by uid:%{public}d", uid);
        return false;
    }

    result = OHOS::Security::Permission::PermissionKit::VerifyPermission(bundleName, permissionName, 0);
    if (result != OHOS::Security::Permission::PermissionState::PERMISSION_GRANTED) {
        TELEPHONY_LOGW("permission = %{public}s, bundleName = %{public}s, result = %{public}d",
            permissionName.c_str(), bundleName.c_str(), result);
    }

    return result == OHOS::Security::Permission::PermissionState::PERMISSION_GRANTED;
#else
    return true;
#endif
}

/**
 * @brief Permission check by callingUid.
 * @param bundleName .
 * @param permissionName permission name.
 * @return Returns true on success, false on failure.
 */
bool TelephonyPermission::CheckPermission(
    const std::string &bundleName, const std::string &permissionName)
{
#ifndef SUPPORT_PERMISSION
    return true;
#endif
    if (bundleName.empty()) {
        TELEPHONY_LOGE("permission check failed，bundleName is empty.");
        return false;
    }

    bool result = OHOS::Security::Permission::PermissionKit::VerifyPermission(bundleName, permissionName, 0);
    if (result != OHOS::Security::Permission::PermissionState::PERMISSION_GRANTED) {
        TELEPHONY_LOGW("permission = %{public}s, bundleName = %{public}s, result = %{public}d",
                       permissionName.c_str(), bundleName.c_str(), result);
    }

    return result == OHOS::Security::Permission::PermissionState::PERMISSION_GRANTED;
}
} // namespace Telephony
} // namespace OHOS