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
#include "accesstoken_kit.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Get bundleName by callingUid.
 * @param callingUid.
 * @param bundleName.
 * @return Returns true on success, false on failure.
 */
bool TelephonyPermission::GetBundleNameByUid(int32_t uid, std::string &bundleName)
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);

    sptr<AppExecFwk::IBundleMgr> iBundleMgr = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        TELEPHONY_LOGE(" permission check failed, cannot get IBundleMgr.");
        return false;
    }
    return iBundleMgr->GetBundleNameForUid(uid, bundleName);
}

/**
 * @brief Permission check by callingUid.
 * @param permissionName permission name.
 * @return Returns true on success, false on failure.
 */
bool TelephonyPermission::CheckPermission(const std::string &permissionName)
{
    if (permissionName.empty()) {
        TELEPHONY_LOGE("permission check failed，permission name is empty.");
        return false;
    }

    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    int result = Security::AccessToken::PERMISSION_DENIED;

    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        result = Security::AccessToken::AccessTokenKit::VerifyNativeToken(callerToken, permissionName);
    } else if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    } else {
        TELEPHONY_LOGE("permission check failed, callerToken:%{public}u, tokenType:%{public}d",
            callerToken, tokenType);
    }

    if (result != Security::AccessToken::PERMISSION_GRANTED) {
        TELEPHONY_LOGE("permission check failed, permission:%{public}s, callerToken:%{public}u, tokenType:%{public}d",
            permissionName.c_str(), callerToken, tokenType);
        return false;
    }
    return true;
}
} // namespace Telephony
} // namespace OHOS