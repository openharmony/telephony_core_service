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

#include "accesstoken_kit.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "privacy_kit.h"
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace Telephony {
using namespace Security::AccessToken;

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
    if (systemAbilityManager == nullptr) {
        TELEPHONY_LOGE("systemAbilityManager is nullptr");
        return false;
    }
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);

    sptr<AppExecFwk::IBundleMgr> iBundleMgr = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        TELEPHONY_LOGE("iBundleMgr is nullptr");
        return false;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    ErrCode errCode = iBundleMgr->GetNameForUid(uid, bundleName);
    IPCSkeleton::SetCallingIdentity(identity);
    if (errCode != ERR_OK) {
        TELEPHONY_LOGE("get name for uid failed, error code : %{public}d", errCode);
        return false;
    }
    return true;
}

/**
 * @brief Permission check by callingUid.
 * @param permissionName permission name.
 * @return Returns true on success, false on failure.
 */
bool TelephonyPermission::CheckPermission(const std::string &permissionName)
{
    if (permissionName.empty()) {
        TELEPHONY_LOGD("permission check failed, permission name is empty.");
        return false;
    }

    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    int result = AccessTokenKit::VerifyAccessToken(callerToken, permissionName);

    if (permissionName == Permission::ANSWER_CALL || permissionName == Permission::READ_CALL_LOG
        || permissionName == Permission::READ_CONTACTS || permissionName == Permission::WRITE_CONTACTS
        || permissionName == Permission::SEND_MESSAGES) {
        if (tokenType == ATokenTypeEnum::TOKEN_HAP) {
            bool status = result == PermissionState::PERMISSION_GRANTED;
            int32_t successCount = status ? 1 : 0;
            int32_t failCount = status ? 0 : 1;
            int32_t ret = PrivacyKit::AddPermissionUsedRecord(callerToken, permissionName, successCount, failCount);
            if (ret != 0) {
                TELEPHONY_LOGD("AddPermissionUsedRecord failed, permission:%{public}s, "
                    "successCount:%{public}d, failCount:%{public}d",
                    permissionName.c_str(), successCount, failCount);
            }
        }
    }

    if (result != PermissionState::PERMISSION_GRANTED) {
        TELEPHONY_LOGE("permission check failed, permission:%{public}s, callerToken:%{public}u, "
            "tokenType:%{public}d, pid:%{public}d",
            permissionName.c_str(), callerToken, tokenType, IPCSkeleton::GetCallingPid());
        return false;
    }
    return true;
}

bool TelephonyPermission::CheckCallerIsSystemApp()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        TELEPHONY_LOGD("tokenType check passed.");
        return true;
    }

    auto selfToken = IPCSkeleton::GetCallingFullTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}
} // namespace Telephony
} // namespace OHOS
