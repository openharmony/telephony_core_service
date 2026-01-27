/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ani_vcard.h"
#include "ani_base_context.h"
#include "wrapper.rs.h"
#include "cxx.h"
#include "napi_util.h"
#include "telephony_permission.h"
#include "vcard_manager.h"
#include "datashare_helper.h"
#include <memory>
#include <string>

using namespace std;

namespace OHOS {
namespace Telephony {
namespace VcardAni {
const std::string CONTACT_URI = "datashare:///com.ohos.contactsdataability";
constexpr int32_t DB_CONNECT_MAX_WAIT_TIME = 10;

static inline ArktsError ConvertArktsErrorWithPermission(int32_t errorCode, const std::string &funcName,
                                                         const std::string &permission)
{
    JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
        errorCode, funcName, permission);

    ArktsError ArktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return ArktsErr;
}

static inline ArktsError ConvertArktsError(int32_t errorCode)
{
    JsError error = NapiUtil::ConverErrorMessageForJs(errorCode);

    ArktsError arktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return arktsErr;
}

bool IsStageContext(AniEnv *env, AniObject *obj)
{
    if (env == nullptr || obj == nullptr) {
        return false;
    }
    ani_boolean stageMode;
    AbilityRuntime::IsStageContext(reinterpret_cast<ani_env *>(env), *reinterpret_cast<ani_object *>(obj), stageMode);
    return stageMode == 1;
}

std::shared_ptr<AbilityRuntime::Context> GetStageModeContext(AniEnv **env, AniObject *obj)
{
    if (env == nullptr || *env == nullptr || obj == nullptr) {
        return nullptr;
    }
    return AbilityRuntime::GetStageModeContext(reinterpret_cast<ani_env *>(*env), *reinterpret_cast<ani_object *>(obj));
}

ArktsError ImportVcard(std::shared_ptr<AbilityRuntime::Context> context, const rust::String filePath, int32_t accountId)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!TelephonyPermission::CheckPermission(Permission::WRITE_CONTACTS)) {
        errorCode = TELEPHONY_ERR_PERMISSION_ERR;
        return ConvertArktsErrorWithPermission(errorCode, "ImportVCard", Permission::WRITE_CONTACTS);
    }
    if (context == nullptr) {
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return ConvertArktsError(errorCode);
    }

    auto path = std::string(filePath);
    if (path.empty() || path.find("..") != std::string::npos || path.find("./")  != std::string::npos ||
        path.find("/./") != std::string::npos || path.find("/../") != std::string::npos) {
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return ConvertArktsError(errorCode);
    }

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(context->GetToken(), CONTACT_URI, "", DB_CONNECT_MAX_WAIT_TIME);
    if (dataShareHelper == nullptr) {
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return ConvertArktsError(errorCode);
    }

    errorCode = VCardManager::GetInstance().ImportLock(path, dataShareHelper, accountId);
    return ConvertArktsError(errorCode);
}

ArktsError ExportVcard(std::shared_ptr<AbilityRuntime::Context> context, int64_t dataSharePredicatesPtr,
    int32_t cardType, const rust::String charset, rust::String &filePath)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!TelephonyPermission::CheckPermission(Permission::READ_CONTACTS)) {
        errorCode = TELEPHONY_ERR_PERMISSION_ERR;
        return ConvertArktsErrorWithPermission(errorCode, "ExportVCard", Permission::READ_CONTACTS);
    }
    if (context == nullptr || dataSharePredicatesPtr == 0) {
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return ConvertArktsError(errorCode);
    }
    auto* predicatesPtr = reinterpret_cast<DataShare::DataSharePredicates*>(dataSharePredicatesPtr);
    if (predicatesPtr == nullptr) {
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return ConvertArktsError(errorCode);
    }

    std::string path = "";
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(context->GetToken(), CONTACT_URI, "", DB_CONNECT_MAX_WAIT_TIME);
    if (dataShareHelper == nullptr) {
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
        return ConvertArktsError(errorCode);
    }

    errorCode = VCardManager::GetInstance().ExportLock(path, dataShareHelper,
        *predicatesPtr, cardType, std::string(charset));
    if (errorCode == ERROR_NONE) {
        filePath = rust::String(path);
    }
    return ConvertArktsError(errorCode);
}
} // namespace VcardAni
} // namespace Telephony
} // namespace OHOS
 