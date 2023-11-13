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

#include "napi_vcard.h"

#include <memory>

#include "ability.h"
#include "core_service_client.h"
#include "iostream"
#include "napi_parameter_util.h"
#include "napi_util.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"
#include "vcard_manager.h"

namespace OHOS {
namespace Telephony {
namespace {
const int32_t ARGS_ONE = 1;
constexpr int32_t NORMAL_STRING_SIZE = 101;
static const int32_t DEFAULT_REF_COUNT = 1;
const std::string CONTACT_URI = "datashare:///com.ohos.contactsdataability";
const std::string PERMISSION_READ_CONTACTS = "ohos.permission.READ_CONTACTS";
const std::string PERMISSION_WRITE_CONTACTS = "ohos.permission.WRITE_CONTACTS";

static napi_value CreateEnumConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    napi_value global = nullptr;
    napi_get_global(env, &global);
    return thisArg;
}

std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelper(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    bool isStageMode = false;
    napi_status status = AbilityRuntime::IsStageContext(env, argv[0], isStageMode);
    if (status != napi_ok || !isStageMode) {
        auto ability = AbilityRuntime::GetCurrentAbility(env);
        if (ability == nullptr) {
            TELEPHONY_LOGE("Failed to get native ability instance");
            return nullptr;
        }
        auto context = ability->GetContext();
        if (context == nullptr) {
            TELEPHONY_LOGE("Failed to get native context instance");
            return nullptr;
        }
        dataShareHelper = DataShare::DataShareHelper::Creator(context->GetToken(), CONTACT_URI);
    } else {
        auto context = AbilityRuntime::GetStageModeContext(env, argv[0]);
        if (context == nullptr) {
            TELEPHONY_LOGE("Failed to get native stage context instance");
            return nullptr;
        }
        dataShareHelper = DataShare::DataShareHelper::Creator(context->GetToken(), CONTACT_URI);
        if (context->GetToken() == nullptr) {
            TELEPHONY_LOGE("Failed to get native GetToken instance");
        }
        if (dataShareHelper == nullptr) {
            TELEPHONY_LOGE("Failed to get native dataShareHelper instance");
        }
    }
    return dataShareHelper;
}

bool MatchImportParameters(
    napi_env env, napi_value parameters[], size_t parameterCount, bool &hasAccountId, bool &hasCallback)
{
    if (parameterCount == TWO_PARAMETERS) {
        return NapiUtil::MatchParameters(env, parameters, { napi_object, napi_string });
    } else if (parameterCount == THREE_PARAMETERS) {
        bool typeMatch = NapiUtil::MatchParameters(env, parameters, { napi_object, napi_string, napi_function });
        bool typeMatch2 = NapiUtil::MatchParameters(env, parameters, { napi_object, napi_string, napi_number });
        if (typeMatch) {
            hasCallback = true;
            return typeMatch;
        }
        if (typeMatch2) {
            hasAccountId = true;
            return true;
        }
    } else if (parameterCount == FOUR_PARAMETERS) {
        bool typeMatch3 =
            NapiUtil::MatchParameters(env, parameters, { napi_object, napi_string, napi_number, napi_function });
        if (typeMatch3) {
            hasAccountId = true;
            hasCallback = true;
            return true;
        }
    }
    return false;
}

void NativeImportVCard(napi_env env, void *data)
{
    auto asyncContext = static_cast<ImportContext *>(data);
    if (asyncContext == nullptr) {
        TELEPHONY_LOGE("asyncContext nullptr");
        return;
    }
    int32_t errorCode = TELEPHONY_SUCCESS;
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        errorCode = TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    } else {
        std::shared_ptr<DataShare::DataShareHelper> datashareHelper = asyncContext->datashareHelper;
        std::string filePath = asyncContext->filePath;
        if (datashareHelper == nullptr) {
            errorCode = TELEPHONY_ERR_PERMISSION_ERR;
        } else {
            VCardManager::GetInstance().SetDataHelper(datashareHelper);
            errorCode = VCardManager::GetInstance().Import(filePath, asyncContext->accountId);
        }
    }
    asyncContext->errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        asyncContext->resolved = true;
    } else {
        asyncContext->resolved = false;
    }
}

void ImportVCardCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<ImportContext *>(data);
    if (context == nullptr) {
        TELEPHONY_LOGE("ImportVCardCallback context nullptr");
    }
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            context->errorCode, "importVCard", PERMISSION_READ_CONTACTS);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle1ValueCallback(env, context, callbackValue);
}

napi_value ImportVCard(napi_env env, napi_callback_info info)
{
    size_t parameterCount = FOUR_PARAMETERS;
    napi_value parameters[FOUR_PARAMETERS] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;

    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    bool hasAccountId = false;
    bool hasCallback = false;
    if (!MatchImportParameters(env, parameters, parameterCount, hasAccountId, hasCallback)) {
        TELEPHONY_LOGE("ImportVCard parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto context = std::make_unique<ImportContext>().release();
    if (context == nullptr) {
        TELEPHONY_LOGE("ImportVCard ImportContext is nullptr.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    context->datashareHelper = GetDataShareHelper(env, info);
    context->filePath = NapiUtil::GetStringFromValue(env, parameters[1]);
    if (hasAccountId) {
        napi_get_value_int32(env, parameters[PARAMETERS_INDEX_TWO], &context->accountId);
    }

    if (hasCallback) {
        if (parameterCount == FOUR_PARAMETERS) {
            napi_create_reference(env, parameters[PARAMETERS_INDEX_THREE], DEFAULT_REF_COUNT, &context->callbackRef);
        } else {
            napi_create_reference(env, parameters[PARAMETERS_INDEX_TWO], DEFAULT_REF_COUNT, &context->callbackRef);
        }
    }
    napi_value result = NapiUtil::HandleAsyncWork(env, context, "ImportVCard", NativeImportVCard, ImportVCardCallback);
    return result;
}

void NativeExportVCard(napi_env env, void *data)
{
    auto asyncContext = static_cast<ExportContext *>(data);
    if (asyncContext == nullptr) {
        TELEPHONY_LOGE("asyncContext nullptr");
        return;
    }
    int32_t errorCode = TELEPHONY_SUCCESS;
    if (!TelephonyPermission::CheckCallerIsSystemApp()) {
        errorCode = TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API;
    } else {
        std::shared_ptr<DataShare::DataShareHelper> datashareHelper = asyncContext->datashareHelper;
        if (datashareHelper == nullptr) {
            errorCode = TELEPHONY_ERR_PERMISSION_ERR;
        } else {
            std::shared_ptr<DataShare::DataSharePredicates> datasharePredicates = asyncContext->predicates;
            std::string charset = asyncContext->charset;
            std::string filePath = "";
            VCardManager::GetInstance().SetDataHelper(datashareHelper);
            errorCode =
                VCardManager::GetInstance().Export(filePath, *datasharePredicates, asyncContext->cardType, charset);
            asyncContext->result = filePath;
        }
    }
    asyncContext->errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        asyncContext->resolved = true;
    } else {
        asyncContext->resolved = false;
    }
}

void ExportVCardCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<ExportContext *>(data);
    if (context == nullptr) {
        TELEPHONY_LOGE("ExportVCardCallback context nullptr");
        return;
    }
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        std::string result = context->result;
        napi_create_string_utf8(env, result.c_str(), result.size(), &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            context->errorCode, "exportVCard", PERMISSION_READ_CONTACTS);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

bool MatchExportParameters(
    napi_env env, napi_value parameters[], size_t parameterCount, bool &hasOption, bool &hasCallback)
{
    if (parameterCount == TWO_PARAMETERS) {
        return NapiUtil::MatchParameters(env, parameters, { napi_object, napi_object });
    } else if (parameterCount == THREE_PARAMETERS) {
        bool typeMatch = NapiUtil::MatchParameters(env, parameters, { napi_object, napi_object, napi_function });
        bool typeMatch2 = NapiUtil::MatchParameters(env, parameters, { napi_object, napi_object, napi_object });
        if (typeMatch) {
            hasCallback = true;
            return typeMatch;
        }
        if (typeMatch2) {
            hasOption = true;
            return true;
        }
    } else if (parameterCount == FOUR_PARAMETERS) {
        bool typeMatch3 =
            NapiUtil::MatchParameters(env, parameters, { napi_object, napi_object, napi_object, napi_function });
        if (typeMatch3) {
            hasOption = true;
            hasCallback = true;
            return true;
        }
    }
    return false;
}

static DataShare::DataSharePredicates UnwrapDataSharePredicates(napi_env env, napi_value value)
{
    auto predicates = DataShare::DataSharePredicatesProxy::GetNativePredicates(env, value);
    if (predicates == nullptr) {
        TELEPHONY_LOGE("GetNativePredicates is nullptr.");
        return {};
    }
    return DataShare::DataSharePredicates(predicates->GetOperationList());
}

std::shared_ptr<DataShare::DataSharePredicates> GetDataSharePredicates(napi_env env, napi_callback_info info)
{
    size_t argc = TWO_PARAMETERS;
    napi_value argv[TWO_PARAMETERS] = { 0 };
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    DataShare::DataSharePredicates predicates = UnwrapDataSharePredicates(env, argv[1]);
    std::shared_ptr<DataShare::DataSharePredicates> dataSharePredicates =
        std::make_shared<DataShare::DataSharePredicates>(predicates);
    return dataSharePredicates;
}

napi_value ExportVCard(napi_env env, napi_callback_info info)
{
    size_t parameterCount = FOUR_PARAMETERS;
    napi_value parameters[FOUR_PARAMETERS] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    bool hasOption = false;
    bool hasCallback = false;
    if (!MatchExportParameters(env, parameters, parameterCount, hasOption, hasCallback)) {
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto context = std::make_unique<ExportContext>().release();
    if (context == nullptr) {
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    context->datashareHelper = GetDataShareHelper(env, info);
    std::shared_ptr<DataShare::DataSharePredicates> datasharePredicates = GetDataSharePredicates(env, info);
    if (datasharePredicates == nullptr) {
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    } else {
        context->predicates = datasharePredicates;
    }
    if (hasOption) {
        napi_value charset = NapiUtil::GetNamedProperty(env, parameters[2], "charset");
        if (charset != nullptr) {
            char strChars[NORMAL_STRING_SIZE] = { 0 };
            size_t strLength = 0;
            napi_get_value_string_utf8(env, charset, strChars, BUFF_LENGTH, &strLength);
            std::string str8(strChars, strLength);
            context->charset = str8;
        }
        napi_value cardType = NapiUtil::GetNamedProperty(env, parameters[2], "cardType");
        if (cardType != nullptr) {
            napi_get_value_int32(env, cardType, &context->cardType);
        }
    }
    if (hasCallback) {
        if (parameterCount == FOUR_PARAMETERS) {
            napi_create_reference(env, parameters[PARAMETERS_INDEX_THREE], DEFAULT_REF_COUNT, &context->callbackRef);
        } else {
            napi_create_reference(env, parameters[PARAMETERS_INDEX_TWO], DEFAULT_REF_COUNT, &context->callbackRef);
        }
    }
    napi_value result = NapiUtil::HandleAsyncWork(env, context, "ExportVCard", NativeExportVCard, ExportVCardCallback);
    return result;
}

napi_value InitEnumVCardType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("VERSION_21", NapiUtil::ToInt32Value(env, static_cast<int32_t>(VCARD_VERSION_21))),
        DECLARE_NAPI_STATIC_PROPERTY("VERSION_30", NapiUtil::ToInt32Value(env, static_cast<int32_t>(VCARD_VERSION_30))),
        DECLARE_NAPI_STATIC_PROPERTY("VERSION_40", NapiUtil::ToInt32Value(env, static_cast<int32_t>(VCARD_VERSION_40))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value CreateEnumVCardType(napi_env env, napi_value exports)
{
    napi_value version_21 = nullptr;
    napi_value version_30 = nullptr;
    napi_value version_40 = nullptr;

    napi_create_int32(env, (int32_t)VCardType::VCARD_VERSION_21, &version_21);
    napi_create_int32(env, (int32_t)VCardType::VCARD_VERSION_30, &version_30);
    napi_create_int32(env, (int32_t)VCardType::VCARD_VERSION_40, &version_40);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("VERSION_21", version_21),
        DECLARE_NAPI_STATIC_PROPERTY("VERSION_30", version_30),
        DECLARE_NAPI_STATIC_PROPERTY("VERSION_40", version_40),
    };

    napi_value result = nullptr;
    napi_define_class(env, "VCardType", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr, sizeof(desc) / sizeof(*desc),
        desc, &result);
    napi_set_named_property(env, exports, "VCardType", result);
    return exports;
}

napi_status InitVcardInterface(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("importVCard", ImportVCard),
        DECLARE_NAPI_FUNCTION("exportVCard", ExportVCard),
    };
    return napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}
} // namespace

EXTERN_C_START
napi_value InitNapiVcard(napi_env env, napi_value exports)
{
    NAPI_CALL(env, InitVcardInterface(env, exports));
    CreateEnumVCardType(env, exports);
    InitEnumVCardType(env, exports);
    return exports;
}
EXTERN_C_END

static napi_module _vcardModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = InitNapiVcard,
    .nm_modname = "telephony.vcard",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterVCardModule(void)
{
    napi_module_register(&_vcardModule);
}
} // namespace Telephony
} // namespace OHOS
