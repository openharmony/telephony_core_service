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

#include "napi_util.h"

#include <codecvt>
#include <cstdio>
#include <cstring>
#include <locale>
#include <memory>
#include <unordered_map>
#include <vector>

#include "core_service_errors.h"
#include "enum_convert_for_js.h"
#include "state_registry_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
static constexpr int32_t MAX_TEXT_LENGTH = 4096;
static constexpr const char *JS_ERROR_TELEPHONY_PERMISSION_DENIED_STRING = "Permission denied.";
static constexpr const char *JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API_STRING = "Non-system applications use system APIs.";
static constexpr const char *JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER_STRING =
    "Parameter error. The type of parameter should match or the number of parameters must match.";
static constexpr const char *JS_ERROR_DEVICE_NOT_SUPPORT_THIS_API_STRING = "The device does not support this API.";
static constexpr const char *JS_ERROR_TELEPHONY_SUCCESS_STRING = "Success.";
static constexpr const char *JS_ERROR_TELEPHONY_ARGUMENT_ERROR_STRING = "Invalid parameter value.";
static constexpr const char *JS_ERROR_TELEPHONY_SERVICE_ERROR_STRING = "Operation failed. Cannot connect to service.";
static constexpr const char *JS_ERROR_TELEPHONY_SYSTEM_ERROR_STRING = "System internal error.";
static constexpr const char *JS_ERROR_TELEPHONY_NO_SIM_CARD_STRING = "Do not have sim card.";
static constexpr const char *JS_ERROR_TELEPHONY_UNKNOW_ERROR_STRING = "Unknown error code.";
static constexpr const char *JS_ERROR_SIM_BASE_ERROR_STRING = "Sim module base error.";
static constexpr const char *JS_ERROR_SIM_CARD_IS_NOT_ACTIVE_STRING = "SIM card is not activated.";
static constexpr const char *JS_ERROR_SIM_CARD_OPERATION_ERROR_STRING = "SIM card operation error.";
static constexpr const char *JS_ERROR_OPERATOR_CONFIG_ERROR_STRING = "Operator config error.";
static constexpr const char *JS_ERROR_NETWORK_SEARCH_BASE_ERROR_STRING = "Network search module base error.";
static constexpr const char *JS_ERROR_CALL_MANAGER_BASE_ERROR_STRING = "Call manager module base error.";
static constexpr const char *JS_ERROR_CELLULAR_CALL_CS_BASE_ERROR_STRING = "Cellular call module cs base error.";
static constexpr const char *JS_ERROR_CELLULAR_CALL_IMS_BASE_ERROR_STRING = "Cellular call module ims base error.";
static constexpr const char *JS_ERROR_CELLULAR_DATA_BASE_ERROR_STRING = "Cellular data module base error.";
static constexpr const char *JS_ERROR_SMS_MMS_BASE_ERROR_STRING = "Sms mms module base error.";
static constexpr const char *JS_ERROR_STATE_REGISTRY_BASE_ERROR_STRING = "State registry module base error.";
static constexpr const char *JS_ERROR_AIRPLANE_MODE_ON_STRING = "Airplane mode is on.";
static constexpr const char *JS_ERROR_NETWORK_NOT_IN_SERVICE = "Network not in service.";
static constexpr const char *JS_ERROR_CONFERENCE_EXCEED_LIMIT_STRING = "Conference call is exceed limit.";
static constexpr const char *JS_ERROR_CONFERENCE_CALL_IS_NOT_ACTIVE_STRING = "Conference call is not active.";
static constexpr const char *JS_ERROR_TELEPHONY_CALL_COUNTS_EXCEED_LIMIT_STRING = "call count exceeds limit";
static constexpr const char *JS_ERROR_TELEPHONY_DIAL_IS_BUSY_STRING =
    "Current on a call, unable to initiate a new call";
static constexpr const char *JS_ERROR_ESIM_SUCCESS_STRING = "Success.";
static constexpr const char *JS_ERROR_ESIM_SERVICE_ERROR_STRING = "Service connection failed.";
static constexpr const char *JS_ERROR_ESIM_SYSTEM_ERROR_STRING = "System internal error.";

static std::unordered_map<int32_t, const char *> errorMap_ = {
    { JsErrorCode::JS_ERROR_TELEPHONY_PERMISSION_DENIED, JS_ERROR_TELEPHONY_PERMISSION_DENIED_STRING },
    { JsErrorCode::JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API, JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER, JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER_STRING },
    { JsErrorCode::JS_ERROR_DEVICE_NOT_SUPPORT_THIS_API, JS_ERROR_DEVICE_NOT_SUPPORT_THIS_API_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_SUCCESS, JS_ERROR_TELEPHONY_SUCCESS_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_ARGUMENT_ERROR, JS_ERROR_TELEPHONY_ARGUMENT_ERROR_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_SERVICE_ERROR, JS_ERROR_TELEPHONY_SERVICE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_SYSTEM_ERROR, JS_ERROR_TELEPHONY_SYSTEM_ERROR_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_NO_SIM_CARD, JS_ERROR_TELEPHONY_NO_SIM_CARD_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_UNKNOW_ERROR, JS_ERROR_TELEPHONY_UNKNOW_ERROR_STRING },
    { JsErrorCode::JS_ERROR_SIM_BASE_ERROR, JS_ERROR_SIM_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_SIM_CARD_IS_NOT_ACTIVE, JS_ERROR_SIM_CARD_IS_NOT_ACTIVE_STRING },
    { JsErrorCode::JS_ERROR_SIM_CARD_OPERATION_ERROR, JS_ERROR_SIM_CARD_OPERATION_ERROR_STRING },
    { JsErrorCode::JS_ERROR_OPERATOR_CONFIG_ERROR, JS_ERROR_OPERATOR_CONFIG_ERROR_STRING },
    { JsErrorCode::JS_ERROR_NETWORK_SEARCH_BASE_ERROR, JS_ERROR_NETWORK_SEARCH_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_CALL_MANAGER_BASE_ERROR, JS_ERROR_CALL_MANAGER_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_CELLULAR_CALL_CS_BASE_ERROR, JS_ERROR_CELLULAR_CALL_CS_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_CELLULAR_CALL_IMS_BASE_ERROR, JS_ERROR_CELLULAR_CALL_IMS_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_CELLULAR_DATA_BASE_ERROR, JS_ERROR_CELLULAR_DATA_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_SMS_MMS_BASE_ERROR, JS_ERROR_SMS_MMS_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_STATE_REGISTRY_BASE_ERROR, JS_ERROR_STATE_REGISTRY_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_AIRPLANE_MODE_ON, JS_ERROR_AIRPLANE_MODE_ON_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_NETWORK_NOT_IN_SERVICE, JS_ERROR_NETWORK_NOT_IN_SERVICE },
    { JsErrorCode::JS_ERROR_TELEPHONY_CONFERENCE_EXCEED_LIMIT, JS_ERROR_CONFERENCE_EXCEED_LIMIT_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_CONFERENCE_CALL_NOT_ACTIVE, JS_ERROR_CONFERENCE_CALL_IS_NOT_ACTIVE_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_CALL_COUNTS_EXCEED_LIMIT, JS_ERROR_TELEPHONY_CALL_COUNTS_EXCEED_LIMIT_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_DIAL_IS_BUSY, JS_ERROR_TELEPHONY_DIAL_IS_BUSY_STRING },
    { JsErrorCode::JS_ERROR_ESIM_SUCCESS, JS_ERROR_ESIM_SUCCESS_STRING },
    { JsErrorCode::JS_ERROR_ESIM_SERVICE_ERROR, JS_ERROR_ESIM_SERVICE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_ESIM_SYSTEM_ERROR, JS_ERROR_ESIM_SYSTEM_ERROR_STRING },
};
const std::string ERROR_STRING = "error";
const std::u16string ERROR_USTRING = u"error";

std::string NapiUtil::GetErrorMessage(int32_t errorCode)
{
    std::string result = "";
    auto iter = errorMap_.find(errorCode);
    if (iter == errorMap_.end()) {
        TELEPHONY_LOGE("NapiUtil::GetErrorMessage return null.");
        return result;
    }
    TELEPHONY_LOGD("NapiUtil::GetErrorMessage errorCode %{public}d, message = %{public}s", errorCode, iter->second);
    result = iter->second;
    return result;
}

std::string NapiUtil::ToUtf8(std::u16string str16)
{
    if (str16 == ERROR_USTRING) {
        return ERROR_STRING;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert(ERROR_STRING);
    std::string result = convert.to_bytes(str16);
    return result == ERROR_STRING ? "" : result;
}

std::u16string NapiUtil::ToUtf16(std::string str)
{
    if (str == ERROR_STRING) {
        return ERROR_USTRING;
    }
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert(ERROR_STRING, ERROR_USTRING);
    std::u16string result = convert.from_bytes(str);
    return result == ERROR_USTRING ? u"" : result;
}

napi_value NapiUtil::CreateErrorMessage(napi_env env, const std::string &msg, int32_t errorCode)
{
    napi_value result = nullptr;
    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), msg.length(), &message));
    napi_value codeValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errorCode, &codeValue));
    NAPI_CALL(env, napi_create_object(env, &result));
    NAPI_CALL(env, napi_set_named_property(env, result, "code", codeValue));
    NAPI_CALL(env, napi_set_named_property(env, result, "message", message));
    return result;
}

napi_value NapiUtil::CreateUndefined(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

bool NapiUtil::MatchValueType(napi_env env, napi_value value, napi_valuetype targetType)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), false);
    return valueType == targetType;
}

bool NapiUtil::MatchParameters(
    napi_env env, const napi_value parameters[], std::initializer_list<napi_valuetype> valueTypes)
{
    if (parameters == nullptr) {
        return false;
    }
    int i = 0;
    for (auto beg = valueTypes.begin(); beg != valueTypes.end(); ++beg) {
        if (!MatchValueType(env, parameters[i], *beg)) {
            return false;
        }
        ++i;
    }
    return true;
}

void NapiUtil::SetPropertyInt32(napi_env env, napi_value object, const std::string &name, int32_t value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, value, &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

void NapiUtil::SetPropertyInt64(napi_env env, napi_value object, const std::string &name, int64_t value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, value, &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

void NapiUtil::SetPropertyStringUtf8(napi_env env, napi_value object, const std::string &name, const std::string &value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, value.c_str(), value.length(), &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

void NapiUtil::SetPropertyBoolean(napi_env env, napi_value object, const std::string &name, bool value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, value, &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

napi_value NapiUtil::ToInt32Value(napi_env env, int32_t value)
{
    napi_value staticValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &staticValue));
    return staticValue;
}

bool NapiUtil::HasNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.data(), &hasProperty), false);
    return hasProperty;
}

bool NapiUtil::HasNamedTypeProperty(
    napi_env env, napi_value object, napi_valuetype type, const std::string &propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.data(), &hasProperty), false);
    if (hasProperty) {
        napi_value value = nullptr;
        NAPI_CALL_BASE(env, napi_get_named_property(env, object, propertyName.data(), &value), false);
        return MatchValueType(env, value, type);
    }
    return false;
}

bool NapiUtil::MatchObjectProperty(
    napi_env env, napi_value object, std::initializer_list<std::pair<std::string, napi_valuetype>> pairList)
{
    if (object == nullptr) {
        return false;
    }
    for (auto beg = pairList.begin(); beg != pairList.end(); ++beg) {
        if (!HasNamedTypeProperty(env, object, beg->second, beg->first)) {
            return false;
        }
    }
    return true;
}

bool NapiUtil::MatchOptionPropertyType(
    napi_env env, napi_value object, napi_valuetype type, const std::string &propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.data(), &hasProperty), false);
    if (hasProperty) {
        napi_value value = nullptr;
        NAPI_CALL_BASE(env, napi_get_named_property(env, object, propertyName.data(), &value), false);
        return MatchValueType(env, value, type);
    }
    return true;
}

std::string NapiUtil::GetStringFromValue(napi_env env, napi_value value)
{
    char msgChars[MAX_TEXT_LENGTH] = {0};
    size_t msgLength = 0;
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, value, msgChars, MAX_TEXT_LENGTH, &msgLength), "");
    TELEPHONY_LOGI("msgLength = %{public}zu", msgLength);
    if (msgLength > 0) {
        return std::string(msgChars, 0, msgLength);
    } else {
        return "";
    }
}

napi_value NapiUtil::GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    napi_value value = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, propertyName.data(), &hasProperty));
    if (hasProperty) {
        NAPI_CALL(env, napi_get_named_property(env, object, propertyName.data(), &value));
    }
    return value;
}

napi_value NapiUtil::HandleAsyncWork(napi_env env, BaseContext *baseContext, const std::string &workName,
    napi_async_execute_callback execute, napi_async_complete_callback complete)
{
    TELEPHONY_LOGD("workName = %{public}s", workName.c_str());
    std::unique_ptr<BaseContext> context(baseContext);
    if (context == nullptr) {
        ThrowParameterError(env);
        return nullptr;
    }
    napi_value result = nullptr;
    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resource = CreateUndefined(env);
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, workName.data(), NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env,
        napi_create_async_work(env, resource, resourceName, execute, complete, (void *)context.get(), &context->work));
    napi_status queueWorkStatus = napi_queue_async_work_with_qos(env, context->work, napi_qos_default);
    if (queueWorkStatus == napi_ok) {
        context.release();
    } else {
        std::string errorCode = std::to_string(queueWorkStatus);
        std::string errorMessage = "error at napi_queue_async_work_with_qos";
        NAPI_CALL(env, napi_throw_error(env, errorCode.c_str(), errorMessage.c_str()));
    }
    TELEPHONY_LOGD("NapiUtil HandleAsyncWork end");
    return result;
}

void NapiUtil::Handle1ValueCallback(napi_env env, BaseContext *baseContext, napi_value callbackValue)
{
    TELEPHONY_LOGD("Handle1ValueCallback start");
    if (baseContext == nullptr) {
        TELEPHONY_LOGE("Handle1ValueCallback baseContext is nullptr");
        NapiUtil::ThrowParameterError(env);
        return;
    }
    if (baseContext->callbackRef != nullptr) {
        TELEPHONY_LOGI("start normal callback");
        napi_value recv = CreateUndefined(env);
        napi_value callbackFunc = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, baseContext->callbackRef, &callbackFunc));
        napi_value callbackValues[] = {callbackValue};
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, recv, callbackFunc, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, baseContext->callbackRef));
        TELEPHONY_LOGD("normal callback end");
    } else if (baseContext->deferred != nullptr) {
        TELEPHONY_LOGI("start promise callback");
        if (baseContext->resolved) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, baseContext->deferred, callbackValue));
            TELEPHONY_LOGI("napi_resolve_deferred end");
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, baseContext->deferred, callbackValue));
            TELEPHONY_LOGI("napi_reject_deferred end");
        }
        TELEPHONY_LOGD("promise callback end");
    }
    napi_delete_async_work(env, baseContext->work);
    delete baseContext;
    baseContext = nullptr;
    TELEPHONY_LOGD("end");
}

void NapiUtil::Handle2ValueCallback(napi_env env, BaseContext *baseContext, napi_value callbackValue)
{
    TELEPHONY_LOGD("Handle2ValueCallback start");
    if (baseContext == nullptr) {
        TELEPHONY_LOGI("Handle2ValueCallback serious error baseContext nullptr");
        ThrowParameterError(env);
        return;
    }
    if (baseContext->callbackRef != nullptr) {
        TELEPHONY_LOGD("Handle2ValueCallback start normal callback");
        napi_value recv = CreateUndefined(env);
        napi_value callbackFunc = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, baseContext->callbackRef, &callbackFunc));
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = baseContext->resolved ? CreateUndefined(env) : callbackValue;
        callbackValues[1] = baseContext->resolved ? callbackValue : CreateUndefined(env);
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, recv, callbackFunc, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, baseContext->callbackRef));
        TELEPHONY_LOGD("Handle2ValueCallback normal callback end");
    } else if (baseContext->deferred != nullptr) {
        TELEPHONY_LOGD("Handle2ValueCallback start promise callback");
        if (baseContext->resolved) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, baseContext->deferred, callbackValue));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, baseContext->deferred, callbackValue));
        }
        TELEPHONY_LOGD("Handle2ValueCallback promise callback end");
    }
    napi_delete_async_work(env, baseContext->work);
    delete baseContext;
    baseContext = nullptr;
    TELEPHONY_LOGD("Handle2ValueCallback end");
}

void NapiUtil::DefineEnumClassByName(
    napi_env env, napi_value exports, std::string_view enumName, size_t arrSize, const napi_property_descriptor *desc)
{
    auto construct = [](napi_env env, napi_callback_info info) -> napi_value { return nullptr; };
    napi_value result = nullptr;
    napi_status status =
        napi_define_class(env, enumName.data(), NAPI_AUTO_LENGTH, construct, nullptr, arrSize, desc, &result);
    if (status != napi_ok) {
        TELEPHONY_LOGE("DefineEnumClassByName napi_define_class failed ret = %d", status);
    }
    status = napi_set_named_property(env, exports, enumName.data(), result);
    if (status != napi_ok) {
        TELEPHONY_LOGE("DefineEnumClassByName napi_set_named_property failed ret = %d", status);
    }
}

JsError NapiUtil::ConverErrorMessageForJs(int32_t errorCode)
{
    JsError error = {};
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        error.errorCode = JS_ERROR_TELEPHONY_SUCCESS;
        error.errorMessage = GetErrorMessage(JS_ERROR_TELEPHONY_SUCCESS);
        return error;
    }

    if (CreateParameterErrorMessageForJs(errorCode, error.errorCode)) {
        error.errorMessage = GetErrorMessage(error.errorCode);
        return error;
    }

    if (!CreateCommonErrorMessageForJs(errorCode, error.errorCode) &&
        !CreateCallErrorMessageForJs(errorCode, error.errorCode) &&
        !CreateDataErrorMessageForJs(errorCode, error.errorCode) &&
        !CreateNetworkSearchErrorMessageForJs(errorCode, error.errorCode) &&
        !CreateVcardErrorMessageForJs(errorCode, error.errorCode) &&
        !CreateSimErrorMessageForJs(errorCode, error.errorCode) &&
        !CreateSmsErrorMessageForJs(errorCode, error.errorCode) &&
        !CreateObserverErrorMessageForJs(errorCode, error.errorCode)) {
        error.errorCode = JS_ERROR_TELEPHONY_UNKNOW_ERROR;
        TELEPHONY_LOGE("NapiUtil::ConverErrorMessageForJs errorCode is out of range");
    }
    error.errorMessage = GetErrorMessage(error.errorCode);
    TELEPHONY_LOGI("errorCode from %{public}d to %{public}d", errorCode, error.errorCode);
    return error;
}

bool NapiUtil::CreateEsimParameterErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;
    switch (errorCode) {
        case ERROR_PARAMETER_COUNTS_INVALID:
        case ERROR_PARAMETER_TYPE_INVALID:
        case ERROR_SLOT_ID_INVALID:
        case napi_status::napi_generic_failure:
        case napi_status::napi_invalid_arg:
            jsErrorCode = JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER;
            break;
        default:
            flag = false;
            break;
    }

    return flag;
}

bool NapiUtil::CreateEsimServiceErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL:
        case TELEPHONY_ERR_WRITE_DATA_FAIL:
        case TELEPHONY_ERR_WRITE_REPLY_FAIL:
        case TELEPHONY_ERR_READ_DATA_FAIL:
        case TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL:
            jsErrorCode = JS_ERROR_ESIM_SERVICE_ERROR;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

bool NapiUtil::CreateEsimSystemErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_ERR_FAIL:
        case TELEPHONY_ERR_LOCAL_PTR_NULL:
            jsErrorCode = JS_ERROR_ESIM_SYSTEM_ERROR;
            break;
        case TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API:
            jsErrorCode = JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

JsError NapiUtil::ConverEsimErrorMessageForJs(int32_t errorCode)
{
    JsError error = {};
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        error.errorCode = JS_ERROR_ESIM_SUCCESS;
        error.errorMessage = GetErrorMessage(JS_ERROR_ESIM_SUCCESS);
        return error;
    }

    if (CreateEsimParameterErrorMessageForJs(errorCode, error.errorCode)) {
        error.errorMessage = GetErrorMessage(error.errorCode);
        return error;
    }

    if (!CreateEsimServiceErrorMessageForJs(errorCode, error.errorCode) &&
        !CreateEsimSystemErrorMessageForJs(errorCode, error.errorCode)) {
        error.errorCode = JS_ERROR_ESIM_SYSTEM_ERROR;
        TELEPHONY_LOGE("NapiUtil::ConverEsimErrorMessageForJs errorCode is out of range");
    }
    error.errorMessage = GetErrorMessage(error.errorCode);
    TELEPHONY_LOGI("errorCode from %{public}d to %{public}d", errorCode, error.errorCode);
    return error;
}

bool NapiUtil::CreateParameterErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;
    switch (errorCode) {
        case ERROR_SERVICE_UNAVAILABLE:
        case ERROR_NATIVE_API_EXECUTE_FAIL:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        case ERROR_PARAMETER_COUNTS_INVALID:
        case ERROR_PARAMETER_TYPE_INVALID:
        case napi_status::napi_generic_failure:
        case napi_status::napi_invalid_arg:
            jsErrorCode = JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER;
            break;
        case ERROR_SLOT_ID_INVALID:
            jsErrorCode = JS_ERROR_TELEPHONY_ARGUMENT_ERROR;
            break;
        default:
            flag = false;
            break;
    }

    return flag;
}

bool NapiUtil::CreateNetworkSearchErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    if ((errorCode < CORE_SERVICE_NETWORK_SEARCH_ERR_OFFSET || errorCode >= CORE_SERVICE_CORE_ERR_OFFSET)) {
        return false;
    }
    bool flag = true;
    switch (errorCode) {
        case CORE_SERVICE_SEND_CALLBACK_FAILED:
        case CORE_SERVICE_RADIO_PROTOCOL_TECH_UNKNOWN:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        default:
            flag = false;
            break;
    }

    return flag;
}

bool NapiUtil::CreateVcardErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;
    switch (errorCode) {
        case TELEPHONY_ERR_VCARD_FILE_INVALID:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        default:
            flag = false;
            break;
    }

    return flag;
}

bool NapiUtil::CreateSimErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    if ((errorCode < CORE_SERVICE_SIM_ERR_OFFSET || errorCode >= CORE_SERVICE_NETWORK_SEARCH_ERR_OFFSET)) {
        return false;
    }
    bool flag = true;
    switch (errorCode) {
        case CORE_SERVICE_SIM_CARD_IS_NOT_ACTIVE:
            jsErrorCode = JS_ERROR_SIM_CARD_IS_NOT_ACTIVE;
            break;
        case CORE_ERR_SIM_CARD_LOAD_FAILED:
        case CORE_ERR_SIM_CARD_UPDATE_FAILED:
            jsErrorCode = JS_ERROR_SIM_CARD_OPERATION_ERROR;
            break;
        case CORE_ERR_OPERATOR_KEY_NOT_EXIT:
        case CORE_ERR_OPERATOR_CONF_NOT_EXIT:
            jsErrorCode = JS_ERROR_OPERATOR_CONFIG_ERROR;
            break;
        default:
            flag = false;
            break;
    }

    return flag;
}

bool NapiUtil::CreateSmsErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    if ((errorCode < SMS_MMS_ERR_OFFSET || errorCode >= STATE_REGISTRY_ERR_OFFSET)) {
        return false;
    }
    bool flag = true;
    switch (errorCode) {
        case TELEPHONY_SMS_MMS_DECODE_DATA_EMPTY:
        case TELEPHONY_SMS_MMS_UNKNOWN_SIM_MESSAGE_STATUS:
        case TELEPHONY_SMS_MMS_MESSAGE_LENGTH_OUT_OF_RANGE:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        default:
            flag = false;
            break;
    }

    return flag;
}

bool NapiUtil::CreateObserverErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    if ((errorCode < STATE_REGISTRY_ERR_OFFSET || errorCode >= NET_MANAGER_ERR_OFFSET)) {
        return false;
    }
    bool flag = true;
    switch (errorCode) {
        case TELEPHONY_STATE_REGISTRY_SLODID_ERROR:
            jsErrorCode = JS_ERROR_TELEPHONY_ARGUMENT_ERROR;
            break;
        case TELEPHONY_STATE_REGISTRY_PERMISSION_DENIED:
            jsErrorCode = JS_ERROR_TELEPHONY_PERMISSION_DENIED;
            break;
        case TELEPHONY_STATE_REGISTRY_DATA_NOT_EXIST:
        case TELEPHONY_STATE_UNREGISTRY_DATA_NOT_EXIST:
        case TELEPHONY_STATE_REGISTRY_DATA_EXIST:
        case TELEPHONY_STATE_REGISTRY_NOT_IMPLEMENTED:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        default:
            flag = false;
            break;
    }

    return flag;
}

bool NapiUtil::CreateCommonErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    if ((errorCode < COMMON_ERR_OFFSET || errorCode >= CALL_ERR_OFFSET)) {
        return false;
    }
    if (CreateCommonArgumentErrorMessageForJs(errorCode, jsErrorCode) ||
        CreateCommonServiceErrorMessageForJs(errorCode, jsErrorCode) ||
        CreateCommonSystemErrorMessageForJs(errorCode, jsErrorCode)) {
        return true;
    }
    return false;
}

bool NapiUtil::CreateCommonArgumentErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_ERR_ARGUMENT_MISMATCH:
        case TELEPHONY_ERR_ARGUMENT_INVALID:
        case TELEPHONY_ERR_ARGUMENT_NULL:
        case TELEPHONY_ERR_SLOTID_INVALID:
            jsErrorCode = JS_ERROR_TELEPHONY_ARGUMENT_ERROR;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

bool NapiUtil::CreateCommonServiceErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_ERR_DESCRIPTOR_MISMATCH:
        case TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL:
        case TELEPHONY_ERR_WRITE_DATA_FAIL:
        case TELEPHONY_ERR_WRITE_REPLY_FAIL:
        case TELEPHONY_ERR_READ_DATA_FAIL:
        case TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL:
        case TELEPHONY_ERR_REGISTER_CALLBACK_FAIL:
        case TELEPHONY_ERR_CALLBACK_ALREADY_REGISTERED:
        case TELEPHONY_ERR_UNINIT:
        case TELEPHONY_ERR_UNREGISTER_CALLBACK_FAIL:
            jsErrorCode = JS_ERROR_TELEPHONY_SERVICE_ERROR;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

bool NapiUtil::CreateCommonSystemErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_ERR_FAIL:
        case TELEPHONY_ERR_MEMCPY_FAIL:
        case TELEPHONY_ERR_MEMSET_FAIL:
        case TELEPHONY_ERR_STRCPY_FAIL:
        case TELEPHONY_ERR_LOCAL_PTR_NULL:
        case TELEPHONY_ERR_SUBSCRIBE_BROADCAST_FAIL:
        case TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL:
        case TELEPHONY_ERR_ADD_DEATH_RECIPIENT_FAIL:
        case TELEPHONY_ERR_STRTOINT_FAIL:
        case TELEPHONY_ERR_RIL_CMD_FAIL:
        case TELEPHONY_ERR_DATABASE_WRITE_FAIL:
        case TELEPHONY_ERR_DATABASE_READ_FAIL:
        case TELEPHONY_ERR_UNKNOWN_NETWORK_TYPE:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        case TELEPHONY_ERR_NO_SIM_CARD:
            jsErrorCode = JS_ERROR_TELEPHONY_NO_SIM_CARD;
            break;
        case TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API:
            jsErrorCode = JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API;
            break;
        case TELEPHONY_ERR_AIRPLANE_MODE_ON:
            jsErrorCode = JS_ERROR_TELEPHONY_AIRPLANE_MODE_ON;
            break;
        case TELEPHONY_ERR_NETWORK_NOT_IN_SERVICE:
            jsErrorCode = JS_ERROR_TELEPHONY_NETWORK_NOT_IN_SERVICE;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

bool NapiUtil::CreateCallErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    if ((errorCode < CALL_ERR_OFFSET || errorCode >= CELLULAR_DATA_ERR_OFFSET)) {
        return false;
    }
    if (CreateCommonCallErrorMessageForJs(errorCode, jsErrorCode) ||
        CreateVideoCallErrorMessageForJs(errorCode, jsErrorCode) ||
        CreateSupplementServiceCallErrorMessageForJs(errorCode, jsErrorCode)) {
        return true;
    }
    return false;
}

bool NapiUtil::CreateCommonCallErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_CALL_ERR_NUMBER_OUT_OF_RANGE:
        case TELEPHONY_CALL_ERR_PHONE_NUMBER_EMPTY:
        case TELEPHONY_CALL_ERR_FORMAT_PHONE_NUMBER_FAILED:
            jsErrorCode = JS_ERROR_TELEPHONY_ARGUMENT_ERROR;
            break;
        case TELEPHONY_CALL_ERR_PARAMETER_OUT_OF_RANGE:
        case TELEPHONY_CALL_ERR_INVALID_SLOT_ID:
            jsErrorCode = JS_ERROR_TELEPHONY_ARGUMENT_ERROR;
            break;
        case TELEPHONY_CALL_ERR_CONFERENCE_CALL_EXCEED_LIMIT:
            jsErrorCode = JS_ERROR_TELEPHONY_CONFERENCE_EXCEED_LIMIT;
            break;
        case TELEPHONY_CALL_ERR_CONFERENCE_CALL_IS_NOT_ACTIVE:
            jsErrorCode = JS_ERROR_TELEPHONY_CONFERENCE_CALL_NOT_ACTIVE;
            break;
        case TELEPHONY_CALL_ERR_CALL_COUNTS_EXCEED_LIMIT:
            jsErrorCode = JS_ERROR_TELEPHONY_CALL_COUNTS_EXCEED_LIMIT;
            break;
        case TELEPHONY_CALL_ERR_CALL_IS_NOT_ACTIVATED:
        case TELEPHONY_CALL_ERR_ILLEGAL_CALL_OPERATION:
        case TELEPHONY_CALL_ERR_AUDIO_SETTING_MUTE_FAILED:
        case TELEPHONY_CALL_ERR_CALL_IS_NOT_ON_HOLDING:
        case TELEPHONY_CALL_ERR_PHONE_CALLS_TOO_FEW:
        case TELEPHONY_CALL_ERR_VIDEO_ILLEGAL_CALL_TYPE:
        case TELEPHONY_CALL_ERR_CONFERENCE_NOT_EXISTS:
        case TELEPHONY_CALL_ERR_CONFERENCE_SEPERATE_FAILED:
        case TELEPHONY_CALL_ERR_EMERGENCY_UNSUPPORT_CONFERENCEABLE:
        case TELEPHONY_CALL_ERR_VOLTE_NOT_SUPPORT:
        case TELEPHONY_CALL_ERR_VOLTE_PROVISIONING_DISABLED:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        case TELEPHONY_CALL_ERR_DIAL_IS_BUSY:
            jsErrorCode = JS_ERROR_TELEPHONY_DIAL_IS_BUSY;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

bool NapiUtil::CreateVideoCallErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_CALL_ERR_VIDEO_ILLEGAL_MEDIA_TYPE:
        case TELEPHONY_CALL_ERR_VIDEO_IN_PROGRESS:
        case TELEPHONY_CALL_ERR_VIDEO_ILLEAGAL_SCENARIO:
        case TELEPHONY_CALL_ERR_VIDEO_MODE_CHANGE_NOTIFY_FAILED:
        case TELEPHONY_CALL_ERR_VIDEO_NOT_SUPPORTED:
        case TELEPHONY_CALL_ERR_SETTING_AUDIO_DEVICE_FAILED:
        case TELEPHONY_CALL_ERR_VIDEO_INVALID_COORDINATES:
        case TELEPHONY_CALL_ERR_VIDEO_INVALID_ZOOM:
        case TELEPHONY_CALL_ERR_VIDEO_INVALID_ROTATION:
        case TELEPHONY_CALL_ERR_VIDEO_INVALID_CAMERA_ID:
        case TELEPHONY_CALL_ERR_INVALID_PATH:
        case TELEPHONY_CALL_ERR_CAMERA_NOT_TURNED_ON:
        case TELEPHONY_CALL_ERR_INVALID_DIAL_SCENE:
        case TELEPHONY_CALL_ERR_INVALID_VIDEO_STATE:
        case TELEPHONY_CALL_ERR_UNKNOW_DIAL_TYPE:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

bool NapiUtil::CreateSupplementServiceCallErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_CALL_ERR_INVALID_RESTRICTION_TYPE:
        case TELEPHONY_CALL_ERR_INVALID_RESTRICTION_MODE:
        case TELEPHONY_CALL_ERR_INVALID_TRANSFER_TYPE:
        case TELEPHONY_CALL_ERR_INVALID_TRANSFER_SETTING_TYPE:
            jsErrorCode = JS_ERROR_TELEPHONY_ARGUMENT_ERROR;
            break;
        case TELEPHONY_CALL_ERR_FUNCTION_NOT_SUPPORTED:
            jsErrorCode = JS_ERROR_DEVICE_NOT_SUPPORT_THIS_API;
            break;
        case TELEPHONY_CALL_ERR_INVALID_TRANSFER_TIME:
        case TELEPHONY_CALL_ERR_NAPI_INTERFACE_FAILED:
        case TELEPHONY_CALL_ERR_CALLBACK_ALREADY_EXIST:
        case TELEPHONY_CALL_ERR_RESOURCE_UNAVAILABLE:
            jsErrorCode = JS_ERROR_TELEPHONY_SYSTEM_ERROR;
            break;
        case TELEPHONY_CALL_ERR_UT_NO_CONNECTION:
            jsErrorCode = JS_ERROR_CALL_UT_NO_CONNECTION;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

bool NapiUtil::CreateDataErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode)
{
    if ((errorCode < CELLULAR_DATA_ERR_OFFSET || errorCode >= SMS_MMS_ERR_OFFSET)) {
        return false;
    }
    bool flag = true;

    switch (errorCode) {
        case TELEPHONY_CELLULAR_DATA_INVALID_PARAM:
            jsErrorCode = JS_ERROR_CELLULAR_DATA_BASE_ERROR;
            break;
        default:
            flag = false;
            break;
    }
    return flag;
}

JsError NapiUtil::ConverErrorMessageWithPermissionForJs(
    int32_t errorCode, const std::string &funcName, const std::string &permission)
{
    if (errorCode == TELEPHONY_ERR_PERMISSION_ERR) {
        JsError error = {};
        error.errorCode = JS_ERROR_TELEPHONY_PERMISSION_DENIED;
        error.errorMessage = "BusinessError 201: Permission denied. An attempt was made to " + funcName +
                             " forbidden by permission: " + permission;
        return error;
    }
    return ConverErrorMessageForJs(errorCode);
}

napi_value NapiUtil::CreateError(napi_env env, int32_t err, const std::string &msg)
{
    napi_value businessError = nullptr;
    napi_value errorCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, err, &errorCode));
    napi_value errorMessage = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMessage));
    napi_create_error(env, nullptr, errorMessage, &businessError);
    napi_set_named_property(env, businessError, "code", errorCode);
    return businessError;
}

void NapiUtil::ThrowError(napi_env env, int32_t errorCode, const std::string &message)
{
    napi_value error = CreateError(env, errorCode, message);
    napi_throw(env, error);
}

void NapiUtil::ThrowParameterError(napi_env env)
{
    ThrowError(
        env, JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER, GetErrorMessage(JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER));
}
} // namespace Telephony
} // namespace OHOS
