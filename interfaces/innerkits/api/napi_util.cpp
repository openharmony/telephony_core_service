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
#include <locale>
#include <vector>
#include <cstring>
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
std::string NapiUtil::ToUtf8(std::u16string str16)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.to_bytes(str16);
}

std::u16string NapiUtil::ToUtf16(std::string str)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.from_bytes(str);
}

napi_value NapiUtil::CreateErrorMessage(napi_env env, std::string msg, int32_t errorCode)
{
    napi_value result = nullptr;
    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), msg.length(), &message));
    napi_value codeValue = nullptr;
    std::string errCode = std::to_string(errorCode);
    NAPI_CALL(env, napi_create_string_utf8(env, errCode.c_str(), errCode.length(), &codeValue));
    NAPI_CALL(env, napi_create_error(env, codeValue, message, &result));
    return result;
}

napi_value NapiUtil::CreateUndefined(napi_env env)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

bool NapiUtil::MatchValueType(napi_env env, napi_value value, napi_valuetype targetType)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
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

void NapiUtil::SetPropertyInt32(napi_env env, napi_value object, std::string name, int32_t value)
{
    napi_value propertyValue = nullptr;
    napi_create_int32(env, value, &propertyValue);
    napi_set_named_property(env, object, name.c_str(), propertyValue);
}

void NapiUtil::SetPropertyStringUtf8(napi_env env, napi_value object, std::string name, std::string value)
{
    napi_value propertyValue = nullptr;
    napi_create_string_utf8(env, value.c_str(), name.length(), &propertyValue);
    napi_set_named_property(env, object, name.c_str(), propertyValue);
}

void NapiUtil::SetPropertyBoolean(napi_env env, napi_value object, std::string name, bool value)
{
    napi_value propertyValue = nullptr;
    napi_get_boolean(env, value, &propertyValue);
    napi_set_named_property(env, object, name.c_str(), propertyValue);
}

napi_value NapiUtil::ToInt32Value(napi_env env, int32_t value)
{
    napi_value staticValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &staticValue));
    return staticValue;
}

bool NapiUtil::HasNamedProperty(napi_env env, napi_value object, std::string propertyName)
{
    bool hasProperty = false;
    napi_has_named_property(env, object, propertyName.data(), &hasProperty);
    return hasProperty;
}

bool NapiUtil::HasNamedTypeProperty(napi_env env, napi_value object, napi_valuetype type, std::string propertyName)
{
    bool hasProperty = false;
    napi_has_named_property(env, object, propertyName.data(), &hasProperty);
    if (hasProperty) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, propertyName.data(), &value);
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
    napi_env env, napi_value object, napi_valuetype type, std::string propertyName)
{
    bool hasProperty = false;
    napi_has_named_property(env, object, propertyName.data(), &hasProperty);
    if (hasProperty) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, propertyName.data(), &value);
        return MatchValueType(env, value, type);
    }
    return true;
}

std::string NapiUtil::GetStringFromValue(napi_env env, napi_value value)
{
    char msgChars[MAX_TEXT_LENGTH] = {0};
    size_t msgLength = 0;
    napi_get_value_string_utf8(env, value, msgChars, MAX_TEXT_LENGTH, &msgLength);
    TELEPHONY_LOGD("NapiUtil GetStringFromValue msgLength = %{public}zu", msgLength);
    if (msgLength > 0) {
        return std::string(msgChars, 0, msgLength);
    } else {
        return "";
    }
}

napi_value NapiUtil::GetNamedProperty(napi_env env, napi_value object, std::string propertyName)
{
    napi_value value = nullptr;
    napi_get_named_property(env, object, propertyName.data(), &value);
    return value;
}

napi_value NapiUtil::HandleAsyncWork(napi_env env, BaseContext *context, std::string workName,
    napi_async_execute_callback execute, napi_async_complete_callback complete)
{
    TELEPHONY_LOGD("NapiUtil HandleAsyncWork start workName = %{public}s", workName.c_str());
    napi_value result = nullptr;
    bool noCallback = context->callbackRef == nullptr;
    TELEPHONY_LOGD("NapiUtil HandleAsyncWork noCallback = %{public}d", noCallback);
    if (noCallback) {
        napi_status createStatus = napi_create_promise(env, &context->deferred, &result);
        TELEPHONY_LOGD("NapiUtil HandleAsyncWork napi_create_promise createStatus  %{public}d", createStatus);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resource = CreateUndefined(env);
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, workName.data(), NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, resource, resourceName, execute, complete, (void *)context, &context->work);
    napi_queue_async_work(env, context->work);
    return result;
}

void NapiUtil::Handle1ValueCallback(napi_env env, BaseContext *baseContext, napi_value callbackValue)
{
    std::unique_ptr<BaseContext> context(baseContext);
    if (context == nullptr) {
        std::string errorCode = std::to_string(napi_invalid_arg);
        std::string errorMessage = "error at baseContext is nullptr";
        NAPI_CALL_RETURN_VOID(env, napi_throw_error(env, errorCode.c_str(), errorMessage.c_str()));
    }
    if (context->callbackRef != nullptr) {
        napi_value recv = CreateUndefined(env);
        napi_value callbackFunc = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, context->callbackRef, &callbackFunc));
        napi_value callbackValues[] = {callbackValue};
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, recv, callbackFunc, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, context->callbackRef));
    } else if (context->deferred != nullptr) {
        if (context->resolved) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context->deferred, callbackValue));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context->deferred, callbackValue));
        }
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, context->work));
}

void NapiUtil::Handle2ValueCallback(napi_env env, BaseContext *context, napi_value callbackValue)
{
    if (context->callbackRef != nullptr) {
        TELEPHONY_LOGD("Handle2ValueCallback normal callback resolved = %{public}d", context->resolved);
        napi_value recv = CreateUndefined(env);
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, context->callbackRef, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = context->resolved ? CreateUndefined(env) : callbackValue;
        callbackValues[1] = context->resolved ? callbackValue : CreateUndefined(env);
        napi_value result = nullptr;
        napi_call_function(env, recv, callbackFunc, std::size(callbackValues), callbackValues, &result);
        napi_delete_reference(env, context->callbackRef);
    } else if (context->deferred != nullptr) {
        TELEPHONY_LOGD("Handle2ValueCallback promise callback resolved = %{public}d", context->resolved);
        if (context->resolved) {
            napi_resolve_deferred(env, context->deferred, callbackValue);
        } else {
            napi_reject_deferred(env, context->deferred, callbackValue);
        }
    }
    napi_delete_async_work(env, context->work);
    delete context;
}
} // namespace Telephony
} // namespace OHOS
