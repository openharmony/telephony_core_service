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
#include <memory>

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

void NapiUtil::SetPropertyInt32(napi_env env, napi_value object, std::string name, int32_t value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, value, &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

void NapiUtil::SetPropertyInt64(napi_env env, napi_value object, std::string name, int64_t value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, value, &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

void NapiUtil::SetPropertyStringUtf8(napi_env env, napi_value object, std::string name, std::string value)
{
    napi_value propertyValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, value.c_str(), value.length(), &propertyValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), propertyValue));
}

void NapiUtil::SetPropertyBoolean(napi_env env, napi_value object, std::string name, bool value)
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

bool NapiUtil::HasNamedProperty(napi_env env, napi_value object, std::string propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.data(), &hasProperty), false);
    return hasProperty;
}

bool NapiUtil::HasNamedTypeProperty(napi_env env, napi_value object, napi_valuetype type, std::string propertyName)
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

bool NapiUtil::MatchOptionPropertyType(napi_env env, napi_value object, napi_valuetype type, std::string propertyName)
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
    TELEPHONY_LOGI("NapiUtil GetStringFromValue msgLength = %{public}zu", msgLength);
    if (msgLength > 0) {
        return std::string(msgChars, 0, msgLength);
    } else {
        return "";
    }
}

napi_value NapiUtil::GetNamedProperty(napi_env env, napi_value object, std::string propertyName)
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
    TELEPHONY_LOGI("NapiUtil HandleAsyncWork workName = %{public}s", workName.c_str());
    std::unique_ptr<BaseContext> context(baseContext);
    if (context == nullptr) {
        std::string errorCode = std::to_string(napi_invalid_arg);
        std::string errorMessage = "error at baseContext is nullptr";
        NAPI_CALL(env, napi_throw_error(env, errorCode.c_str(), errorMessage.c_str()));
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
    napi_status queueWorkStatus = napi_queue_async_work(env, context->work);
    if (queueWorkStatus == napi_ok) {
        context.release();
        TELEPHONY_LOGI("NapiUtil HandleAsyncWork napi_queue_async_work ok");
    } else {
        std::string errorCode = std::to_string(queueWorkStatus);
        std::string errorMessage = "error at napi_queue_async_work";
        NAPI_CALL(env, napi_throw_error(env, errorCode.c_str(), errorMessage.c_str()));
    }
    TELEPHONY_LOGI("NapiUtil HandleAsyncWork end");
    return result;
}

void NapiUtil::Handle1ValueCallback(napi_env env, BaseContext *baseContext, napi_value callbackValue)
{
    TELEPHONY_LOGI("Handle1ValueCallback start");
    if (baseContext == nullptr) {
        TELEPHONY_LOGI("Handle1ValueCallback serious error baseContext nullptr");
        std::string errorCode = std::to_string(napi_invalid_arg);
        std::string errorMessage = "error at baseContext is nullptr";
        NAPI_CALL_RETURN_VOID(env, napi_throw_error(env, errorCode.c_str(), errorMessage.c_str()));
        return;
    }
    if (baseContext->callbackRef != nullptr) {
        TELEPHONY_LOGI("Handle1ValueCallback start normal callback");
        napi_value recv = CreateUndefined(env);
        napi_value callbackFunc = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, baseContext->callbackRef, &callbackFunc));
        napi_value callbackValues[] = {callbackValue};
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, recv, callbackFunc, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, baseContext->callbackRef));
        TELEPHONY_LOGI("Handle1ValueCallback normal callback end");
    } else if (baseContext->deferred != nullptr) {
        TELEPHONY_LOGI("Handle1ValueCallback start promise callback");
        if (baseContext->resolved) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, baseContext->deferred, callbackValue));
            TELEPHONY_LOGI("Handle1ValueCallback napi_resolve_deferred end");
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, baseContext->deferred, callbackValue));
            TELEPHONY_LOGI("Handle1ValueCallback napi_reject_deferred end");
        }
        TELEPHONY_LOGI("Handle1ValueCallback promise callback end");
    }
    napi_delete_async_work(env, baseContext->work);
    delete baseContext;
    baseContext = nullptr;
    TELEPHONY_LOGI("Handle1ValueCallback end");
}

void NapiUtil::Handle2ValueCallback(napi_env env, BaseContext *baseContext, napi_value callbackValue)
{
    TELEPHONY_LOGI("Handle2ValueCallback start");
    if (baseContext == nullptr) {
        TELEPHONY_LOGI("Handle2ValueCallback serious error baseContext nullptr");
        std::string errorCode = std::to_string(napi_invalid_arg);
        std::string errorMessage = "error at baseContext is nullptr";
        NAPI_CALL_RETURN_VOID(env, napi_throw_error(env, errorCode.c_str(), errorMessage.c_str()));
        return;
    }
    if (baseContext->callbackRef != nullptr) {
        TELEPHONY_LOGI("Handle2ValueCallback start normal callback");
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
        TELEPHONY_LOGI("Handle2ValueCallback normal callback end");
    } else if (baseContext->deferred != nullptr) {
        TELEPHONY_LOGI("Handle2ValueCallback start promise callback");
        if (baseContext->resolved) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, baseContext->deferred, callbackValue));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, baseContext->deferred, callbackValue));
        }
        TELEPHONY_LOGI("Handle2ValueCallback promise callback end");
    }
    napi_delete_async_work(env, baseContext->work);
    delete baseContext;
    baseContext = nullptr;
    TELEPHONY_LOGI("Handle2ValueCallback end");
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
} // namespace Telephony
} // namespace OHOS