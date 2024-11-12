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

#ifndef BASE_TELEPHONY_NAPI_NAPI_UTIL_H
#define BASE_TELEPHONY_NAPI_NAPI_UTIL_H

#include <string>
#include <vector>

#include "base_context.h"
#include "js_error_code.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "telephony_napi_common_error.h"

namespace OHOS {
namespace Telephony {
class NapiUtil {
public:
    static std::string ToUtf8(std::u16string str16);
    static std::u16string ToUtf16(std::string str);
    static napi_value CreateErrorMessage(napi_env env, const std::string &message, int32_t errorCode = ERROR_DEFAULT);
    static napi_value CreateUndefined(napi_env env);
    static bool MatchValueType(napi_env env, napi_value value, napi_valuetype targetType);
    static bool MatchParameters(
        napi_env env, const napi_value parameters[], std::initializer_list<napi_valuetype> valueTypes);
    static void SetPropertyInt32(napi_env env, napi_value object, const std::string &name, int32_t value);
    static void SetPropertyInt64(napi_env env, napi_value object, const std::string &name, int64_t value);
    static void SetPropertyStringUtf8(
        napi_env env, napi_value object, const std::string &name, const std::string &value);
    static void SetPropertyBoolean(napi_env env, napi_value object, const std::string &name, bool value);
    static napi_value ToInt32Value(napi_env env, int value);
    static bool HasNamedProperty(napi_env env, napi_value object, const std::string &propertyName);
    static bool HasNamedTypeProperty(
        napi_env env, napi_value object, napi_valuetype type, const std::string &propertyName);
    static bool MatchObjectProperty(
        napi_env env, napi_value object, std::initializer_list<std::pair<std::string, napi_valuetype>> pairList);
    static bool MatchOptionPropertyType(
        napi_env env, napi_value object, napi_valuetype type, const std::string &propertyName);
    static std::string GetStringFromValue(napi_env env, napi_value value);
    static napi_value GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName);
    static napi_value HandleAsyncWork(napi_env env, BaseContext *context, const std::string &workName,
        napi_async_execute_callback execute, napi_async_complete_callback complete);
    static void Handle1ValueCallback(napi_env env, BaseContext *context, napi_value callbackValue);
    static void Handle2ValueCallback(napi_env env, BaseContext *context, napi_value callbackValue);
    static void DefineEnumClassByName(napi_env env, napi_value exports, std::string_view enumName,
        size_t arrSize, const napi_property_descriptor *desc);
    static JsError ConverErrorMessageForJs(int32_t errorCode);
    static JsError ConverErrorMessageWithPermissionForJs(
        int32_t errorCode, const std::string &funcName, const std::string &permission);
    static void ThrowError(napi_env env, int32_t errorCode, const std::string &message);
    static void ThrowParameterError(napi_env env);
    static void ReleaseBaseContext(napi_env env, BaseContext *baseContext);

private:
    static bool CreateParameterErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateNetworkSearchErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateSimErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateSmsErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateObserverErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateCommonErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateCommonArgumentErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateCommonServiceErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateCommonSystemErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateCallErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateCommonCallErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateVideoCallErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateSupplementServiceCallErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static bool CreateDataErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
    static napi_value CreateError(napi_env env, int32_t err, const std::string &msg);
    static std::string GetErrorMessage(int32_t errorCode);
    static bool CreateVcardErrorMessageForJs(int32_t errorCode, JsErrorCode &jsErrorCode);
};
} // namespace Telephony
} // namespace OHOS
#endif // NAPI_UTIL_H
