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
#include <tuple>
#include <type_traits>
#include <vector>

#include "telephony_napi_common_error.h"
#include "base_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Telephony {
using vecNapiType = std::vector<napi_valuetype>;

class NapiUtil {
public:
    static const int32_t MAX_TEXT_LENGTH = 4096;
    static std::string ToUtf8(std::u16string str16);
    static std::u16string ToUtf16(std::string str);
    static napi_value CreateErrorMessage(napi_env env, std::string message, int32_t errorCode = ERROR_DEFAULT);
    static napi_value CreateUndefined(napi_env env);
    static bool MatchValueType(napi_env env, napi_value value, napi_valuetype targetType);
    static bool MatchParameters(
        napi_env env, const napi_value parameters[], std::initializer_list<napi_valuetype> valueTypes);
    static void SetPropertyInt32(napi_env env, napi_value object, std::string name, int32_t value);
    static void SetPropertyStringUtf8(napi_env env, napi_value object, std::string name, std::string value);
    static void SetPropertyBoolean(napi_env env, napi_value object, std::string name, bool value);
    static napi_value ToInt32Value(napi_env env, int value);
    static bool HasNamedProperty(napi_env env, napi_value object, std::string propertyName);
    static bool HasNamedTypeProperty(
        napi_env env, napi_value object, napi_valuetype type, std::string propertyName);
    static bool MatchObjectProperty(
        napi_env env, napi_value object, std::initializer_list<std::pair<std::string, napi_valuetype>> pairList);
    static bool MatchOptionPropertyType(
        napi_env env, napi_value object, napi_valuetype type, std::string propertyName);
    static std::string GetStringFromValue(napi_env env, napi_value value);
    static napi_value GetNamedProperty(napi_env env, napi_value object, std::string propertyName);
    static napi_value HandleAsyncWork(napi_env env, BaseContext *context, std::string workName,
        napi_async_execute_callback execute, napi_async_complete_callback complete);
    static void Handle1ValueCallback(napi_env env, BaseContext *context, napi_value callbackValue);
    static void Handle2ValueCallback(napi_env env, BaseContext *context, napi_value callbackValue);
};

template<typename T, std::enable_if_t<std::is_same_v<T, bool>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    napi_value result = nullptr;
    napi_get_boolean(env, val, &result);
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, int32_t>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    napi_value result = nullptr;
    napi_create_int32(env, val, &result);
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, std::string>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    napi_value result = nullptr;
    napi_create_string_utf8(env, val.c_str(), val.length(), &result);
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, char>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, const T *val)
{
    napi_value result = nullptr;
    napi_create_string_utf8(env, val, NAPI_AUTO_LENGTH, &result);
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, napi_value>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    return val;
}

template<typename T, std::enable_if_t<std::is_same_v<T, int32_t>, int32_t> = 0>
napi_status NapiValueConverted(napi_env env, napi_value arg, T *val)
{
    return napi_get_value_int32(env, arg, val);
}

template<typename T, std::enable_if_t<std::is_same_v<T, napi_ref>, int32_t> = 0>
napi_status NapiValueConverted(napi_env env, napi_value arg, T *ref)
{
    return napi_create_reference(env, arg, 1, ref);
}

template<typename T, std::enable_if_t<std::is_same_v<T, bool>, int32_t> = 0>
napi_status NapiValueConverted(napi_env env, napi_value arg, T *res)
{
    return napi_get_value_bool(env, arg, res);
}

template<typename T, std::enable_if_t<std::is_same_v<T, char>, int32_t> = 0>
napi_status NapiValueConverted(napi_env env, napi_value arg, T *buf)
{
    constexpr size_t bufSize = 32;
    size_t result {0};
    return napi_get_value_string_utf8(env, arg, buf, bufSize, &result);
}

template<typename T, std::enable_if_t<std::is_same_v<T, napi_value>, int32_t> = 0>
napi_status NapiValueConverted(napi_env env, napi_value arg, T *npaiValue)
{
    *npaiValue = arg;
    return napi_ok;
}

template<typename T>
napi_status NapiValueToCppValue(napi_env env, napi_value arg, napi_valuetype argType, T *val)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    if (valueType == argType) {
        return NapiValueConverted(env, arg, val);
    }
    return napi_invalid_arg;
}

template<typename... Ts>
bool MatchParameters(
    napi_env env, const napi_value argv[], size_t argc, std::tuple<Ts...> &theTuple, const vecNapiType &typeStd)
{
    bool typeMatched = false;
    if (argc == typeStd.size()) {
        vecNapiType paraType;
        paraType.reserve(argc);
        for (size_t i = 0; i < argc; i++) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[i], &valueType);
            paraType.emplace_back(valueType);
        }

        if (paraType == typeStd) {
            std::apply(
                [env, argc, &argv](Ts &...tupleArgs) {
                    size_t index {0};
                    ((index < argc ? NapiValueConverted(env, argv[index++], tupleArgs) : napi_ok), ...);
                },
                theTuple);
            typeMatched = true;
        }
    }
    return typeMatched;
}
} // namespace Telephony
} // namespace OHOS
#endif // NAPI_UTIL_H