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

#ifndef CORE_SERVICE_COMMON_NAPI_NAPI_PARAMETER_UTIL_H
#define CORE_SERVICE_COMMON_NAPI_NAPI_PARAMETER_UTIL_H

#include <tuple>
#include <type_traits>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Telephony {
template<typename T, std::enable_if_t<std::is_same_v<T, int32_t>, int32_t> = 0>
napi_valuetype GetInputArgvType(T *)
{
    return napi_number;
}

template<typename T, std::enable_if_t<std::is_same_v<T, napi_ref>, int32_t> = 0>
napi_valuetype GetInputArgvType(T *)
{
    return napi_function;
}

template<typename T, std::enable_if_t<std::is_same_v<T, char>, int32_t> = 0>
napi_valuetype GetInputArgvType(T *)
{
    return napi_string;
}

template<typename T, std::enable_if_t<std::is_same_v<T, std::string>, int32_t> = 0>
napi_valuetype GetInputArgvType(T *)
{
    return napi_string;
}

template<typename T, std::enable_if_t<std::is_same_v<T, napi_value>, int32_t> = 0>
napi_valuetype GetInputArgvType(T *)
{
    return napi_object;
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
    size_t result {0};
    constexpr size_t bufSize { 1024 };
    return napi_get_value_string_utf8(env, arg, buf, bufSize, &result);
}

template<typename T, std::enable_if_t<std::is_same_v<T, napi_value>, int32_t> = 0>
napi_status NapiValueConverted(napi_env env, napi_value arg, T *npaiValue)
{
    *npaiValue = arg;
    return napi_ok;
}

template<typename T, std::enable_if_t<std::is_same_v<T, bool>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, val, &result));
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, int32_t>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, val, &result));
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, uint32_t>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, val, &result));
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, int64_t>, int64_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int64(env, val, &result));
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, std::string>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, const T &val)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, val.c_str(), val.length(), &result));
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, char>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, const T *val)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, val, NAPI_AUTO_LENGTH, &result));
    return result;
}

template<typename T, std::enable_if_t<std::is_same_v<T, napi_value>, int32_t> = 0>
napi_value GetNapiValue(napi_env env, T val)
{
    return val;
}

template<typename T>
void SetPropertyToNapiObject(napi_env env, napi_value object, std::string_view name, T value)
{
    napi_value propertyValue = GetNapiValue(env, value);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.data(), propertyValue));
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

template<typename T, std::enable_if_t<std::is_same_v<T, bool>, int32_t> = 0>
napi_valuetype GetInputArgvType(T *)
{
    return napi_boolean;
}

template<typename... Ts, size_t N>
std::optional<NapiError> MatchParameters(
    napi_env env, const napi_value (&argv)[N], size_t argc, std::tuple<Ts...> &theTuple)
{
    int32_t typeSize = sizeof...(Ts);
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[typeSize - 1], &valueType);
    if (valueType != napi_function) {
        typeSize--;
    }
    std::vector<napi_valuetype> typeStd(typeSize, napi_undefined);

    if (argc != typeStd.size()) {
        return std::optional<NapiError>(ERROR_PARAMETER_COUNTS_INVALID);
    }
    bool typeMatched = true;
    std::apply(
        [argc, &argv, &typeStd](Ts &... tupleArgs) {
            size_t index { 0 };
            ((index < argc ? (typeStd[index++] = GetInputArgvType(tupleArgs)) : true), ...);
        },
        theTuple);
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (valueType != typeStd[i]) {
            typeMatched = false;
            break;
        }
    }
    if (typeMatched) {
        std::apply(
            [env, argc, &argv](Ts &... tupleArgs) {
                size_t index { 0 };
                ((index < argc ? NapiValueConverted(env, argv[index++], tupleArgs) : napi_ok), ...);
            },
            theTuple);
        return std::nullopt;
    }
    return std::optional<NapiError>(ERROR_PARAMETER_TYPE_INVALID);
}
} // namespace Telephony
} // namespace OHOS
#endif
