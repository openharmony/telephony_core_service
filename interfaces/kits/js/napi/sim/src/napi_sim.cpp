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

#include "napi_sim.h"
#include <cstring>
#include <memory>
#include "kit_core_service_hilog_wrapper.h"
#include "sim_card_manager.h"
#include "str_convert.h"

namespace OHOS {
namespace TelephonyNapi {
static std::unique_ptr<SimCardManager> g_simCardManager;
static bool InitSimCardManager()
{
    if (g_simCardManager == nullptr) {
        g_simCardManager = std::make_unique<SimCardManager>();
    }
    return g_simCardManager != nullptr;
}

static char *GetChars(std::string str)
{
    return (char *)str.data();
}

static napi_value CreateErrorMessage(napi_env env, std::string msg)
{
    napi_value result = nullptr;
    napi_value message = nullptr;
    napi_create_string_utf8(env, GetChars(msg), msg.size(), &message);
    napi_create_error(env, nullptr, message, &result);
    return result;
}

static napi_value CreateUndefined(napi_env env)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

static void ExecNativeGetIsoForSim(napi_env env, AsyncContext &asyncContext)
{
    HILOG_DEBUG("Exec ExecNativeGetIsoForSim Start");
    std::string isoCountryCode = "";
    if (InitSimCardManager()) {
        isoCountryCode = ToUtf8(g_simCardManager->GetIsoCountryCode(asyncContext.slotId));
    }
    if (isoCountryCode.empty()) {
        HILOG_DEBUG("Exec ExecNativeGetIsoForSim Start REJECT");
        asyncContext.status = REJECT;
    } else {
        HILOG_DEBUG("Exec ExecNativeGetIsoForSim Start RESOLVED");
        asyncContext.status = RESOLVED;
        char *chars = GetChars(isoCountryCode);
        napi_create_string_utf8(env, chars, strlen(chars), &(asyncContext.value));
    }
}

static void ExecGetIsoForSimCallback(napi_env env, napi_status status, AsyncContext &asyncContext)
{
    HILOG_DEBUG("Exec ExecGetIsoForSimCallback Start");
    if (asyncContext.deferred) {
        if (asyncContext.status == RESOLVED) {
            napi_resolve_deferred(env, asyncContext.deferred, asyncContext.value);
            HILOG_DEBUG("Exec ExecGetIsoForSimCallback deferred ,RESOLVED");
        } else {
            napi_value undefined = CreateUndefined(env);
            napi_reject_deferred(env, asyncContext.deferred, undefined);
            HILOG_DEBUG("Exec ExecGetIsoForSimCallback deferred ,REJECT");
        }
    } else {
        napi_value callbackValue[2] = {0};
        if (asyncContext.status == RESOLVED) {
            callbackValue[0] = CreateUndefined(env);
            callbackValue[1] = asyncContext.value;
            HILOG_DEBUG("Exec ExecGetIsoForSimCallback not deferred ,RESOLVED");
        } else {
            callbackValue[0] = CreateErrorMessage(env, "get iso country code failed");
            callbackValue[1] = CreateUndefined(env);
            HILOG_DEBUG("Exec ExecGetIsoForSimCallback not deferred ,REJECT");
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext.callbackRef, &callback);
        napi_call_function(env, nullptr, callback, TWO_PARAMETER, callbackValue, nullptr);
    }
    napi_delete_reference(env, asyncContext.callbackRef);
    HILOG_DEBUG("Exec ExecGetIsoForSimCallback End");
    delete &asyncContext;
}

static napi_value GetIsoCountryCodeForSim(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("Exec GetIsoCountryCodeForSim start");
    GET_PARAMS(env, info, TWO_PARAMETER);
    NAPI_ASSERT(env, argc >= 1, "requires at least 1 parameter");
    auto asyncContext = new AsyncContext();
    asyncContext->env = env;
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &(asyncContext->slotId));
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &(asyncContext->callbackRef));
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "GetIsoCountryCodeForSim", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecNativeGetIsoForSim(env, *asyncContext);
        },
        [](napi_env env, napi_status status, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecGetIsoForSimCallback(env, status, *asyncContext);
        },
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

static void ExecNativeGetSimOperatorNumeric(napi_env env, AsyncContext &asyncContext)
{
    std::string simOperatorNumeric = "";
    if (InitSimCardManager()) {
        simOperatorNumeric = ToUtf8(g_simCardManager->GetOperatorNumeric(asyncContext.slotId));
    }
    if (simOperatorNumeric.empty()) {
        asyncContext.status = REJECT;
    } else {
        asyncContext.status = RESOLVED;
        char *chars = GetChars(simOperatorNumeric);
        napi_create_string_utf8(env, chars, strlen(chars), &(asyncContext.value));
    }
}

static void ExecGetSimOperatorNumericCallback(napi_env env, napi_status status, AsyncContext &asyncContext)
{
    if (asyncContext.deferred) {
        if (asyncContext.status == RESOLVED) {
            napi_resolve_deferred(env, asyncContext.deferred, asyncContext.value);
        } else {
            napi_value undefined = CreateUndefined(env);
            napi_reject_deferred(env, asyncContext.deferred, undefined);
        }
    } else {
        napi_value result[2] = {0};
        if (asyncContext.status == RESOLVED) {
            result[0] = CreateUndefined(env);
            result[1] = asyncContext.value;
        } else {
            result[0] = CreateErrorMessage(env, "get sim operator numeric failed");
            result[1] = CreateUndefined(env);
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext.callbackRef, &callback);
        napi_call_function(env, nullptr, callback, TWO_PARAMETER, result, nullptr);
    }
    napi_delete_reference(env, asyncContext.callbackRef);
    delete &asyncContext;
}

static napi_value GetSimOperatorNumeric(napi_env env, napi_callback_info info)
{
    GET_PARAMS(env, info, TWO_PARAMETER);
    NAPI_ASSERT(env, argc >= 1, "requires at least 1 parameter");
    auto asyncContext = new AsyncContext();
    asyncContext->env = env;
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &(asyncContext->slotId));
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &(asyncContext->callbackRef));
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "GetSimOperatorNumeric", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecNativeGetSimOperatorNumeric(env, *asyncContext);
        },
        [](napi_env env, napi_status status, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecGetSimOperatorNumericCallback(env, status, *asyncContext);
        },
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

static void ExecNativeGetSimSpn(napi_env env, AsyncContext &asyncContext)
{
    std::string simSpn = "";
    if (InitSimCardManager()) {
        simSpn = ToUtf8(g_simCardManager->GetSpn(asyncContext.slotId));
    }
    if (simSpn.empty()) {
        asyncContext.status = REJECT;
    } else {
        asyncContext.status = RESOLVED;
        char *chars = GetChars(simSpn);
        napi_create_string_utf8(env, chars, strlen(chars), &(asyncContext.value));
    }
}

static void ExecGetSpnCallback(napi_env env, napi_status status, AsyncContext &asyncContext)
{
    if (asyncContext.deferred) {
        if (asyncContext.status == RESOLVED) {
            napi_resolve_deferred(env, asyncContext.deferred, asyncContext.value);
        } else {
            napi_value undefined = CreateUndefined(env);
            napi_reject_deferred(env, asyncContext.deferred, undefined);
        }
    } else {
        napi_value result[2] = {0};
        if (asyncContext.status == RESOLVED) {
            result[0] = CreateUndefined(env);
            result[1] = asyncContext.value;
        } else {
            result[0] = CreateErrorMessage(env, "get sim spn failed");
            result[1] = CreateUndefined(env);
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext.callbackRef, &callback);
        napi_call_function(env, nullptr, callback, TWO_PARAMETER, result, nullptr);
    }
    napi_delete_reference(env, asyncContext.callbackRef);
    delete &asyncContext;
}

static napi_value GetSimSpn(napi_env env, napi_callback_info info)
{
    GET_PARAMS(env, info, TWO_PARAMETER);
    NAPI_ASSERT(env, argc >= 1, "requires at least 1 parameter");
    auto asyncContext = new AsyncContext();
    asyncContext->env = env;
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &(asyncContext->slotId));
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &(asyncContext->callbackRef));
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "GetSimSpn", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecNativeGetSimSpn(env, *asyncContext);
        },
        [](napi_env env, napi_status status, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecGetSpnCallback(env, status, *asyncContext);
        },
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

static void ExecNativeGetSimState(napi_env env, AsyncContext &asyncContext)
{
    HILOG_DEBUG("Exec ExecNativeGetSimState start");
    int32_t simState = -1;
    if (InitSimCardManager()) {
        simState = g_simCardManager->GetSimState(asyncContext.slotId);
        HILOG_DEBUG("Exec ExecNativeGetSimState GetSimState End simState = %d", simState);
    }
    if (simState >= 0) {
        asyncContext.status = RESOLVED;
        napi_create_int32(env, simState, &(asyncContext.value));
    } else {
        asyncContext.status = REJECT;
    }
}

static void ExecGetSimStateCallback(napi_env env, napi_status status, AsyncContext &asyncContext)
{
    HILOG_DEBUG("Exec ExecGetSimStateCallback start");
    if (asyncContext.deferred != nullptr) {
        HILOG_DEBUG("Exec ExecGetSimStateCallback has deferred");
        if (asyncContext.status == RESOLVED) {
            napi_resolve_deferred(env, asyncContext.deferred, asyncContext.value);
        } else {
            napi_value undefined = CreateUndefined(env);
            napi_reject_deferred(env, asyncContext.deferred, undefined);
        }
    } else {
        HILOG_DEBUG("Exec ExecGetSimStateCallback no deferred");
        napi_value result[2] = {0};
        if (asyncContext.status == RESOLVED) {
            result[0] = CreateUndefined(env);
            result[1] = asyncContext.value;
        } else {
            result[0] = CreateErrorMessage(env, "get sim state failed");
            result[1] = CreateUndefined(env);
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext.callbackRef, &callback);
        napi_call_function(env, nullptr, callback, TWO_PARAMETER, result, nullptr);
        HILOG_DEBUG("Exec ExecGetSimStateCallback after call_function");
    }
    napi_delete_reference(env, asyncContext.callbackRef);
    delete &asyncContext;
    HILOG_DEBUG("Exec ExecGetSimStateCallback end");
}

static napi_value GetSimState(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("Exec GetSimState ");
    GET_PARAMS(env, info, TWO_PARAMETER);
    NAPI_ASSERT(env, argc >= 1, "requires at least 1 parameter");
    auto asyncContext = new AsyncContext();
    asyncContext->env = env;
    asyncContext->callbackRef = nullptr;
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == 0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &(asyncContext->slotId));
        } else if (i == 1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &(asyncContext->callbackRef));
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "GetSimState", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecNativeGetSimState(env, *asyncContext);
        },
        [](napi_env env, napi_status status, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecGetSimStateCallback(env, status, *asyncContext);
        },
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work);
    HILOG_DEBUG("Exec GetSimState after napi_queue_async_work");
    return result;
}

EXTERN_C_START
napi_value InitNapiSim(napi_env env, napi_value exports)
{
    napi_value simStateUnknown = nullptr;
    napi_value simStateNotPresent = nullptr;
    napi_value simStateLocked = nullptr;
    napi_value simStateNotReady = nullptr;
    napi_value simStateReady = nullptr;
    napi_value simStateLoaded = nullptr;
    napi_create_int32(env, static_cast<int32_t>(SIM_STATE_UNKNOWN), &simStateUnknown);
    napi_create_int32(env, static_cast<int32_t>(SIM_STATE_NOT_PRESENT), &simStateNotPresent);
    napi_create_int32(env, static_cast<int32_t>(SIM_STATE_LOCKED), &simStateLocked);
    napi_create_int32(env, static_cast<int32_t>(SIM_STATE_NOT_READY), &simStateNotReady);
    napi_create_int32(env, static_cast<int32_t>(SIM_STATE_READY), &simStateReady);
    napi_create_int32(env, static_cast<int32_t>(SIM_STATE_LOADED), &simStateLoaded);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getISOCountryCodeForSim", GetIsoCountryCodeForSim),
        DECLARE_NAPI_FUNCTION("getSimOperatorNumeric", GetSimOperatorNumeric),
        DECLARE_NAPI_FUNCTION("getSimSpn", GetSimSpn), DECLARE_NAPI_FUNCTION("getSimState", GetSimState),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_UNKNOWN", simStateUnknown),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_NOT_PRESENT", simStateNotPresent),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_LOCKED", simStateLocked),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_NOT_READY", simStateNotReady),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_READY", simStateReady),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_LOADED", simStateLoaded)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END

static napi_module _simModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = InitNapiSim,
    .nm_modname = "libtelephony_sim.z.so",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void RegisterSimCardModule(void)
{
    napi_module_register(&_simModule);
}
} // namespace TelephonyNapi
} // namespace OHOS
