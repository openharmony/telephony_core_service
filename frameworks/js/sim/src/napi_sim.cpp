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

#include <memory>
#include <string>
#include <string_view>

#include "core_service_client.h"
#include "napi_parameter_util.h"
#include "napi_sim_type.h"
#include "napi_util.h"
#include "network_state.h"
#include "sim_state_type.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"

namespace OHOS {
namespace Telephony {
namespace {
constexpr const char *CHINA_TELECOM_CARD = "china_telecom_card";
constexpr const char *JS_ERROR_TELEPHONY_ARGUMENT_ERROR_STRING = "Invalid parameter value.";
const int32_t PARAMETER_COUNT_ZERO = 0;
const int32_t PARAMETER_COUNT_ONE = 1;
const int32_t PARAMETER_COUNT_TWO = 2;
struct AsyncPara {
    std::string funcName = "";
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    napi_async_execute_callback execute = nullptr;
    napi_async_complete_callback complete = nullptr;
};
struct PermissionPara {
    std::string func = "";
    std::string permission = "";
};

static inline bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
}

static inline bool IsValidSlotIdEx(int32_t slotId)
{
    // One more slot for VSim.
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT + 1));
}

static inline bool IsValidSlotIdForDefault(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID_REMOVE) && (slotId < SIM_SLOT_COUNT));
}

template<typename T, napi_async_execute_callback exec, napi_async_complete_callback complete>
napi_value NapiCreateAsyncWork(napi_env env, napi_callback_info info, std::string_view funcName)
{
    size_t argc = 2;
    napi_value argv[] {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    std::unique_ptr<AsyncContext<T>> asyncContext = std::make_unique<AsyncContext<T>>();
    BaseContext &context = asyncContext->context;
    auto inParaTp = std::make_tuple(&asyncContext->slotId, &context.callbackRef);
    std::optional<NapiError> errCode = MatchParameters(env, argv, argc, inParaTp);
    if (errCode.has_value()) {
        JsError error = NapiUtil::ConverErrorMessageForJs(errCode.value());
        NapiUtil::ThrowError(env, error.errorCode, error.errorMessage);
        return nullptr;
    }

    napi_value result = nullptr;
    if (context.callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context.deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, funcName.data(), funcName.length(), &resourceName));
    AsyncContext<T> *pContext = asyncContext.release();
    NAPI_CALL(env,
        napi_create_async_work(
            env, nullptr, resourceName, exec, complete, static_cast<void *>(pContext), &context.work));
    if (napi_queue_async_work_with_qos(env, context.work, napi_qos_default) != napi_ok) {
        delete pContext;
        result = nullptr;
    }
    return result;
}

template<typename AsyncContextType, typename... Ts>
napi_value NapiCreateAsyncWork2(const AsyncPara &para, AsyncContextType *asyncContext, std::tuple<Ts...> &theTuple)
{
    napi_env env = para.env;
    BaseContext &context = asyncContext->asyncContext.context;

    size_t argc = sizeof...(Ts);
    napi_value argv[sizeof...(Ts)] {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, para.info, &argc, argv, nullptr, nullptr));

    std::optional<NapiError> errCode = MatchParameters(env, argv, argc, theTuple);
    if (errCode.has_value()) {
        JsError error = NapiUtil::ConverErrorMessageForJs(errCode.value());
        NapiUtil::ThrowError(env, error.errorCode, error.errorMessage);
        delete asyncContext;
        asyncContext = nullptr;
        return nullptr;
    }

    napi_value result = nullptr;
    if (context.callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context.deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, para.funcName.c_str(), para.funcName.length(), &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, para.execute, para.complete,
            static_cast<void *>(asyncContext), &context.work));
    return result;
}

template<typename AsyncContextType, typename... Ts>
napi_value NapiCreateAsyncWork3(const AsyncPara &para, AsyncContextType *asyncContext, std::tuple<Ts...> &theTuple)
{
    napi_env env = para.env;
    BaseContext &context = asyncContext->asyncContext.context;
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, para.info, &parameterCount, parameters, nullptr, nullptr));

    napi_value result = nullptr;
    std::optional<NapiError> errCode = MatchParameters(env, parameters, parameterCount, theTuple);
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        TELEPHONY_LOGI("parameterCount is zero");
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_undefined || valueType == napi_null) {
            TELEPHONY_LOGI("undefined or null parameter detected, treating as no parameter input");
        } else if (valueType == napi_function) {
            TELEPHONY_LOGI("napi_function parameter detected");
        } else {
            if (errCode.has_value()) {
                JsError error = NapiUtil::ConverErrorMessageForJs(errCode.value());
                NapiUtil::ThrowError(env, error.errorCode, error.errorMessage);
                return nullptr;
            }
        }
    } else if (parameterCount >= PARAMETER_COUNT_TWO) {
        if (errCode.has_value()) {
            JsError error = NapiUtil::ConverErrorMessageForJs(errCode.value());
            NapiUtil::ThrowError(env, error.errorCode, error.errorMessage);
            return nullptr;
        }
    }

    if (context.callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context.deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, para.funcName.c_str(), para.funcName.length(), &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, para.execute, para.complete,
                       static_cast<void *>(asyncContext), &context.work));
    return result;
}

template<typename T>
void NapiAsyncCompleteCallback(napi_env env, napi_status status, const AsyncContext<T> &asyncContext,
    const std::string &errMessage, bool funcIgnoreReturnVal = false, int errorCode = ERROR_DEFAULT)
{
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "excute failed");
        return;
    }

    const BaseContext &context = asyncContext.context;
    if (context.deferred != nullptr) {
        if (!context.resolved) {
            napi_value errorMessage = NapiUtil::CreateErrorMessage(env, errMessage, errorCode);
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, errorMessage));
        } else {
            napi_value res =
                (funcIgnoreReturnVal ? NapiUtil::CreateUndefined(env) : GetNapiValue(env, asyncContext.callbackVal));
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, res));
        }
    } else {
        napi_value res =
            (funcIgnoreReturnVal ? NapiUtil::CreateUndefined(env) : GetNapiValue(env, asyncContext.callbackVal));
        napi_value callbackValue[] {NapiUtil::CreateUndefined(env), res};
        if (!context.resolved) {
            callbackValue[0] = NapiUtil::CreateErrorMessage(env, errMessage, errorCode);
            callbackValue[1] = NapiUtil::CreateUndefined(env);
        }
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, context.callbackRef, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValue), callbackValue, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, context.callbackRef));
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, context.work));
}

template<typename T>
void NapiAsyncBaseCompleteCallback(
    napi_env env, const AsyncContext<T> &asyncContext, JsError error, bool funcIgnoreReturnVal = false)
{
    const BaseContext &context = asyncContext.context;
    if (context.deferred != nullptr && !context.resolved) {
        napi_value errorMessage = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, errorMessage));
        NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, context.work));
        TELEPHONY_LOGE("NapiAsyncBaseCompleteCallback deferred error and resolved is false");
        return;
    }

    if (context.deferred != nullptr && context.resolved) {
        napi_value res =
            (funcIgnoreReturnVal ? NapiUtil::CreateUndefined(env) : GetNapiValue(env, asyncContext.callbackVal));
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, res));
        NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, context.work));
        TELEPHONY_LOGE("NapiAsyncBaseCompleteCallback deferred error and resolved is true");
        return;
    }

    napi_value res =
        (funcIgnoreReturnVal ? NapiUtil::CreateUndefined(env) : GetNapiValue(env, asyncContext.callbackVal));
    napi_value callbackValue[] { NapiUtil::CreateUndefined(env), res };
    if (!context.resolved) {
        callbackValue[0] = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
        callbackValue[1] = NapiUtil::CreateUndefined(env);
    }
    napi_value undefined = nullptr;
    napi_value callback = nullptr;
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, context.callbackRef, &callback));
    NAPI_CALL_RETURN_VOID(
        env, napi_call_function(env, undefined, callback, std::size(callbackValue), callbackValue, &result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, context.callbackRef));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, context.work));
}

template<typename T>
void NapiAsyncPermissionCompleteCallback(napi_env env, napi_status status, const AsyncContext<T> &asyncContext,
    bool funcIgnoreReturnVal, PermissionPara permissionPara)
{
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "excute failed");
        return;
    }

    JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
        asyncContext.context.errorCode, permissionPara.func, permissionPara.permission);
    NapiAsyncBaseCompleteCallback(env, asyncContext, error, funcIgnoreReturnVal);
}

template<typename T>
void NapiAsyncCommomCompleteCallback(
    napi_env env, napi_status status, const AsyncContext<T> &asyncContext, bool funcIgnoreReturnVal)
{
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "excute failed");
        return;
    }

    JsError error = NapiUtil::ConverErrorMessageForJs(asyncContext.context.errorCode);
    NapiAsyncBaseCompleteCallback(env, asyncContext, error, funcIgnoreReturnVal);
}

napi_value IccAccountInfoConversion(napi_env env, const IccAccountInfo &iccAccountInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "simId", iccAccountInfo.simId);
    SetPropertyToNapiObject(env, val, "slotIndex", iccAccountInfo.slotIndex);
    SetPropertyToNapiObject(env, val, "isEsim", iccAccountInfo.isEsim);
    SetPropertyToNapiObject(env, val, "isActive", iccAccountInfo.isActive);
    SetPropertyToNapiObject(env, val, "iccId", NapiUtil::ToUtf8(iccAccountInfo.iccId));
    SetPropertyToNapiObject(env, val, "showName", NapiUtil::ToUtf8(iccAccountInfo.showName));
    SetPropertyToNapiObject(env, val, "showNumber", NapiUtil::ToUtf8(iccAccountInfo.showNumber));
    return val;
}

napi_value PinOrPukUnlockConversion(napi_env env, const LockStatusResponse &response)
{
    TELEPHONY_LOGI("PinOrPukUnlockConversion response.result %{public}d, response.remain %{public}d", response.result,
        response.remain);
    constexpr int32_t passWordErr = -1;
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "result", response.result);
    napi_value res =
        (response.result == passWordErr ? GetNapiValue(env, response.remain) : NapiUtil::CreateUndefined(env));
    napi_set_named_property(env, val, "remain", res);
    return val;
}

napi_value OperatorConfigAnalyze(napi_env env, const ConfigInfo &config)
{
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    SetPropertyToNapiObject(env, obj, "field", config.field);
    SetPropertyToNapiObject(env, obj, "value", config.value);
    return obj;
}

napi_value DiallingNumbersConversion(napi_env env, const TelNumbersInfo &info)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "recordNumber", info.recordNumber);
    SetPropertyToNapiObject(env, val, "alphaTag", std::data(info.alphaTag));
    SetPropertyToNapiObject(env, val, "number", std::data(info.number));
    SetPropertyToNapiObject(env, val, "pin2", std::data(info.pin2));
    return val;
}

napi_value SimAuthResultConversion(napi_env env, const SimAuthenticationResponse &responseResult)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    NapiUtil::SetPropertyInt32(env, val, "simStatusWord1", responseResult.sw1);
    NapiUtil::SetPropertyInt32(env, val, "simStatusWord2", responseResult.sw2);
    NapiUtil::SetPropertyStringUtf8(env, val, "response", responseResult.response);
    return val;
}

void GetDiallingNumberInfo(const std::shared_ptr<DiallingNumbersInfo> &telNumber, const TelNumbersInfo &info)
{
    telNumber->index_ = info.recordNumber;
    telNumber->name_ = NapiUtil::ToUtf16(info.alphaTag.data());
    telNumber->number_ = NapiUtil::ToUtf16(info.number.data());
    telNumber->pin2_ = NapiUtil::ToUtf16(info.pin2.data());
}

void DiallingNumberParaAnalyze(napi_env env, napi_value arg, TelNumbersInfo &info)
{
    napi_value recordNumber = NapiUtil::GetNamedProperty(env, arg, "recordNumber");
    if (recordNumber) {
        NapiValueToCppValue(env, recordNumber, napi_number, &info.recordNumber);
    }

    napi_value alphaTag = NapiUtil::GetNamedProperty(env, arg, "alphaTag");
    if (alphaTag) {
        NapiValueToCppValue(env, alphaTag, napi_string, std::data(info.alphaTag));
    }

    napi_value number = NapiUtil::GetNamedProperty(env, arg, "number");
    if (number) {
        NapiValueToCppValue(env, number, napi_string, std::data(info.number));
    }

    napi_value pin2 = NapiUtil::GetNamedProperty(env, arg, "pin2");
    if (pin2) {
        NapiValueToCppValue(env, pin2, napi_string, std::data(info.pin2));
    }
}

void PinInfoParaAnalyze(napi_env env, napi_value arg, AsyncContextPIN &pinContext)
{
    napi_value lockType = NapiUtil::GetNamedProperty(env, arg, "lockType");
    if (lockType) {
        NapiValueToCppValue(env, lockType, napi_number, &pinContext.result);
    }

    napi_value pin = NapiUtil::GetNamedProperty(env, arg, "password");
    if (pin) {
        char tmpStr[ARRAY_SIZE] = {0};
        NapiValueToCppValue(env, pin, napi_string, tmpStr);
        pinContext.inStr1 = std::string(tmpStr);
    }

    napi_value state = NapiUtil::GetNamedProperty(env, arg, "state");
    if (state) {
        NapiValueToCppValue(env, state, napi_number, &pinContext.remain);
    }
}

void PersoLockInfoAnalyze(napi_env env, napi_value arg, AsyncContextPIN &pinContext)
{
    napi_value lockType = NapiUtil::GetNamedProperty(env, arg, "lockType");
    if (lockType) {
        NapiValueToCppValue(env, lockType, napi_number, &pinContext.pinEnable);
    }

    napi_value password = NapiUtil::GetNamedProperty(env, arg, "password");
    if (password) {
        char tmpStr[ARRAY_SIZE] = {0};
        NapiValueToCppValue(env, password, napi_string, tmpStr);
        pinContext.inStr1 = std::string(tmpStr);
    }
}

void NativeIsSimActive(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    if (!IsValidSlotId(reVal->slotId)) {
        TELEPHONY_LOGE("NativeIsSimActive slotId is invalid");
        reVal->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    reVal->callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsSimActive(reVal->slotId);
    TELEPHONY_LOGI("NAPI NativeIsSimActive %{public}d", reVal->callbackVal);
    /* transparent return value */
    reVal->context.resolved = true;
}

void IsSimActiveCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    if (context->context.errorCode == ERROR_SLOT_ID_INVALID) {
        NapiAsyncCompleteCallback(
            env, status, *context, JS_ERROR_TELEPHONY_ARGUMENT_ERROR_STRING, false, JS_ERROR_TELEPHONY_ARGUMENT_ERROR);
    } else {
        NapiAsyncCompleteCallback(env, status, *context, "get simActive state failed");
    }
}

napi_value IsSimActive(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeIsSimActive, IsSimActiveCallback>(env, info, "IsSimActive");
}

napi_value IsSimActiveSync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    bool isSimActive = false;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        NAPI_CALL(env, napi_create_int32(env, isSimActive, &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        NAPI_CALL(env, napi_create_int32(env, isSimActive, &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        isSimActive = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsSimActive(slotId);
    }
    NAPI_CALL(env, napi_get_boolean(env, isSimActive, &value));
    return value;
}

void NativeActivateSim(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *simContext = static_cast<AsyncContext<bool> *>(data);
    if (!IsValidSlotId(simContext->slotId)) {
        TELEPHONY_LOGE("NativeActivateSim slotId is invalid");
        simContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    constexpr int32_t active = 1;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetActiveSim(simContext->slotId, active);
    TELEPHONY_LOGI("NAPI NativeActivateSim %{public}d", errorCode);
    simContext->context.errorCode = errorCode;
    simContext->context.resolved = (errorCode == ERROR_NONE);
}

void ActivateSimCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, true, { "ActivateSim", Permission::SET_TELEPHONY_STATE });
}

napi_value ActivateSim(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeActivateSim, ActivateSimCallback>(env, info, "ActivateSim");
}

void NativeDeactivateSim(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *simContext = static_cast<AsyncContext<bool> *>(data);
    if (!IsValidSlotId(simContext->slotId)) {
        TELEPHONY_LOGE("NativeDeactivateSim slotId is invalid");
        simContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    constexpr int32_t deactive = 0;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().SetActiveSim(simContext->slotId, deactive);
    TELEPHONY_LOGI("NAPI NativeDeactivateSim %{public}d", errorCode);
    simContext->context.errorCode = errorCode;
    simContext->context.resolved = (errorCode == ERROR_NONE);
}

void DeactivateSimCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, true, { "DeactivateSim", Permission::SET_TELEPHONY_STATE });
}

napi_value DeactivateSim(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeDeactivateSim, DeactivateSimCallback>(env, info, "DeactivateSim");
}

void NativeGetDefaultVoiceSlotId(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<int32_t> *asyncContext = &(static_cast<AsyncDefaultSlotId *>(data)->asyncContext);

    asyncContext->callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSlotId();
    TELEPHONY_LOGI("NAPI NativeGetDefaultVoiceSlotId %{public}d", asyncContext->callbackVal);
    asyncContext->context.resolved = (asyncContext->callbackVal > ERROR_DEFAULT);
}

void GetDefaultVoiceSlotIdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDefaultSlotId> context(static_cast<AsyncDefaultSlotId *>(data));
    NapiAsyncCompleteCallback(env, status, context->asyncContext, "get default voice slot id failed");
}

napi_value GetDefaultVoiceSlotId(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncDefaultSlotId();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara = std::make_tuple(&context.callbackRef);
    AsyncPara para {
        .funcName = "GetDefaultVoiceSlotId",
        .env = env,
        .info = info,
        .execute = NativeGetDefaultVoiceSlotId,
        .complete = GetDefaultVoiceSlotIdCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncDefaultSlotId>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetDefaultVoiceSimId(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    AsyncContext<int32_t> *asyncContext = &(static_cast<AsyncDefaultSimId *>(data)->asyncContext);
    int32_t simId = 0;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSimId(simId);
    TELEPHONY_LOGI("error: %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = simId;
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetDefaultVoiceSimIdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDefaultSimId> context(static_cast<AsyncDefaultSimId *>(data));
    NapiAsyncCommomCompleteCallback(env, status, context->asyncContext, false);
}

napi_value GetDefaultVoiceSimId(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncDefaultSimId();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara = std::make_tuple(&context.callbackRef);
    AsyncPara para {
        .funcName = "GetDefaultVoiceSimId",
        .env = env,
        .info = info,
        .execute = NativeGetDefaultVoiceSimId,
        .complete = GetDefaultVoiceSimIdCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncDefaultSimId>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetIsoForSim(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetIsoForSim slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string countryCode;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetISOCountryCodeForSim(
        asyncContext->slotId, countryCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(countryCode);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    TELEPHONY_LOGI("NAPI NativeGetIsoForSim %{public}d", errorCode);
    asyncContext->context.errorCode = errorCode;
}

void GetIsoForSimCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
}

napi_value GetISOCountryCodeForSim(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetIsoForSim, GetIsoForSimCallback>(
        env, info, "GetISOCountryCodeForSim");
}

napi_value GetISOCountryCodeForSimSync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    std::u16string countryCode;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        std::string code = NapiUtil::ToUtf8(countryCode);
        NAPI_CALL(env, napi_create_string_utf8(env, code.c_str(), code.length(), &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        std::string code = NapiUtil::ToUtf8(countryCode);
        NAPI_CALL(env, napi_create_string_utf8(env, code.c_str(), code.length(), &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetISOCountryCodeForSim(slotId, countryCode);
    }
    std::string code = NapiUtil::ToUtf8(countryCode);
    NAPI_CALL(env, napi_create_string_utf8(env, code.c_str(), code.length(), &value));
    return value;
}

void NativeGetSimOperatorNumeric(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetSimOperatorNumeric slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string operatorNumeric;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimOperatorNumeric(
        asyncContext->slotId, operatorNumeric);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(operatorNumeric);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    TELEPHONY_LOGI("NAPI NativeGetSimOperatorNumeric %{public}d", errorCode);
    asyncContext->context.errorCode = errorCode;
}

void GetSimOperatorNumericCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
}

napi_value GetSimOperatorNumeric(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimOperatorNumeric, GetSimOperatorNumericCallback>(
        env, info, "GetSimOperatorNumeric");
}

napi_value GetSimOperatorNumericSync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    std::u16string operatorNumeric;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        std::string numeric = NapiUtil::ToUtf8(operatorNumeric);
        NAPI_CALL(env, napi_create_string_utf8(env, numeric.c_str(), numeric.length(), &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        std::string numeric = NapiUtil::ToUtf8(operatorNumeric);
        NAPI_CALL(env, napi_create_string_utf8(env, numeric.c_str(), numeric.length(), &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimOperatorNumeric(slotId, operatorNumeric);
    }
    std::string numeric = NapiUtil::ToUtf8(operatorNumeric);
    NAPI_CALL(env, napi_create_string_utf8(env, numeric.c_str(), numeric.length(), &value));
    return value;
}

void NativeGetSimSpn(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetSimSpn slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string spn;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimSpn(asyncContext->slotId, spn);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(spn);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    TELEPHONY_LOGI("NAPI NativeGetSimSpn %{public}d", errorCode);
    asyncContext->context.errorCode = errorCode;
}

void GetSimSpnCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
}

napi_value GetSimSpn(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimSpn, GetSimSpnCallback>(env, info, "GetSimSpn");
}

napi_value GetSimSpnSync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    std::u16string spn;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        std::string simSpn = NapiUtil::ToUtf8(spn);
        NAPI_CALL(env, napi_create_string_utf8(env, simSpn.c_str(), simSpn.length(), &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        std::string simSpn = NapiUtil::ToUtf8(spn);
        NAPI_CALL(env, napi_create_string_utf8(env, simSpn.c_str(), simSpn.length(), &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimSpn(slotId, spn);
    }
    std::string simSpn = NapiUtil::ToUtf8(spn);
    NAPI_CALL(env, napi_create_string_utf8(env, simSpn.c_str(), simSpn.length(), &value));
    return value;
}

void NativeGetDsdsMode(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<int32_t> *asyncContext = &(static_cast<AsyncDsdsInfo *>(data)->asyncContext);
    int32_t dsdsMode = DSDS_MODE_V2;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDsdsMode(dsdsMode);
    TELEPHONY_LOGD("NAPI NativeGetDsdsMode %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = dsdsMode;
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetDsdsModeCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDsdsInfo> context(static_cast<AsyncDsdsInfo *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "GetDsdsMode", Permission::GET_TELEPHONY_STATE });
}

napi_value GetDsdsMode(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncDsdsInfo();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara = std::make_tuple(&context.callbackRef);
    AsyncPara para {
        .funcName = "GetDsdsMode",
        .env = env,
        .info = info,
        .execute = NativeGetDsdsMode,
        .complete = GetDsdsModeCallback,
    };
    napi_value result = NapiCreateAsyncWork3<AsyncDsdsInfo>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetSimAuthentication(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncSimAuthInfo *asyncContext = static_cast<AsyncSimAuthInfo *>(data);
    if (!IsValidSlotId(asyncContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetSimAuthentication slotId is invalid");
        asyncContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    SimAuthenticationResponse response;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SimAuthentication(
        asyncContext->asyncContext.slotId, static_cast<AuthType>(asyncContext->authType),
        asyncContext->authData, response);
    TELEPHONY_LOGI("NAPI NativeGetSimAuthentication %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->responseResult = response;
        asyncContext->asyncContext.context.resolved = true;
    } else {
        asyncContext->asyncContext.context.resolved = false;
    }
    asyncContext->asyncContext.context.errorCode = errorCode;
}

void GetSimAuthenticationCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncSimAuthInfo> context(static_cast<AsyncSimAuthInfo *>(data));
    AsyncContext<napi_value> &asyncContext = context->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal =  SimAuthResultConversion(env, context->responseResult);
    }

    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "GetSimAuthentication", Permission::GET_TELEPHONY_STATE });
}

napi_value GetSimAuthentication(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncSimAuthInfo();
    BaseContext &context = asyncContext->asyncContext.context;
    char authDataStr[ARRAY_SIZE] = {0};

    auto initPara = std::make_tuple(&asyncContext->asyncContext.slotId, &asyncContext->authType, authDataStr,
        &context.callbackRef);
    AsyncPara para {
        .funcName = "GetSimAuthentication",
        .env = env,
        .info = info,
        .execute = NativeGetSimAuthentication,
        .complete = GetSimAuthenticationCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncSimAuthInfo>(para, asyncContext, initPara);
    if (result) {
        asyncContext->authData = std::string(authDataStr);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetSimState(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimState(asyncContext->slotId, simState);
    TELEPHONY_LOGI("NAPI NativeGetSimState %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->context.resolved = true;
        asyncContext->callbackVal = static_cast<int32_t>(simState);
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetSimStateCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
    TELEPHONY_LOGI("GetSimStateCallback end");
}

napi_value GetSimState(napi_env env, napi_callback_info info)
{
    TELEPHONY_LOGI("GetSimState start");
    return NapiCreateAsyncWork<int32_t, NativeGetSimState, GetSimStateCallback>(env, info, "GetSimState");
}

napi_value GetSimStateSync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(simState), &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(simState), &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimState(slotId, simState);
    }
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(simState), &value));
    return value;
}

void NativeGetCardType(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetCardType slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    CardType cardType = CardType::UNKNOWN_CARD;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCardType(asyncContext->slotId, cardType);
    TELEPHONY_LOGI("NAPI NativeGetCardType %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->context.resolved = true;
        asyncContext->callbackVal = static_cast<int32_t>(cardType);
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetCardTypeCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
}

napi_value GetCardType(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<int32_t, NativeGetCardType, GetCardTypeCallback>(env, info, "GetCardType");
}

napi_value GetCardTypeSync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    CardType cardType = CardType::UNKNOWN_CARD;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(cardType), &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(cardType), &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCardType(slotId, cardType);
    }
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(cardType), &value));
    return value;
}

void NativeGetVoiceMailIdentifier(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetVoiceMailIdentifier slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string voiceMailIdentifier;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetVoiceMailIdentifier(
        asyncContext->slotId, voiceMailIdentifier);
    TELEPHONY_LOGI("NAPI NativeGetVoiceMailIdentifier %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(voiceMailIdentifier);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetVoiceMailIdentifierCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetVoiceMailIdentifier", Permission::GET_TELEPHONY_STATE });
}

napi_value GetVoiceMailIdentifier(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetVoiceMailIdentifier, GetVoiceMailIdentifierCallback>(
        env, info, "GetVoiceMailIdentifier");
}

void NativeGetVoiceMailNumber(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetVoiceMailNumber slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string voiceMailNumber;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetVoiceMailNumber(asyncContext->slotId, voiceMailNumber);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(voiceMailNumber);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetVoiceMailNumberCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetVoiceMailNumber", Permission::GET_TELEPHONY_STATE });
}

napi_value GetVoiceMailNumber(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetVoiceMailNumber, GetVoiceMailNumberCallback>(
        env, info, "GetVoiceMailNumber");
}

void NativeGetVoiceMailCount(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetVoiceMailCount slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t voiceMailCount = ERROR_DEFAULT;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetVoiceMailCount(asyncContext->slotId, voiceMailCount);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = voiceMailCount;
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetVoiceMailCountCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetVoiceMailCount", Permission::GET_TELEPHONY_STATE });
}

napi_value GetVoiceMailCount(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<int32_t, NativeGetVoiceMailCount, GetVoiceMailCountCallback>(
        env, info, "GetVoiceMailCount");
}

void NativeGetSimTelephoneNumber(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetSimTelephoneNumber slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string telephoneNumber;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimTelephoneNumber(
        asyncContext->slotId, telephoneNumber);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(telephoneNumber);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetSimTelephoneNumberCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetSimTelephoneNumber", Permission::GET_TELEPHONY_STATE });
}

napi_value GetSimTelephoneNumber(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimTelephoneNumber, GetSimTelephoneNumberCallback>(
        env, info, "GetSimTelephoneNumber");
}

void NativeGetSimGid1(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetSimGid1 slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string gid1;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimGid1(asyncContext->slotId, gid1);
    TELEPHONY_LOGI("NAPI NativeGetSimGid1 %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(gid1);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetSimGid1Callback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetSimGid1", Permission::GET_TELEPHONY_STATE });
}

napi_value GetSimGid1(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimGid1, GetSimGid1Callback>(env, info, "GetSimGid1");
}

void NativeGetSimIccId(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetSimIccId slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string iccId;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimIccId(asyncContext->slotId, iccId);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(iccId);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetSimIccIdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetSimIccId", Permission::GET_TELEPHONY_STATE });
}

napi_value GetSimIccId(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimIccId, GetSimIccIdCallback>(env, info, "GetSimIccId");
}

void NativeGetSimAccountInfo(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncIccAccountInfo *info = static_cast<AsyncIccAccountInfo *>(data);
    if (!IsValidSlotIdEx(info->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetSimAccountInfo slotId is invalid");
        info->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    IccAccountInfo operInfo;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimAccountInfo(info->asyncContext.slotId, operInfo);
    TELEPHONY_LOGI("NAPI NativeGetSimAccountInfo %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        info->vecInfo.push_back(std::move(operInfo));
        info->asyncContext.context.resolved = true;
    } else {
        info->asyncContext.context.resolved = false;
    }
    info->asyncContext.context.errorCode = errorCode;
}

void GetSimAccountInfoCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncIccAccountInfo> info(static_cast<AsyncIccAccountInfo *>(data));
    AsyncContext<napi_value> &asyncContext = info->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal = IccAccountInfoConversion(env, info->vecInfo.at(0));
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, asyncContext, false, { "GetSimAccountInfo", Permission::GET_TELEPHONY_STATE });
}

napi_value GetSimAccountInfo(napi_env env, napi_callback_info info)
{
    auto iccAccountInfo = new AsyncIccAccountInfo();
    BaseContext &context = iccAccountInfo->asyncContext.context;

    auto initPara = std::make_tuple(&iccAccountInfo->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "GetSimAccountInfo",
        .env = env,
        .info = info,
        .execute = NativeGetSimAccountInfo,
        .complete = GetSimAccountInfoCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncIccAccountInfo>(para, iccAccountInfo, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeSetDefaultVoiceSlotId(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    if (!IsValidSlotIdForDefault(reVal->slotId)) {
        TELEPHONY_LOGE("NativeSetDefaultVoiceSlotId slotId is invalid");
        reVal->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetDefaultVoiceSlotId(reVal->slotId);
    TELEPHONY_LOGI("NAPI NativeSetDefaultVoiceSlotId %{public}d", errorCode);
    reVal->context.errorCode = errorCode;
    reVal->context.resolved = (errorCode == ERROR_NONE);
}

void SetDefaultVoiceSlotIdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, true, { "SetDefaultVoiceSlotId", Permission::SET_TELEPHONY_STATE });
}

napi_value SetDefaultVoiceSlotId(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeSetDefaultVoiceSlotId, SetDefaultVoiceSlotIdCallback>(
        env, info, "SetDefaultVoiceSlotId");
}

void NativeUnlockPin(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *pinContext = static_cast<AsyncContextPIN *>(data);
    if (!IsValidSlotId(pinContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeUnlockPin slotId is invalid");
        pinContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPin(
        pinContext->asyncContext.slotId, NapiUtil::ToUtf16(pinContext->inStr1.data()), response);
    TELEPHONY_LOGI("NAPI NativeUnlockPin %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        pinContext->result = response.result;
        pinContext->remain = response.remain;
        pinContext->asyncContext.context.resolved = true;
    } else {
        pinContext->asyncContext.context.resolved = false;
    }
    pinContext->asyncContext.context.errorCode = errorCode;
}

void UnlockPinCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->asyncContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "UnlockPin", Permission::SET_TELEPHONY_STATE });
}

napi_value UnlockPin(napi_env env, napi_callback_info info)
{
    auto pinContext = new AsyncContextPIN();
    BaseContext &context = pinContext->asyncContext.context;
    char tmpStr[ARRAY_SIZE] = {0};

    auto initPara = std::make_tuple(&pinContext->asyncContext.slotId, tmpStr, &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockPin",
        .env = env,
        .info = info,
        .execute = NativeUnlockPin,
        .complete = UnlockPinCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextPIN>(para, pinContext, initPara);
    if (result) {
        pinContext->inStr1 = std::string(tmpStr);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeUnlockPuk(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *pukContext = static_cast<AsyncContextPIN *>(data);
    if (!IsValidSlotId(pukContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeUnlockPuk slotId is invalid");
        pukContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPuk(pukContext->asyncContext.slotId,
        NapiUtil::ToUtf16(pukContext->inStr1.data()), NapiUtil::ToUtf16(pukContext->inStr2.data()), response);
    TELEPHONY_LOGI("NAPI NativeUnlockPuk %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        pukContext->result = response.result;
        pukContext->remain = response.remain;
        pukContext->asyncContext.context.resolved = true;
    } else {
        pukContext->asyncContext.context.resolved = false;
    }
    pukContext->asyncContext.context.errorCode = errorCode;
}

void UnlockPukCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->asyncContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "UnlockPuk", Permission::SET_TELEPHONY_STATE });
}

napi_value UnlockPuk(napi_env env, napi_callback_info info)
{
    auto pukContext = new AsyncContextPIN();
    BaseContext &context = pukContext->asyncContext.context;
    char tmpStr1[ARRAY_SIZE] = {0};
    char tmpStr2[ARRAY_SIZE] = {0};

    auto initPara = std::make_tuple(&pukContext->asyncContext.slotId, tmpStr1, tmpStr2, &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockPuk",
        .env = env,
        .info = info,
        .execute = NativeUnlockPuk,
        .complete = UnlockPukCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextPIN>(para, pukContext, initPara);
    if (result) {
        pukContext->inStr1 = std::string(tmpStr1);
        pukContext->inStr2 = std::string(tmpStr2);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeAlterPin(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    AsyncContextPIN *alterPinContext = static_cast<AsyncContextPIN *>(data);
    if (!IsValidSlotId(alterPinContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeAlterPin slotId is invalid");
        alterPinContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().AlterPin(
        alterPinContext->asyncContext.slotId, NapiUtil::ToUtf16(alterPinContext->inStr1.data()),
        NapiUtil::ToUtf16(alterPinContext->inStr2.data()), response);
    TELEPHONY_LOGI("NAPI NativeAlterPin %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        alterPinContext->result = response.result;
        alterPinContext->remain = response.remain;
        alterPinContext->asyncContext.context.resolved = true;
    } else {
        alterPinContext->asyncContext.context.resolved = false;
    }
    alterPinContext->asyncContext.context.errorCode = errorCode;
}

void AlterPinCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->asyncContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "AlterPin", Permission::SET_TELEPHONY_STATE });
}

napi_value AlterPin(napi_env env, napi_callback_info info)
{
    auto alterPinContext = new AsyncContextPIN();
    BaseContext &context = alterPinContext->asyncContext.context;

    char tmpStr1[ARRAY_SIZE] = {0};
    char tmpStr2[ARRAY_SIZE] = {0};
    auto initPara = std::make_tuple(&alterPinContext->asyncContext.slotId, tmpStr1, tmpStr2, &context.callbackRef);
    AsyncPara para {
        .funcName = "AlterPin",
        .env = env,
        .info = info,
        .execute = NativeAlterPin,
        .complete = AlterPinCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextPIN>(para, alterPinContext, initPara);
    if (result) {
        alterPinContext->inStr1 = std::string(tmpStr1);
        alterPinContext->inStr2 = std::string(tmpStr2);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeSetLockState(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *lockContext = static_cast<AsyncContextPIN *>(data);
    if (!IsValidSlotId(lockContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeSetLockState slotId is invalid");
        lockContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };
    TELEPHONY_LOGI("NativeSetLockState slotId = %{public}d, lockType = %{public}d, state = %{public}d",
        lockContext->asyncContext.slotId, lockContext->result, lockContext->remain);
    const LockInfo info { static_cast<LockType>(lockContext->result), NapiUtil::ToUtf16(lockContext->inStr1.data()),
        static_cast<LockState>(lockContext->remain) };
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetLockState(
        lockContext->asyncContext.slotId, info, response);
    TELEPHONY_LOGI("NAPI NativeSetLockState %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        lockContext->result = response.result;
        lockContext->remain = response.remain;
        lockContext->asyncContext.context.resolved = true;
    } else {
        lockContext->asyncContext.context.resolved = false;
    }
    lockContext->asyncContext.context.errorCode = errorCode;
}

void SetLockStateCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->asyncContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "SetLockState", Permission::SET_TELEPHONY_STATE });
}

napi_value SetLockState(napi_env env, napi_callback_info info)
{
    auto asyncContextPIN = new AsyncContextPIN;
    BaseContext &context = asyncContextPIN->asyncContext.context;
    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara = std::make_tuple(&asyncContextPIN->asyncContext.slotId, &object, &context.callbackRef);
    AsyncPara para {
        .funcName = "SetLockState",
        .env = env,
        .info = info,
        .execute = NativeSetLockState,
        .complete = SetLockStateCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextPIN>(para, asyncContextPIN, initPara);
    if (result) {
        PinInfoParaAnalyze(env, object, *asyncContextPIN);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeHasSimCard(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    if (!IsValidSlotIdEx(reVal->slotId)) {
        TELEPHONY_LOGE("slotId is invalid");
        reVal->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    bool hasSimCard = false;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(reVal->slotId, hasSimCard);
    if (errorCode == ERROR_NONE) {
        reVal->callbackVal = hasSimCard;
        reVal->context.resolved = true;
    } else {
        reVal->context.resolved = false;
    }
    TELEPHONY_LOGD("errorCode is %{public}d", errorCode);
    reVal->context.errorCode = errorCode;
}

void HasSimCardCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
}

napi_value HasSimCard(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeHasSimCard, HasSimCardCallback>(env, info, "HasSimCard");
}

napi_value HasSimCardSync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    bool hasSimCard = false;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        NAPI_CALL(env, napi_create_int32(env, hasSimCard, &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        NAPI_CALL(env, napi_create_int32(env, hasSimCard, &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasSimCard);
    }
    NAPI_CALL(env, napi_get_boolean(env, hasSimCard, &value));
    return value;
}

void NativeGetIMSI(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetIMSI slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string imsi;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetIMSI(asyncContext->slotId, imsi);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(imsi);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetIMSICallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncPermissionCompleteCallback(env, status, *context, false, { "GetIMSI", Permission::GET_TELEPHONY_STATE });
}

napi_value GetIMSI(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetIMSI, GetIMSICallback>(env, info, "GetIMSI");
}

napi_value IsOperatorSimCard(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    if (parameterCount != PARAMETER_COUNT_TWO ||
        !NapiUtil::MatchParameters(env, parameters, { napi_number, napi_string })) {
        TELEPHONY_LOGE("parameter type is incorrect");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    int32_t slotId = -1;
    napi_get_value_int32(env, parameters[0], &slotId);
    if (!IsValidSlotId(slotId)) {
        NapiUtil::ThrowError(env, JS_ERROR_TELEPHONY_ARGUMENT_ERROR, JS_ERROR_TELEPHONY_ARGUMENT_ERROR_STRING);
        return nullptr;
    }
    std::string operatorSimCard = NapiUtil::GetStringFromValue(env, parameters[1]);
    int32_t errorCode = TELEPHONY_SUCCESS;
    bool isOperatorSimCard = false;
    if (!operatorSimCard.compare(CHINA_TELECOM_CARD)) {
        errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsCTSimCard(slotId, isOperatorSimCard);
    } else {
        errorCode = TELEPHONY_ERR_ARGUMENT_MISMATCH;
    }
    if (errorCode != TELEPHONY_SUCCESS) {
        JsError error = NapiUtil::ConverErrorMessageForJs(errorCode);
        NapiUtil::ThrowError(env, error.errorCode, error.errorMessage);
        return nullptr;
    }
    napi_value value = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isOperatorSimCard, &value));
    return value;
}

void NativeSetShowName(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext2 *context = static_cast<AsyncContext2 *>(data);
    if (!IsValidSlotId(context->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeSetShowName slotId is invalid");
        context->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string name = NapiUtil::ToUtf16(std::data(context->inputStr));
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().SetShowName(context->asyncContext.slotId, name);
    TELEPHONY_LOGI("NAPI NativeSetShowName %{public}d", errorCode);
    context->asyncContext.context.errorCode = errorCode;
    context->asyncContext.context.resolved = (errorCode == ERROR_NONE);
}

void SetShowNameCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext2> context(static_cast<AsyncContext2 *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "SetShowName", Permission::SET_TELEPHONY_STATE });
}

napi_value SetShowName(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncContext2();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara =
        std::make_tuple(&asyncContext->asyncContext.slotId, std::data(asyncContext->inputStr),
            &context.callbackRef);
    AsyncPara para {
        .funcName = "SetShowName",
        .env = env,
        .info = info,
        .execute = NativeSetShowName,
        .complete = SetShowNameCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContext2>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetShowName(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetShowName slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string showName;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetShowName(asyncContext->slotId, showName);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(showName);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetShowNameCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetShowName", Permission::GET_TELEPHONY_STATE });
}

napi_value GetShowName(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetShowName, GetShowNameCallback>(env, info, "GetShowName");
}

void NativeSetShowNumber(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext2 *context = static_cast<AsyncContext2 *>(data);
    if (!IsValidSlotId(context->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeSetShowNumber slotId is invalid");
        context->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetShowNumber(
        context->asyncContext.slotId, NapiUtil::ToUtf16(std::data(context->inputStr)));
    TELEPHONY_LOGI("NAPI NativeSetShowNumber %{public}d", errorCode);
    context->asyncContext.context.errorCode = errorCode;
    context->asyncContext.context.resolved = (errorCode == ERROR_NONE);
}

void SetShowNumberCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext2> context(static_cast<AsyncContext2 *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "SetShowNumber", Permission::SET_TELEPHONY_STATE });
}

napi_value SetShowNumber(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncContext2();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara =
        std::make_tuple(&asyncContext->asyncContext.slotId, std::data(asyncContext->inputStr), &context.callbackRef);
    AsyncPara para {
        .funcName = "SetShowNumber",
        .env = env,
        .info = info,
        .execute = NativeSetShowNumber,
        .complete = SetShowNumberCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContext2>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetShowNumber(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetShowNumber slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string showNumber;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetShowNumber(asyncContext->slotId, showNumber);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(showNumber);
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetShowNumberCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetShowNumber", Permission::GET_TELEPHONY_STATE });
}

napi_value GetShowNumber(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetShowNumber, GetShowNumberCallback>(env, info, "GetShowNumber");
}

void NativeUnlockPin2(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *pinContext = static_cast<AsyncContextPIN *>(data);
    if (!IsValidSlotId(pinContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeUnlockPin2 slotId is invalid");
        pinContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPin2(
        pinContext->asyncContext.slotId, NapiUtil::ToUtf16(pinContext->inStr1.data()), response);
    TELEPHONY_LOGI("NAPI NativeUnlockPin2 %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        pinContext->result = response.result;
        pinContext->remain = response.remain;
        pinContext->asyncContext.context.resolved = true;
    } else {
        pinContext->asyncContext.context.resolved = false;
    }
    pinContext->asyncContext.context.errorCode = errorCode;
}

void UnlockPinCallback2(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->asyncContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "UnlockPin2", Permission::SET_TELEPHONY_STATE });
}

napi_value UnlockPin2(napi_env env, napi_callback_info info)
{
    auto pinContext = new AsyncContextPIN();
    BaseContext &context = pinContext->asyncContext.context;

    char tmpStr[ARRAY_SIZE] = {0};
    auto initPara = std::make_tuple(&pinContext->asyncContext.slotId, tmpStr, &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockPin2",
        .env = env,
        .info = info,
        .execute = NativeUnlockPin2,
        .complete = UnlockPinCallback2,
    };
    napi_value result = NapiCreateAsyncWork2(para, pinContext, initPara);
    if (result) {
        pinContext->inStr1 = std::string(tmpStr);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeUnlockPuk2(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *pukContext = static_cast<AsyncContextPIN *>(data);
    if (!IsValidSlotId(pukContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeUnlockPuk2 slotId is invalid");
        pukContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPuk2(pukContext->asyncContext.slotId,
            NapiUtil::ToUtf16(pukContext->inStr1.data()), NapiUtil::ToUtf16(pukContext->inStr2.data()), response);
    TELEPHONY_LOGI("NAPI NativeUnlockPuk2 %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        pukContext->result = response.result;
        pukContext->remain = response.remain;
        pukContext->asyncContext.context.resolved = true;
    } else {
        pukContext->asyncContext.context.resolved = false;
    }
    pukContext->asyncContext.context.errorCode = errorCode;
}

void UnlockPukCallback2(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->asyncContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "UnlockPuk2", Permission::SET_TELEPHONY_STATE });
}

napi_value UnlockPuk2(napi_env env, napi_callback_info info)
{
    auto pinContext = new AsyncContextPIN();
    BaseContext &context = pinContext->asyncContext.context;
    char tmpStr1[ARRAY_SIZE] = {0};
    char tmpStr2[ARRAY_SIZE] = {0};

    auto initPara = std::make_tuple(&pinContext->asyncContext.slotId, tmpStr1,
        tmpStr2, &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockPuk2",
        .env = env,
        .info = info,
        .execute = NativeUnlockPuk2,
        .complete = UnlockPukCallback2,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextPIN>(para, pinContext, initPara);
    if (result) {
        pinContext->inStr1 = std::string(tmpStr1);
        pinContext->inStr2 = std::string(tmpStr2);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeAlterPin2(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *pinContext = static_cast<AsyncContextPIN *>(data);
    if (!IsValidSlotId(pinContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeAlterPin2 slotId is invalid");
        pinContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().AlterPin2(pinContext->asyncContext.slotId,
        NapiUtil::ToUtf16(pinContext->inStr1.data()), NapiUtil::ToUtf16(pinContext->inStr2.data()), response);
    TELEPHONY_LOGI("NAPI NativeAlterPin2 %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        pinContext->result = response.result;
        pinContext->remain = response.remain;
        pinContext->asyncContext.context.resolved = true;
    } else {
        pinContext->asyncContext.context.resolved = false;
    }
    pinContext->asyncContext.context.errorCode = errorCode;
}

void AlterPinCallback2(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->asyncContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "AlterPin2", Permission::SET_TELEPHONY_STATE });
}

napi_value AlterPin2(napi_env env, napi_callback_info info)
{
    auto pinContext = new AsyncContextPIN();
    BaseContext &context = pinContext->asyncContext.context;
    char tmpStr1[ARRAY_SIZE] = {0};
    char tmpStr2[ARRAY_SIZE] = {0};

    auto initPara = std::make_tuple(&pinContext->asyncContext.slotId, tmpStr1, tmpStr2, &context.callbackRef);
    AsyncPara para {
        .funcName = "AlterPin2",
        .env = env,
        .info = info,
        .execute = NativeAlterPin2,
        .complete = AlterPinCallback2,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextPIN>(para, pinContext, initPara);
    if (result) {
        pinContext->inStr1 = std::string(tmpStr1);
        pinContext->inStr2 = std::string(tmpStr2);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetOperatorConfigs(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncOperatorConfig *info = static_cast<AsyncOperatorConfig *>(data);
    if (!IsValidSlotId(info->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetOperatorConfigs slotId is invalid");
        info->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    OperatorConfig config;
    int32_t errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorConfigs(info->asyncContext.slotId, config);
    TELEPHONY_LOGI("NAPI NativeGetOperatorConfigs %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        for (const auto &val : config.configValue) {
            ConfigInfo &&config = {NapiUtil::ToUtf8(val.first), NapiUtil::ToUtf8(val.second)};
            info->configValue.push_back(config);
        }
        info->asyncContext.context.resolved = true;
    } else {
        info->asyncContext.context.resolved = false;
    }
    info->asyncContext.context.errorCode = errorCode;
}

void GetOperatorConfigsCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncOperatorConfig> operatorConfig(static_cast<AsyncOperatorConfig *>(data));
    AsyncContext<napi_value> &aContext = operatorConfig->asyncContext;
    if (aContext.context.resolved) {
        aContext.callbackVal = nullptr;
        napi_create_array(env, &aContext.callbackVal);
        for (size_t i = 0; i < operatorConfig->configValue.size(); i++) {
            napi_value val = OperatorConfigAnalyze(env, operatorConfig->configValue.at(i));
            napi_set_element(env, aContext.callbackVal, i, val);
        }
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, aContext, false, { "GetOperatorConfigs", Permission::GET_TELEPHONY_STATE });
}

napi_value GetOperatorConfigs(napi_env env, napi_callback_info info)
{
    auto crrierConfig = new AsyncOperatorConfig();
    BaseContext &context = crrierConfig->asyncContext.context;

    auto initPara = std::make_tuple(&crrierConfig->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "GetOperatorConfigs",
        .env = env,
        .info = info,
        .execute = NativeGetOperatorConfigs,
        .complete = GetOperatorConfigsCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncOperatorConfig>(para, crrierConfig, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetActiveSimAccountInfoList(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncIccAccountInfo *accountInfo = static_cast<AsyncIccAccountInfo *>(data);
    accountInfo->vecInfo.clear();
    std::vector<IccAccountInfo> activeInfo;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetActiveSimAccountInfoList(activeInfo);
    TELEPHONY_LOGI("NAPI NativeGetActiveSimAccountInfoList %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        accountInfo->vecInfo.swap(activeInfo);
        accountInfo->asyncContext.context.resolved = true;
    } else {
        accountInfo->asyncContext.context.resolved = false;
    }
    accountInfo->asyncContext.context.errorCode = errorCode;
}

void GetActiveSimAccountInfoListCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncIccAccountInfo> info(static_cast<AsyncIccAccountInfo *>(data));
    AsyncContext<napi_value> &asyncContext = info->asyncContext;
    asyncContext.callbackVal = nullptr;
    napi_create_array(env, &asyncContext.callbackVal);
    for (size_t i = 0; i < info->vecInfo.size(); i++) {
        napi_value val = IccAccountInfoConversion(env, info->vecInfo.at(i));
        napi_set_element(env, asyncContext.callbackVal, i, val);
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, asyncContext, false, { "GetActiveSimAccountInfoList", Permission::GET_TELEPHONY_STATE });
}

napi_value GetActiveSimAccountInfoList(napi_env env, napi_callback_info info)
{
    auto accountInfo = new AsyncIccAccountInfo();
    BaseContext &context = accountInfo->asyncContext.context;

    auto initPara = std::make_tuple(&context.callbackRef);
    AsyncPara para {
        .funcName = "GetActiveSimAccountInfoList",
        .env = env,
        .info = info,
        .execute = NativeGetActiveSimAccountInfoList,
        .complete = GetActiveSimAccountInfoListCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncIccAccountInfo>(para, accountInfo, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeQueryIccDiallingNumbers(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncDiallingNumbers<napi_value> *diallingNumbers = static_cast<AsyncDiallingNumbers<napi_value> *>(data);
    if (!IsValidSlotId(diallingNumbers->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeQueryIccDiallingNumbers slotId is invalid");
        diallingNumbers->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbersResult;
    diallingNumbersResult.clear();
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().QueryIccDiallingNumbers(
        diallingNumbers->asyncContext.slotId, diallingNumbers->type, diallingNumbersResult);
    TELEPHONY_LOGI("NAPI NativeQueryIccDiallingNumbers %{public}zu", diallingNumbersResult.size());
    if (!diallingNumbersResult.empty()) {
        std::vector<TelNumbersInfo> &dialNumbers = diallingNumbers->infoVec;
        for (const auto &dialNumber : diallingNumbersResult) {
            TelNumbersInfo info {};
            NapiUtil::ToUtf8(dialNumber->name_).copy(info.alphaTag.data(), ARRAY_SIZE);
            NapiUtil::ToUtf8(dialNumber->number_).copy(info.number.data(), ARRAY_SIZE);
            info.recordNumber = dialNumber->index_;
            dialNumbers.push_back(std::move(info));
        }
    }
    diallingNumbers->asyncContext.context.errorCode = errorCode;
    diallingNumbers->asyncContext.context.resolved = (errorCode == ERROR_NONE);
}

void QueryIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDiallingNumbers<napi_value>> diallingNumbers(
        static_cast<AsyncDiallingNumbers<napi_value> *>(data));
    diallingNumbers->asyncContext.callbackVal = nullptr;
    napi_create_array(env, &diallingNumbers->asyncContext.callbackVal);
    for (size_t i = 0; i < diallingNumbers->infoVec.size(); i++) {
        napi_value val = DiallingNumbersConversion(env, diallingNumbers->infoVec.at(i));
        napi_set_element(env, diallingNumbers->asyncContext.callbackVal, i, val);
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, diallingNumbers->asyncContext, false, { "QueryIccDiallingNumbers", Permission::READ_CONTACTS });
}

napi_value QueryIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    auto diallingNumbers = new AsyncDiallingNumbers<napi_value>();
    BaseContext &context = diallingNumbers->asyncContext.context;

    auto initPara =
        std::make_tuple(&diallingNumbers->asyncContext.slotId, &diallingNumbers->type, &context.callbackRef);
    AsyncPara para {
        .funcName = "QueryIccDiallingNumbers",
        .env = env,
        .info = info,
        .execute = NativeQueryIccDiallingNumbers,
        .complete = QueryIccDiallingNumbersCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncDiallingNumbers<napi_value>>(para, diallingNumbers, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeAddIccDiallingNumbers(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncDiallingNumbers<int32_t> *diallingNumbersContext = static_cast<AsyncDiallingNumbers<int32_t> *>(data);
    AsyncContext<int32_t> &asyncContext = diallingNumbersContext->asyncContext;
    if (!IsValidSlotId(asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeAddIccDiallingNumbers slotId is invalid");
        asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    if (diallingNumbersContext->infoVec.size() > 0) {
        std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
        GetDiallingNumberInfo(telNumber, diallingNumbersContext->infoVec.at(0));
        int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().AddIccDiallingNumbers(
            asyncContext.slotId, diallingNumbersContext->type, telNumber);
        TELEPHONY_LOGI("NAPI NativeAddIccDiallingNumbers errorCode: %{public}d", errorCode);
        asyncContext.context.errorCode = errorCode;
        asyncContext.context.resolved = (errorCode == ERROR_NONE);
    }
}

void AddIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDiallingNumbers<int32_t>> context(static_cast<AsyncDiallingNumbers<int32_t> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "AddIccDiallingNumbers", Permission::WRITE_CONTACTS });
}

napi_value AddIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    auto diallingNumbers = new AsyncDiallingNumbers<int32_t>();
    BaseContext &context = diallingNumbers->asyncContext.context;

    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara =
        std::make_tuple(&diallingNumbers->asyncContext.slotId, &diallingNumbers->type, &object, &context.callbackRef);

    AsyncPara para {
        .funcName = "AddIccDiallingNumbers",
        .env = env,
        .info = info,
        .execute = NativeAddIccDiallingNumbers,
        .complete = AddIccDiallingNumbersCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncDiallingNumbers<int32_t>>(para, diallingNumbers, initPara);
    if (result) {
        TelNumbersInfo inputInfo;
        DiallingNumberParaAnalyze(env, object, inputInfo);
        diallingNumbers->infoVec.push_back(std::move(inputInfo));
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeDelIccDiallingNumbers(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncDiallingNumbers<int32_t> *diallingNumbers = static_cast<AsyncDiallingNumbers<int32_t> *>(data);
    if (!IsValidSlotId(diallingNumbers->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeDelIccDiallingNumbers slotId is invalid");
        diallingNumbers->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    if (diallingNumbers->infoVec.size() > 0) {
        std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
        GetDiallingNumberInfo(telNumber, diallingNumbers->infoVec.at(0));
        int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().DelIccDiallingNumbers(
            diallingNumbers->asyncContext.slotId, diallingNumbers->type, telNumber);
        TELEPHONY_LOGI("NAPI NativeDelIccDiallingNumbers errorCode: %{public}d", errorCode);
        diallingNumbers->asyncContext.context.errorCode = errorCode;
        diallingNumbers->asyncContext.context.resolved = (errorCode == ERROR_NONE);
    }
}

void DelIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDiallingNumbers<int32_t>> diallingNumbers(static_cast<AsyncDiallingNumbers<int32_t> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, diallingNumbers->asyncContext, true, { "DelIccDiallingNumbers", Permission::WRITE_CONTACTS });
}

napi_value DelIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    auto diallingNumbers = new AsyncDiallingNumbers<int32_t>();
    BaseContext &context = diallingNumbers->asyncContext.context;

    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara =
        std::make_tuple(&diallingNumbers->asyncContext.slotId, &diallingNumbers->type, &object, &context.callbackRef);
    AsyncPara para {
        .funcName = "DelIccDiallingNumbers",
        .env = env,
        .info = info,
        .execute = NativeDelIccDiallingNumbers,
        .complete = DelIccDiallingNumbersCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, diallingNumbers, initPara);
    if (result) {
        TelNumbersInfo inputInfo;
        DiallingNumberParaAnalyze(env, object, inputInfo);
        diallingNumbers->infoVec.push_back(std::move(inputInfo));
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeUpdateIccDiallingNumbers(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncDiallingNumbers<int32_t> *diallingNumbers = static_cast<AsyncDiallingNumbers<int32_t> *>(data);
    AsyncContext<int32_t> &asyncContext = diallingNumbers->asyncContext;
    if (!IsValidSlotId(asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeUpdateIccDiallingNumbers slotId is invalid");
        asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    if (diallingNumbers->infoVec.size() > 0) {
        std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
        GetDiallingNumberInfo(telNumber, diallingNumbers->infoVec.at(0));
        int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UpdateIccDiallingNumbers(
            asyncContext.slotId, diallingNumbers->type, telNumber);
        TELEPHONY_LOGI("NAPI NativeUpdateIccDiallingNumbers errorCode: %{public}d", errorCode);
        asyncContext.context.errorCode = errorCode;
        asyncContext.context.resolved = (errorCode == ERROR_NONE);
    }
}

void UpdateIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDiallingNumbers<int32_t>> context(static_cast<AsyncDiallingNumbers<int32_t> *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "UpdateIccDiallingNumbers", Permission::WRITE_CONTACTS });
}

napi_value UpdateIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    auto diallingNumbers = new AsyncDiallingNumbers<int32_t>();
    BaseContext &context = diallingNumbers->asyncContext.context;

    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara =
        std::make_tuple(&diallingNumbers->asyncContext.slotId, &diallingNumbers->type, &object, &context.callbackRef);

    AsyncPara para {
        .funcName = "UpdateIccDiallingNumbers",
        .env = env,
        .info = info,
        .execute = NativeUpdateIccDiallingNumbers,
        .complete = UpdateIccDiallingNumbersCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncDiallingNumbers<int32_t>>(para, diallingNumbers, initPara);
    if (result) {
        TelNumbersInfo inputInfo;
        DiallingNumberParaAnalyze(env, object, inputInfo);
        diallingNumbers->infoVec.push_back(std::move(inputInfo));
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeSetVoiceMailInfo(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncVoiceMail *mailContext = static_cast<AsyncVoiceMail *>(data);
    AsyncContext<bool> &asyncContext = mailContext->asyncContext;
    if (!IsValidSlotId(asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeSetVoiceMailInfo slotId is invalid");
        asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string mailName = NapiUtil::ToUtf16(std::data(mailContext->mailName));
    std::u16string mailNumber = NapiUtil::ToUtf16(std::data(mailContext->mailNumber));
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetVoiceMailInfo(
        asyncContext.slotId, mailName, mailNumber);
    TELEPHONY_LOGI("NAPI NativeSetVoiceMailInfo %{public}d", errorCode);
    asyncContext.context.errorCode = errorCode;
    asyncContext.context.resolved = (errorCode == ERROR_NONE);
}

void SetVoiceMailInfoCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncVoiceMail> context(static_cast<AsyncVoiceMail *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "SetVoiceMailInfo", Permission::SET_TELEPHONY_STATE });
}

napi_value SetVoiceMailInfo(napi_env env, napi_callback_info info)
{
    auto mailContext = new AsyncVoiceMail();
    BaseContext &context = mailContext->asyncContext.context;

    auto initPara = std::make_tuple(&mailContext->asyncContext.slotId, std::data(mailContext->mailName),
        std::data(mailContext->mailNumber), &context.callbackRef);

    AsyncPara para {
        .funcName = "SetVoiceMailNumber",
        .env = env,
        .info = info,
        .execute = NativeSetVoiceMailInfo,
        .complete = SetVoiceMailInfoCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncVoiceMail>(para, mailContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeSendEnvelopeCmd(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext2 *context = static_cast<AsyncContext2 *>(data);
    if (!IsValidSlotId(context->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeSendEnvelopeCmd slotId is invalid");
        context->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendEnvelopeCmd(
        context->asyncContext.slotId, std::data(context->inputStr));
    TELEPHONY_LOGI("NAPI NativeSendEnvelopeCmd %{public}d", errorCode);
    context->asyncContext.context.errorCode = errorCode;
    context->asyncContext.context.resolved = (errorCode == ERROR_NONE);
}

void SendEnvelopeCmdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext2> context(static_cast<AsyncContext2 *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "SendEnvelopeCmd", Permission::SET_TELEPHONY_STATE });
}

napi_value SendEnvelopeCmd(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncContext2();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara =
        std::make_tuple(&asyncContext->asyncContext.slotId, std::data(asyncContext->inputStr), &context.callbackRef);
    AsyncPara para {
        .funcName = "SendEnvelopeCmd",
        .env = env,
        .info = info,
        .execute = NativeSendEnvelopeCmd,
        .complete = SendEnvelopeCmdCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContext2>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeSendTerminalResponseCmd(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext2 *context = static_cast<AsyncContext2 *>(data);
    if (!IsValidSlotId(context->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeSendTerminalResponseCmd slotId is invalid");
        context->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendTerminalResponseCmd(
        context->asyncContext.slotId, std::data(context->inputStr));
    TELEPHONY_LOGI("NAPI NativeSendTerminalResponseCmd %{public}d", errorCode);
    context->asyncContext.context.errorCode = errorCode;
    context->asyncContext.context.resolved = (errorCode == ERROR_NONE);
}

void SendTerminalResponseCmdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext2> context(static_cast<AsyncContext2 *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "SendTerminalResponseCmd", Permission::SET_TELEPHONY_STATE });
}

napi_value SendTerminalResponseCmd(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncContext2();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara =
        std::make_tuple(&asyncContext->asyncContext.slotId, std::data(asyncContext->inputStr), &context.callbackRef);
    AsyncPara para {
        .funcName = "SendTerminalResponseCmd",
        .env = env,
        .info = info,
        .execute = NativeSendTerminalResponseCmd,
        .complete = SendTerminalResponseCmdCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContext2>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeAcceptCallSetupRequest(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncStkCallSetupResult *context = static_cast<AsyncStkCallSetupResult *>(data);
    if (!IsValidSlotId(context->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeAcceptCallSetupRequest slotId is invalid");
        context->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendCallSetupRequestResult(
        context->asyncContext.slotId, true);
    TELEPHONY_LOGI("NAPI NativeAcceptCallSetupRequest %{public}d", errorCode);
    context->asyncContext.context.errorCode = errorCode;
    context->asyncContext.context.resolved = errorCode == ERROR_NONE;
}

void AcceptCallSetupRequestCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncStkCallSetupResult> context(static_cast<AsyncStkCallSetupResult *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "acceptCallSetup", Permission::SET_TELEPHONY_STATE });
}

napi_value AcceptCallSetupRequest(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncStkCallSetupResult();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara = std::make_tuple(&asyncContext->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "AcceptCallSetupRequest",
        .env = env,
        .info = info,
        .execute = NativeAcceptCallSetupRequest,
        .complete = AcceptCallSetupRequestCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncStkCallSetupResult>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeRejectCallSetupRequest(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncStkCallSetupResult *context = static_cast<AsyncStkCallSetupResult *>(data);
    if (!IsValidSlotId(context->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeRejectCallSetupRequest slotId is invalid");
        context->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendCallSetupRequestResult(
        context->asyncContext.slotId, false);
    TELEPHONY_LOGI("NAPI NativeRejectCallSetupRequest %{public}d", errorCode);
    context->asyncContext.context.errorCode = errorCode;
    context->asyncContext.context.resolved = errorCode == ERROR_NONE;
}

void RejectCallSetupRequestCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncStkCallSetupResult> context(static_cast<AsyncStkCallSetupResult *>(data));
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, true, { "rejectCallSetup", Permission::SET_TELEPHONY_STATE });
}

napi_value RejectCallSetupRequest(napi_env env, napi_callback_info info)
{
    auto asyncContext = new AsyncStkCallSetupResult();
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara = std::make_tuple(&asyncContext->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "RejectCallSetupRequest",
        .env = env,
        .info = info,
        .execute = NativeRejectCallSetupRequest,
        .complete = RejectCallSetupRequestCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncStkCallSetupResult>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

napi_value GetMaxSimCount(napi_env env, napi_callback_info)
{
    return GetNapiValue(env, DelayedRefSingleton<CoreServiceClient>::GetInstance().GetMaxSimCount());
}

void NativeGetOpKey(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetOpKey slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string opkey;
    int32_t code = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOpKey(asyncContext->slotId, opkey);
    if (code == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(opkey);
        asyncContext->context.resolved = true;
        return;
    }
    asyncContext->context.errorCode = code;
    asyncContext->context.resolved = false;
}

void GetOpKeyCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
}

napi_value GetOpKey(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetOpKey, GetOpKeyCallback>(env, info, "GetOpKey");
}

napi_value GetOpKeySync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    std::u16string opKey;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        std::string operatorKey = NapiUtil::ToUtf8(opKey);
        NAPI_CALL(env, napi_create_string_utf8(env, operatorKey.c_str(), operatorKey.length(), &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        std::string operatorKey = NapiUtil::ToUtf8(opKey);
        NAPI_CALL(env, napi_create_string_utf8(env, operatorKey.c_str(), operatorKey.length(), &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOpKey(slotId, opKey);
    }
    std::string operatorKey = NapiUtil::ToUtf8(opKey);
    NAPI_CALL(env, napi_create_string_utf8(env, operatorKey.c_str(), operatorKey.length(), &value));
    return value;
}

void NativeGetOpName(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetOpName slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string opname;
    int32_t code = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOpName(asyncContext->slotId, opname);
    if (code == ERROR_NONE) {
        asyncContext->callbackVal = NapiUtil::ToUtf8(opname);
        asyncContext->context.resolved = true;
        return;
    }
    asyncContext->context.errorCode = code;
    asyncContext->context.resolved = false;
}

void GetOpNameCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
}

napi_value GetOpName(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetOpName, GetOpNameCallback>(env, info, "GetOpName");
}

napi_value GetOpNameSync(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    std::u16string opName;
    napi_value value = nullptr;
    if (parameterCount != 1) {
        TELEPHONY_LOGE("parameter count is incorrect");
        std::string operatorName = NapiUtil::ToUtf8(opName);
        NAPI_CALL(env, napi_create_string_utf8(env, operatorName.c_str(), operatorName.length(), &value));
        return value;
    }
    int32_t slotId = -1;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("convert parameter fail");
        std::string operatorName = NapiUtil::ToUtf8(opName);
        NAPI_CALL(env, napi_create_string_utf8(env, operatorName.c_str(), operatorName.length(), &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOpName(slotId, opName);
    }
    std::string operatorName = NapiUtil::ToUtf8(opName);
    NAPI_CALL(env, napi_create_string_utf8(env, operatorName.c_str(), operatorName.length(), &value));
    return value;
}

void NativeGetLockState(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncGetLockState *lockContext = static_cast<AsyncGetLockState *>(data);
    AsyncContext<int32_t> &asContext = lockContext->asyncContext;
    if (!IsValidSlotId(asContext.slotId)) {
        TELEPHONY_LOGE("NativeGetLockState slotId is invalid");
        asContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockState lockState = LockState::LOCK_ERROR;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetLockState(
        asContext.slotId, static_cast<LockType>(lockContext->lockType), lockState);
    TELEPHONY_LOGI("NAPI NativeGetLockState %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asContext.context.resolved = true;
        asContext.callbackVal = static_cast<int32_t>(lockState);
    } else {
        asContext.context.resolved = false;
    }
    asContext.context.errorCode = errorCode;
}

void GetLockStateCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncGetLockState> context(static_cast<AsyncGetLockState *>(data));
    TELEPHONY_LOGI("NAPI NativeGetLockState value:%{public}d", context->asyncContext.callbackVal);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "GetLockState", Permission::GET_TELEPHONY_STATE });
}

napi_value GetLockState(napi_env env, napi_callback_info info)
{
    auto lockStateContext = new AsyncGetLockState();
    BaseContext &context = lockStateContext->asyncContext.context;

    auto initPara =
        std::make_tuple(&lockStateContext->asyncContext.slotId, &lockStateContext->lockType, &context.callbackRef);
    AsyncPara para {
        .funcName = "GetLockState",
        .env = env,
        .info = info,
        .execute = NativeGetLockState,
        .complete = GetLockStateCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncGetLockState>(para, lockStateContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeHasOperatorPrivileges(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    if (!IsValidSlotId(reVal->slotId)) {
        TELEPHONY_LOGE("NativeHasOperatorPrivileges slotId is invalid");
        reVal->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    bool hasOperatorPrivileges = false;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasOperatorPrivileges(
        reVal->slotId, hasOperatorPrivileges);
    TELEPHONY_LOGI("NAPI NativeHasOperatorPrivileges %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        reVal->callbackVal = hasOperatorPrivileges;
        reVal->context.resolved = true;
    } else {
        reVal->context.resolved = false;
    }
    reVal->context.errorCode = errorCode;
}

void HasOperatorPrivilegesCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCommomCompleteCallback(env, status, *context, false);
}

napi_value HasOperatorPrivileges(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeHasOperatorPrivileges, HasOperatorPrivilegesCallback>(
        env, info, "HasOperatorPrivileges");
}

void NativeUnlockSimLock(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *asyncContext = static_cast<AsyncContextPIN *>(data);
    if (!IsValidSlotId(asyncContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeUnlockSimLock slotId is invalid");
        asyncContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };
    PersoLockInfo lockInfo { static_cast<PersoLockType>(asyncContext->pinEnable),
        NapiUtil::ToUtf16(asyncContext->inStr1.data()) };
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockSimLock(
        asyncContext->asyncContext.slotId, lockInfo, response);
    TELEPHONY_LOGI("NAPI NativeUnlockSimLock %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->result = response.result;
        asyncContext->remain = response.remain;
        asyncContext->asyncContext.context.resolved = true;
    } else {
        asyncContext->asyncContext.context.resolved = false;
    }
    asyncContext->asyncContext.context.errorCode = errorCode;
}

void UnlockSimLockCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->asyncContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "UnlockSimLock", Permission::SET_TELEPHONY_STATE });
}

napi_value UnlockSimLock(napi_env env, napi_callback_info info)
{
    auto asyncContextPIN = new AsyncContextPIN();
    BaseContext &context = asyncContextPIN->asyncContext.context;
    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara = std::make_tuple(&asyncContextPIN->asyncContext.slotId, &object, &context.callbackRef);

    AsyncPara para {
        .funcName = "UnlockSimLock",
        .env = env,
        .info = info,
        .execute = NativeUnlockSimLock,
        .complete = UnlockSimLockCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextPIN>(para, asyncContextPIN, initPara);
    if (result) {
        PersoLockInfoAnalyze(env, object, *asyncContextPIN);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

napi_status InitEnumSimState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_STATE_UNKNOWN", GetNapiValue(env, static_cast<int32_t>(SimState::SIM_STATE_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_STATE_NOT_PRESENT", GetNapiValue(env, static_cast<int32_t>(SimState::SIM_STATE_NOT_PRESENT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_STATE_LOCKED", GetNapiValue(env, static_cast<int32_t>(SimState::SIM_STATE_LOCKED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_STATE_NOT_READY", GetNapiValue(env, static_cast<int32_t>(SimState::SIM_STATE_NOT_READY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_STATE_READY", GetNapiValue(env, static_cast<int32_t>(SimState::SIM_STATE_READY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_STATE_LOADED", GetNapiValue(env, static_cast<int32_t>(SimState::SIM_STATE_LOADED))),
    };
    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "SimState", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumContactType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "GENERAL_CONTACT", GetNapiValue(env, static_cast<int32_t>(ContactType::GENERAL_CONTACT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FIXED_DIALING", GetNapiValue(env, static_cast<int32_t>(ContactType::FIXED_DIALING))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "ContactType", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumLockState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("LOCK_OFF", GetNapiValue(env, static_cast<int32_t>(LockState::LOCK_OFF))),
        DECLARE_NAPI_STATIC_PROPERTY("LOCK_ON", GetNapiValue(env, static_cast<int32_t>(LockState::LOCK_ON))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "LockState", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumLockType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("PIN_LOCK", GetNapiValue(env, static_cast<int32_t>(LockType::PIN_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY("FDN_LOCK", GetNapiValue(env, static_cast<int32_t>(LockType::FDN_LOCK))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "LockType", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumCardType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("UNKNOWN_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::UNKNOWN_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SINGLE_MODE_SIM_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::SINGLE_MODE_SIM_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SINGLE_MODE_USIM_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::SINGLE_MODE_USIM_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SINGLE_MODE_RUIM_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::SINGLE_MODE_RUIM_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "DUAL_MODE_CG_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::DUAL_MODE_CG_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "CT_NATIONAL_ROAMING_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::CT_NATIONAL_ROAMING_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "CU_DUAL_MODE_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::CU_DUAL_MODE_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY("DUAL_MODE_TELECOM_LTE_CARD",
            GetNapiValue(env, static_cast<int32_t>(CardType::DUAL_MODE_TELECOM_LTE_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "DUAL_MODE_UG_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::DUAL_MODE_UG_CARD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SINGLE_MODE_ISIM_CARD", GetNapiValue(env, static_cast<int32_t>(CardType::SINGLE_MODE_ISIM_CARD))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "CardType", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumPersoLockType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "PN_PIN_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::PN_PIN_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PN_PUK_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::PN_PUK_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PU_PIN_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::PU_PIN_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PU_PUK_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::PU_PUK_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PP_PIN_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::PP_PIN_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PP_PUK_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::PP_PUK_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PC_PIN_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::PC_PIN_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PC_PUK_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::PC_PUK_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_PIN_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::SIM_PIN_LOCK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_PUK_LOCK", GetNapiValue(env, static_cast<int32_t>(PersoLockType::SIM_PUK_LOCK))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "PersoLockType", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumOperatorConfigKey(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("KEY_VOICE_MAIL_NUMBER_STRING", GetNapiValue(env, "voice_mail_number_string")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_IMS_SWITCH_ON_BY_DEFAULT_BOOL",
            GetNapiValue(env, "ims_switch_on_by_default_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_HIDE_IMS_SWITCH_BOOL", GetNapiValue(env, "hide_ims_switch_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_VOLTE_SUPPORTED_BOOL", GetNapiValue(env, "volte_supported_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_NR_MODE_SUPPORTED_LIST_INT_ARRAY",
            GetNapiValue(env, "nr_mode_supported_list_int_array")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_VOLTE_PROVISIONING_SUPPORTED_BOOL",
            GetNapiValue(env, "volte_provisioning_supported_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_SS_OVER_UT_SUPPORTED_BOOL", GetNapiValue(env, "ss_over_ut_supported_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_IMS_GBA_REQUIRED_BOOL", GetNapiValue(env, "ims_gba_required_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_UT_PROVISIONING_SUPPORTED_BOOL",
            GetNapiValue(env, "ut_provisioning_supported_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_IMS_PREFER_FOR_EMERGENCY_BOOL",
            GetNapiValue(env, "ims_prefer_for_emergency_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_CALL_WAITING_SERVICE_CLASS_INT",
            GetNapiValue(env, "call_waiting_service_class_int")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_CALL_TRANSFER_VISIBILITY_BOOL",
            GetNapiValue(env, "call_transfer_visibility_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_IMS_CALL_DISCONNECT_REASON_INFO_MAPPING_STRING_ARRAY",
            GetNapiValue(env, "ims_call_disconnect_reason_info_mapping_string_array")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_FORCE_VOLTE_SWITCH_ON_BOOL", GetNapiValue(env, "force_volte_switch_on_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_ENABLE_OPERATOR_NAME_CUST_BOOL",
            GetNapiValue(env, "enable_operator_name_cust_bool")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_OPERATOR_NAME_CUST_STRING",
            GetNapiValue(env, "operator_name_cust_string")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_SPN_DISPLAY_CONDITION_CUST_INT",
            GetNapiValue(env, "spn_display_condition_cust_int")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_PNN_CUST_STRING_ARRAY", GetNapiValue(env, "pnn_cust_string_array")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_OPL_CUST_STRING_ARRAY", GetNapiValue(env, "opl_cust_string_array")),
        DECLARE_NAPI_STATIC_PROPERTY("KEY_EMERGENCY_CALL_STRING_ARRAY",
            GetNapiValue(env, "emergency_call_string_array")),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "OperatorConfigKey", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumOperatorSimCard(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CHINA_TELECOM_CARD", GetNapiValue(env, CHINA_TELECOM_CARD)),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "OperatorSimCard", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumAuthType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_AUTH_EAP_SIM_TYPE", GetNapiValue(env, static_cast<int32_t>(AuthType::SIM_AUTH_EAP_SIM_TYPE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SIM_AUTH_EAP_AKA_TYPE", GetNapiValue(env, static_cast<int32_t>(AuthType::SIM_AUTH_EAP_AKA_TYPE))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "AuthType", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitSimLockInterface(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("unlockPin", UnlockPin),
        DECLARE_NAPI_FUNCTION("unlockPuk", UnlockPuk),
        DECLARE_NAPI_FUNCTION("alterPin", AlterPin),
        DECLARE_NAPI_FUNCTION("setLockState", SetLockState),
        DECLARE_NAPI_FUNCTION("unlockPin2", UnlockPin2),
        DECLARE_NAPI_FUNCTION("unlockPuk2", UnlockPuk2),
        DECLARE_NAPI_FUNCTION("alterPin2", AlterPin2),
        DECLARE_NAPI_FUNCTION("getLockState", GetLockState),
        DECLARE_NAPI_FUNCTION("unlockSimLock", UnlockSimLock),
    };
    return napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

napi_status InitSimDiallingNumbersInterface(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("queryIccDiallingNumbers", QueryIccDiallingNumbers),
        DECLARE_NAPI_FUNCTION("addIccDiallingNumbers", AddIccDiallingNumbers),
        DECLARE_NAPI_FUNCTION("delIccDiallingNumbers", DelIccDiallingNumbers),
        DECLARE_NAPI_FUNCTION("updateIccDiallingNumbers", UpdateIccDiallingNumbers),
    };
    return napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

napi_status InitSimInterfaceAboutVoice(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("setDefaultVoiceSlotId", SetDefaultVoiceSlotId),
        DECLARE_NAPI_FUNCTION("getDefaultVoiceSlotId", GetDefaultVoiceSlotId),
        DECLARE_NAPI_FUNCTION("getDefaultVoiceSimId", GetDefaultVoiceSimId),
        DECLARE_NAPI_FUNCTION("getVoiceMailIdentifier", GetVoiceMailIdentifier),
        DECLARE_NAPI_FUNCTION("getVoiceMailNumber", GetVoiceMailNumber),
        DECLARE_NAPI_FUNCTION("getVoiceMailCount", GetVoiceMailCount),
        DECLARE_NAPI_FUNCTION("setVoiceMailInfo", SetVoiceMailInfo),
    };
    return napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

napi_status InitSimInterface(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getISOCountryCodeForSim", GetISOCountryCodeForSim),
        DECLARE_NAPI_FUNCTION("getISOCountryCodeForSimSync", GetISOCountryCodeForSimSync),
        DECLARE_NAPI_FUNCTION("getSimOperatorNumeric", GetSimOperatorNumeric),
        DECLARE_NAPI_FUNCTION("getSimOperatorNumericSync", GetSimOperatorNumericSync),
        DECLARE_NAPI_FUNCTION("getSimSpn", GetSimSpn),
        DECLARE_NAPI_FUNCTION("getSimSpnSync", GetSimSpnSync),
        DECLARE_NAPI_FUNCTION("getSimState", GetSimState),
        DECLARE_NAPI_FUNCTION("getSimStateSync", GetSimStateSync),
        DECLARE_NAPI_FUNCTION("getCardType", GetCardType),
        DECLARE_NAPI_FUNCTION("getCardTypeSync", GetCardTypeSync),
        DECLARE_NAPI_FUNCTION("getSimIccId", GetSimIccId),
        DECLARE_NAPI_FUNCTION("getIMSI", GetIMSI),
        DECLARE_NAPI_FUNCTION("isOperatorSimCard", IsOperatorSimCard),
        DECLARE_NAPI_FUNCTION("hasSimCard", HasSimCard),
        DECLARE_NAPI_FUNCTION("hasSimCardSync", HasSimCardSync),
        DECLARE_NAPI_FUNCTION("getSimGid1", GetSimGid1),
        DECLARE_NAPI_FUNCTION("getSimAccountInfo", GetSimAccountInfo),
        DECLARE_NAPI_FUNCTION("isSimActive", IsSimActive),
        DECLARE_NAPI_FUNCTION("isSimActiveSync", IsSimActiveSync),
        DECLARE_NAPI_FUNCTION("activateSim", ActivateSim),
        DECLARE_NAPI_FUNCTION("deactivateSim", DeactivateSim),
        DECLARE_NAPI_FUNCTION("setShowName", SetShowName),
        DECLARE_NAPI_FUNCTION("getShowName", GetShowName),
        DECLARE_NAPI_FUNCTION("setShowNumber", SetShowNumber),
        DECLARE_NAPI_FUNCTION("getShowNumber", GetShowNumber),
        DECLARE_NAPI_FUNCTION("getOperatorConfigs", GetOperatorConfigs),
        DECLARE_NAPI_FUNCTION("getActiveSimAccountInfoList", GetActiveSimAccountInfoList),
        DECLARE_NAPI_FUNCTION("getSimTelephoneNumber", GetSimTelephoneNumber),
        DECLARE_NAPI_FUNCTION("sendEnvelopeCmd", SendEnvelopeCmd),
        DECLARE_NAPI_FUNCTION("sendTerminalResponseCmd", SendTerminalResponseCmd),
        DECLARE_NAPI_FUNCTION("acceptCallSetupRequest", AcceptCallSetupRequest),
        DECLARE_NAPI_FUNCTION("rejectCallSetupRequest", RejectCallSetupRequest),
        DECLARE_NAPI_FUNCTION("getMaxSimCount", GetMaxSimCount),
        DECLARE_NAPI_FUNCTION("hasOperatorPrivileges", HasOperatorPrivileges),
        DECLARE_NAPI_FUNCTION("getOpKey", GetOpKey),
        DECLARE_NAPI_FUNCTION("getOpKeySync", GetOpKeySync),
        DECLARE_NAPI_FUNCTION("getOpName", GetOpName),
        DECLARE_NAPI_FUNCTION("getOpNameSync", GetOpNameSync),
        DECLARE_NAPI_FUNCTION("getDsdsMode", GetDsdsMode),
        DECLARE_NAPI_FUNCTION("getSimAuthentication", GetSimAuthentication),
    };
    return napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}
} // namespace

EXTERN_C_START
napi_value InitNapiSim(napi_env env, napi_value exports)
{
    NAPI_CALL(env, InitSimInterface(env, exports));
    NAPI_CALL(env, InitSimLockInterface(env, exports));
    NAPI_CALL(env, InitSimDiallingNumbersInterface(env, exports));
    NAPI_CALL(env, InitSimInterfaceAboutVoice(env, exports));
    NAPI_CALL(env, InitEnumSimState(env, exports));
    NAPI_CALL(env, InitEnumContactType(env, exports));
    NAPI_CALL(env, InitEnumLockState(env, exports));
    NAPI_CALL(env, InitEnumLockType(env, exports));
    NAPI_CALL(env, InitEnumCardType(env, exports));
    NAPI_CALL(env, InitEnumPersoLockType(env, exports));
    NAPI_CALL(env, InitEnumOperatorConfigKey(env, exports));
    NAPI_CALL(env, InitEnumOperatorSimCard(env, exports));
    NAPI_CALL(env, InitEnumAuthType(env, exports));
    return exports;
}
EXTERN_C_END

static napi_module _simModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = InitNapiSim,
    .nm_modname = "telephony.sim",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterSimCardModule(void)
{
    napi_module_register(&_simModule);
}
} // namespace Telephony
} // namespace OHOS
