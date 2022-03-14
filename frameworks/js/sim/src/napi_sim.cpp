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
#include <string_view>
#include "core_service_client.h"
#include "napi_parameter_util.h"
#include "napi_sim_type.h"
#include "napi_util.h"
#include "network_state.h"
#include "sim_state_type.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
struct AsyncPara {
    std::string funcName = "";
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    napi_async_execute_callback execute = nullptr;
    napi_async_complete_callback complete = nullptr;
};

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
        const std::string errMsg = "type of input parameters error : " + std::to_string(errCode.value());
        napi_throw_error(env, nullptr, errMsg.c_str());
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
    if (napi_queue_async_work(env, context.work) != napi_ok) {
        delete pContext;
        result = nullptr;
    }
    return result;
}

template<typename... Ts>
napi_value NapiCreateAsyncWork2(const AsyncPara &para, BaseContext &context, std::tuple<Ts...> &theTuple)
{
    napi_env env = para.env;

    size_t argc = sizeof...(Ts);
    napi_value argv[sizeof...(Ts)] {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, para.info, &argc, argv, nullptr, nullptr));

    std::optional<NapiError> errCode = MatchParameters(env, argv, argc, theTuple);
    if (errCode.has_value()) {
        const std::string errMsg = "type of input parameters error : " + std::to_string(errCode.value());
        napi_throw_error(env, nullptr, errMsg.c_str());
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
    NAPI_CALL(env,
        napi_create_async_work(
            env, nullptr, resourceName, para.execute, para.complete, static_cast<void *>(&context), &context.work));
    return result;
}

template<typename T>
void NapiAsyncCompleteCallback(napi_env env, napi_status status, const AsyncContext<T> &asyncContext,
    std::string errMessage, bool funcIgnoreReturnVal = false)
{
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "excute failed");
        return;
    }

    const BaseContext &context = asyncContext.context;
    if (context.deferred != nullptr) {
        if (!context.resolved) {
            napi_value errorMessage = NapiUtil::CreateErrorMessage(env, errMessage);
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
            callbackValue[0] = NapiUtil::CreateErrorMessage(env, errMessage);
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

void GetDiallingNumberInfo(std::shared_ptr<DiallingNumbersInfo> &telNumber, const TelNumbersInfo &info)
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
        NapiValueToCppValue(env, pin, napi_string, std::data(pinContext.inStr1));
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
        NapiValueToCppValue(env, password, napi_string, std::data(pinContext.inStr1));
    }
}

void NativeIsSimActive(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    reVal->callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsSimActive(reVal->slotId);
    TELEPHONY_LOGI("NAPI NativeIsSimActive %{public}d", reVal->callbackVal);
    /* transparent return value */
    reVal->context.resolved = true;
}

void IsSimActiveCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get simActive state failed");
}

napi_value IsSimActive(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeIsSimActive, IsSimActiveCallback>(env, info, "IsSimActive");
}

void NativeActivateSim(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *simContext = static_cast<AsyncContext<bool> *>(data);
    constexpr int32_t active = 1;
    simContext->callbackVal =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().SetActiveSim(simContext->slotId, active);
    TELEPHONY_LOGI("NAPI NativeActivateSim %{public}d", simContext->callbackVal);
    simContext->context.resolved = simContext->callbackVal;
}

void ActivateSimCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "activate sim state failed", true);
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
    constexpr int32_t deactive = 0;
    simContext->callbackVal =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().SetActiveSim(simContext->slotId, deactive);
    TELEPHONY_LOGI("NAPI NativeDeactivateSim %{public}d", simContext->callbackVal);
    simContext->context.resolved = simContext->callbackVal;
}

void DeactivateSimCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "deactivate sim state failed", true);
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
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);

    asyncContext->callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSlotId();
    TELEPHONY_LOGI("NAPI NativeGetDefaultVoiceSlotId %{public}d", asyncContext->callbackVal);
    asyncContext->context.resolved = (asyncContext->callbackVal > ERROR_DEFAULT);
}

void GetDefaultVoiceSlotIdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get default voice slot id failed");
}

napi_value GetDefaultVoiceSlotId(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContext<int32_t>> asyncContext = std::make_unique<AsyncContext<int32_t>>();
    BaseContext &context = asyncContext->context;

    auto initPara = std::make_tuple(&context.callbackRef);
    AsyncPara para {
        .funcName = "GetDefaultVoiceSlotId",
        .env = env,
        .info = info,
        .execute = NativeGetDefaultVoiceSlotId,
        .complete = GetDefaultVoiceSlotIdCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        asyncContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeGetIsoForSim(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal = NapiUtil::ToUtf8(
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetISOCountryCodeForSim(asyncContext->slotId));
    TELEPHONY_LOGI("NAPI NativeGetIsoForSim %{public}s", asyncContext->callbackVal.c_str());
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetIsoForSimCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get iso country code for sim failed");
}

napi_value GetISOCountryCodeForSim(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetIsoForSim, GetIsoForSimCallback>(
        env, info, "GetISOCountryCodeForSim");
}

void NativeGetSimOperatorNumeric(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal = NapiUtil::ToUtf8(
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimOperatorNumeric(asyncContext->slotId));
    TELEPHONY_LOGI("NAPI NativeGetSimOperatorNumeric %{public}s", asyncContext->callbackVal.c_str());
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetSimOperatorNumericCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim operator numeric failed");
}

napi_value GetSimOperatorNumeric(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimOperatorNumeric, GetSimOperatorNumericCallback>(
        env, info, "GetSimOperatorNumeric");
}

void NativeGetSimSpn(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimSpn(asyncContext->slotId));
    TELEPHONY_LOGI("NAPI NativeGetSimSpn %{public}s", asyncContext->callbackVal.c_str());
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetSimSpnCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim spn failed");
}

napi_value GetSimSpn(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimSpn, GetSimSpnCallback>(env, info, "GetSimSpn");
}

void NativeGetSimState(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);
    int32_t simState = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimState(asyncContext->slotId);
    TELEPHONY_LOGI("NAPI NativeGetSimState %{public}d", simState);
    if (simState >= static_cast<int32_t>(SimState::SIM_STATE_UNKNOWN) &&
        simState <= static_cast<int32_t>(SimState::SIM_STATE_LOADED)) {
        asyncContext->context.resolved = true;
        asyncContext->callbackVal = simState;
    } else {
        asyncContext->context.resolved = false;
    }
}

void GetSimStateCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim state failed");
}

napi_value GetSimState(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<int32_t, NativeGetSimState, GetSimStateCallback>(env, info, "GetSimState");
}

void NativeGetCardType(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);
    asyncContext->callbackVal =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCardType(asyncContext->slotId);
    asyncContext->context.resolved = true;
}

void GetCardTypeCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get card type failed");
}

napi_value GetCardType(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<int32_t, NativeGetCardType, GetCardTypeCallback>(env, info, "GetCardType");
}

void NativeGetVoiceMailIdentifier(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal = NapiUtil::ToUtf8(
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetVoiceMailIdentifier(asyncContext->slotId));
    TELEPHONY_LOGI("NAPI NativeGetVoiceMailIdentifier %{public}s", asyncContext->callbackVal.c_str());
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetVoiceMailIdentifierCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get voice mail identifier failed");
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

    asyncContext->callbackVal = NapiUtil::ToUtf8(
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetVoiceMailNumber(asyncContext->slotId));
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetVoiceMailNumberCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get voice mail number failed");
}

napi_value GetVoiceMailNumber(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetVoiceMailNumber, GetVoiceMailNumberCallback>(
        env, info, "GetVoiceMailNumber");
}

void NativeGetSimTelephoneNumber(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal = NapiUtil::ToUtf8(
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimTelephoneNumber(asyncContext->slotId));
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetSimTelephoneNumberCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim telephone number failed");
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
    asyncContext->callbackVal =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimGid1(asyncContext->slotId));
    TELEPHONY_LOGI("NAPI NativeGetSimGid1 %{public}s", asyncContext->callbackVal.c_str());
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetSimGid1Callback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim gid1 failed");
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
    asyncContext->callbackVal =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimIccId(asyncContext->slotId));
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetSimIccIdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim icc id failed");
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

    IccAccountInfo operInfo;
    bool result =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimAccountInfo(info->asyncContext.slotId, operInfo);
    TELEPHONY_LOGI("NAPI NativeGetSimAccountInfo %{public}d", result);
    if (result) {
        info->vecInfo.push_back(std::move(operInfo));
    }
    info->asyncContext.context.resolved = result;
}

void GetSimAccountInfoCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncIccAccountInfo> info(static_cast<AsyncIccAccountInfo *>(data));
    AsyncContext<napi_value> &asyncContext = info->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal = IccAccountInfoConversion(env, info->vecInfo.at(0));
    }
    NapiAsyncCompleteCallback(env, status, asyncContext, "get sim subscription info failed");
}

napi_value GetSimAccountInfo(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncIccAccountInfo> iccAccountInfo = std::make_unique<AsyncIccAccountInfo>();
    BaseContext &context = iccAccountInfo->asyncContext.context;

    auto initPara = std::make_tuple(&iccAccountInfo->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "GetSimAccountInfo",
        .env = env,
        .info = info,
        .execute = NativeGetSimAccountInfo,
        .complete = GetSimAccountInfoCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        iccAccountInfo.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeSetDefaultVoiceSlotId(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    reVal->callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetDefaultVoiceSlotId(reVal->slotId);
    TELEPHONY_LOGI("NAPI NativeSetDefaultVoiceSlotId %{public}d", reVal->callbackVal);
    reVal->context.resolved = reVal->callbackVal;
}

void SetDefaultVoiceSlotIdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "set default voice slot id failed", true);
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

    LockStatusResponse response {ERROR_DEFAULT, ERROR_DEFAULT};
    bool res = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPin(
        pinContext->pinContext.slotId, NapiUtil::ToUtf16(pinContext->inStr1.data()), response);
    TELEPHONY_LOGI("NAPI NativeUnlockPin %{public}d", res);
    if (res) {
        pinContext->result = response.result;
        pinContext->remain = response.remain;
    }
    pinContext->pinContext.context.resolved = res;
}

void UnlockPinCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, context->pinContext, "unlock pin failed");
}

napi_value UnlockPin(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pinContext->pinContext.context;

    auto initPara =
        std::make_tuple(&pinContext->pinContext.slotId, std::data(pinContext->inStr1), &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockPin",
        .env = env,
        .info = info,
        .execute = NativeUnlockPin,
        .complete = UnlockPinCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        pinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeUnlockPuk(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *pukContext = static_cast<AsyncContextPIN *>(data);
    LockStatusResponse response {ERROR_DEFAULT, ERROR_DEFAULT};
    bool res = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPuk(pukContext->pinContext.slotId,
        NapiUtil::ToUtf16(pukContext->inStr1.data()), NapiUtil::ToUtf16(pukContext->inStr2.data()), response);
    TELEPHONY_LOGI("NAPI NativeUnlockPuk %{public}d", res);
    if (res) {
        pukContext->result = response.result;
        pukContext->remain = response.remain;
    }
    pukContext->pinContext.context.resolved = res;
}

void UnlockPukCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, context->pinContext, "unlock puk failed");
}

napi_value UnlockPuk(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pukContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pukContext->pinContext.context;

    auto initPara = std::make_tuple(&pukContext->pinContext.slotId, std::data(pukContext->inStr1),
        std::data(pukContext->inStr2), &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockPuk",
        .env = env,
        .info = info,
        .execute = NativeUnlockPuk,
        .complete = UnlockPukCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        pukContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeAlterPin(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *alterPinContext = static_cast<AsyncContextPIN *>(data);
    LockStatusResponse response {ERROR_DEFAULT, ERROR_DEFAULT};
    bool res = DelayedRefSingleton<CoreServiceClient>::GetInstance().AlterPin(alterPinContext->pinContext.slotId,
        NapiUtil::ToUtf16(alterPinContext->inStr1.data()), NapiUtil::ToUtf16(alterPinContext->inStr2.data()),
        response);
    TELEPHONY_LOGI("NAPI NativeAlterPin %{public}d", res);
    if (res) {
        alterPinContext->result = response.result;
        alterPinContext->remain = response.remain;
    }
    alterPinContext->pinContext.context.resolved = res;
}

void AlterPinCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, context->pinContext, "alter pin failed");
}

napi_value AlterPin(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> alterPinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = alterPinContext->pinContext.context;

    auto initPara = std::make_tuple(&alterPinContext->pinContext.slotId, std::data(alterPinContext->inStr1),
        std::data(alterPinContext->inStr2), &context.callbackRef);
    AsyncPara para {
        .funcName = "AlterPin",
        .env = env,
        .info = info,
        .execute = NativeAlterPin,
        .complete = AlterPinCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        alterPinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeSetLockState(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *lockContext = static_cast<AsyncContextPIN *>(data);
    LockStatusResponse response {ERROR_DEFAULT, ERROR_DEFAULT};
    TELEPHONY_LOGI("NativeSetLockState slotId = %{public}d, lockType = %{public}d, state = %{public}d",
        lockContext->pinContext.slotId, lockContext->result, lockContext->remain);
    const LockInfo info {static_cast<LockType>(lockContext->result), NapiUtil::ToUtf16(lockContext->inStr1.data()),
        static_cast<LockState>(lockContext->remain)};
    bool res = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetLockState(
        lockContext->pinContext.slotId, info, response);
    TELEPHONY_LOGI("NAPI NativeSetLockState %{public}d", res);
    if (res) {
        lockContext->result = response.result;
        lockContext->remain = response.remain;
    }
    lockContext->pinContext.context.resolved = res;
}

void SetLockStateCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, context->pinContext, "set lock state failed");
}

napi_value SetLockState(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> lockContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = lockContext->pinContext.context;

    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara = std::make_tuple(&lockContext->pinContext.slotId, &object, &context.callbackRef);
    AsyncPara para {
        .funcName = "SetLockState",
        .env = env,
        .info = info,
        .execute = NativeSetLockState,
        .complete = SetLockStateCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        PinInfoParaAnalyze(env, object, *lockContext);
        lockContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeHasSimCard(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    reVal->callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(reVal->slotId);
    TELEPHONY_LOGI("NAPI NativeHasSimCard %{public}d", reVal->callbackVal);
    /* Transparent return value */
    reVal->context.resolved = true;
}

void HasSimCardCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "has sim card state failed");
}

napi_value HasSimCard(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeHasSimCard, HasSimCardCallback>(env, info, "HasSimCard");
}

void NativeGetIMSI(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetIMSI(asyncContext->slotId));
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetIMSICallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get IMSI failed");
}

napi_value GetIMSI(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetIMSI, GetIMSICallback>(env, info, "GetIMSI");
}

void NativeSetShowName(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext2<bool> *context = static_cast<AsyncContext2<bool> *>(data);
    std::u16string name = NapiUtil::ToUtf16(std::data(context->inputStr));
    context->aContext.callbackVal =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().SetShowName(context->aContext.slotId, name);
    TELEPHONY_LOGI("NAPI NativeSetShowName %{public}d", context->aContext.callbackVal);
    context->aContext.context.resolved = context->aContext.callbackVal;
}

void SetShowNameCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext2<bool>> context(static_cast<AsyncContext2<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, context->aContext, "set display name failed", true);
}

napi_value SetShowName(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContext2<bool>> asyncContext = std::make_unique<AsyncContext2<bool>>();
    BaseContext &context = asyncContext->aContext.context;

    auto initPara =
        std::make_tuple(&asyncContext->aContext.slotId, std::data(asyncContext->inputStr), &context.callbackRef);
    AsyncPara para {
        .funcName = "SetShowName",
        .env = env,
        .info = info,
        .execute = NativeSetShowName,
        .complete = SetShowNameCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        asyncContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeGetShowName(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetShowName(asyncContext->slotId));
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetShowNameCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get show name failed");
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
    AsyncContext2<bool> *context = static_cast<AsyncContext2<bool> *>(data);
    context->aContext.callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetShowNumber(
        context->aContext.slotId, NapiUtil::ToUtf16(std::data(context->inputStr)));
    TELEPHONY_LOGI("NAPI NativeSetShowNumber %{public}d", context->aContext.callbackVal);
    context->aContext.context.resolved = context->aContext.callbackVal;
}

void SetShowNumberCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext2<bool>> context(static_cast<AsyncContext2<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, context->aContext, "set show number failed", true);
}

napi_value SetShowNumber(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContext2<bool>> asyncContext = std::make_unique<AsyncContext2<bool>>();
    BaseContext &context = asyncContext->aContext.context;

    auto initPara =
        std::make_tuple(&asyncContext->aContext.slotId, std::data(asyncContext->inputStr), &context.callbackRef);
    AsyncPara para {
        .funcName = "SetShowNumber",
        .env = env,
        .info = info,
        .execute = NativeSetShowNumber,
        .complete = SetShowNumberCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        asyncContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeGetShowNumber(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetShowNumber(asyncContext->slotId));
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetShowNumberCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get display number failed");
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
    LockStatusResponse response {ERROR_DEFAULT, ERROR_DEFAULT};
    bool result = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPin2(
        pinContext->pinContext.slotId, NapiUtil::ToUtf16(pinContext->inStr1.data()), response);
    TELEPHONY_LOGI("NAPI NativeUnlockPin2 %{public}d", result);
    if (result) {
        pinContext->result = response.result;
        pinContext->remain = response.remain;
    }
    pinContext->pinContext.context.resolved = result;
}

void UnlockPinCallback2(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, context->pinContext, "unlock pin2 failed");
}

napi_value UnlockPin2(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pinContext->pinContext.context;

    auto initPara =
        std::make_tuple(&pinContext->pinContext.slotId, std::data(pinContext->inStr1), &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockPin2",
        .env = env,
        .info = info,
        .execute = NativeUnlockPin2,
        .complete = UnlockPinCallback2,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        pinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeUnlockPuk2(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *pukContext = static_cast<AsyncContextPIN *>(data);
    LockStatusResponse response {ERROR_DEFAULT, ERROR_DEFAULT};
    bool result = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPuk2(pukContext->pinContext.slotId,
        NapiUtil::ToUtf16(pukContext->inStr1.data()), NapiUtil::ToUtf16(pukContext->inStr2.data()), response);
    TELEPHONY_LOGI("NAPI NativeUnlockPuk2 %{public}d", result);
    if (result) {
        pukContext->result = response.result;
        pukContext->remain = response.remain;
    }
    pukContext->pinContext.context.resolved = result;
}

void UnlockPukCallback2(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, context->pinContext, "unlock puk2 failed");
}

napi_value UnlockPuk2(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pinContext->pinContext.context;

    auto initPara = std::make_tuple(&pinContext->pinContext.slotId, std::data(pinContext->inStr1),
        std::data(pinContext->inStr2), &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockPuk2",
        .env = env,
        .info = info,
        .execute = NativeUnlockPuk2,
        .complete = UnlockPukCallback2,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        pinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeAlterPin2(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContextPIN *pinContext = static_cast<AsyncContextPIN *>(data);
    LockStatusResponse response {ERROR_DEFAULT, ERROR_DEFAULT};
    bool result = DelayedRefSingleton<CoreServiceClient>::GetInstance().AlterPin2(pinContext->pinContext.slotId,
        NapiUtil::ToUtf16(pinContext->inStr1.data()), NapiUtil::ToUtf16(pinContext->inStr2.data()), response);
    TELEPHONY_LOGI("NAPI NativeAlterPin2 %{public}d", result);
    if (result) {
        pinContext->result = response.result;
        pinContext->remain = response.remain;
    }
    pinContext->pinContext.context.resolved = result;
}

void AlterPinCallback2(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, context->pinContext, "alter pin2 failed");
}

napi_value AlterPin2(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pinContext->pinContext.context;

    auto initPara = std::make_tuple(&pinContext->pinContext.slotId, std::data(pinContext->inStr1),
        std::data(pinContext->inStr2), &context.callbackRef);
    AsyncPara para {
        .funcName = "AlterPin2",
        .env = env,
        .info = info,
        .execute = NativeAlterPin2,
        .complete = AlterPinCallback2,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        pinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeGetOperatorConfigs(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncOperatorConfig *info = static_cast<AsyncOperatorConfig *>(data);
    OperatorConfig config;
    bool result =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorConfigs(info->asyncContext.slotId, config);
    TELEPHONY_LOGI("NAPI NativeGetOperatorConfigs %{public}d", result);
    if (result) {
        for (const auto &val : config.configValue) {
            ConfigInfo &&config = {NapiUtil::ToUtf8(val.first), NapiUtil::ToUtf8(val.second)};
            info->configValue.push_back(config);
        }
    }
    info->asyncContext.context.resolved = result;
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
    NapiAsyncCompleteCallback(env, status, aContext, "get operator config failed");
}

napi_value GetOperatorConfigs(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncOperatorConfig> crrierConfig = std::make_unique<AsyncOperatorConfig>();
    BaseContext &context = crrierConfig->asyncContext.context;

    auto initPara = std::make_tuple(&crrierConfig->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "GetOperatorConfigs",
        .env = env,
        .info = info,
        .execute = NativeGetOperatorConfigs,
        .complete = GetOperatorConfigsCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        crrierConfig.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
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
    bool result = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetActiveSimAccountInfoList(activeInfo);
    TELEPHONY_LOGI("NAPI NativeGetActiveSimAccountInfoList %{public}d", result);
    if (result) {
        accountInfo->vecInfo.swap(activeInfo);
        accountInfo->asyncContext.context.resolved = true;
    } else {
        accountInfo->asyncContext.context.resolved = false;
    }
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
    NapiAsyncCompleteCallback(env, status, asyncContext, "get active subscription info list failed");
}

napi_value GetActiveSimAccountInfoList(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncIccAccountInfo> accountInfo = std::make_unique<AsyncIccAccountInfo>();
    BaseContext &context = accountInfo->asyncContext.context;

    auto initPara = std::make_tuple(&context.callbackRef);
    AsyncPara para {
        .funcName = "GetActiveSimAccountInfoList",
        .env = env,
        .info = info,
        .execute = NativeGetActiveSimAccountInfoList,
        .complete = GetActiveSimAccountInfoListCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        accountInfo.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeQueryIccDiallingNumbers(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncDiallingNumbers<napi_value> *diallingNumbers = static_cast<AsyncDiallingNumbers<napi_value> *>(data);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().QueryIccDiallingNumbers(
            diallingNumbers->asyncContext.slotId, diallingNumbers->type);
    TELEPHONY_LOGI("NAPI NativeQueryIccDiallingNumbers %{public}zu", result.size());
    if (!result.empty()) {
        std::vector<TelNumbersInfo> &dialNumbers = diallingNumbers->infoVec;
        for (const auto &dialNumber : result) {
            TelNumbersInfo info {};
            NapiUtil::ToUtf8(dialNumber->name_).copy(info.alphaTag.data(), ARRAY_SIZE);
            NapiUtil::ToUtf8(dialNumber->number_).copy(info.number.data(), ARRAY_SIZE);
            info.recordNumber = dialNumber->index_;
            dialNumbers.push_back(std::move(info));
        }
    }
    diallingNumbers->asyncContext.context.resolved = true;
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
    NapiAsyncCompleteCallback(env, status, diallingNumbers->asyncContext, "query icc dialling numbers failed");
}

napi_value QueryIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncDiallingNumbers<napi_value>> diallingNumbers =
        std::make_unique<AsyncDiallingNumbers<napi_value>>();
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
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        diallingNumbers.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeAddIccDiallingNumbers(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncDiallingNumbers<bool> *diallingNumbersContext = static_cast<AsyncDiallingNumbers<bool> *>(data);
    AsyncContext<bool> &asyncContext = diallingNumbersContext->asyncContext;
    if (diallingNumbersContext->infoVec.size() > 0) {
        std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
        GetDiallingNumberInfo(telNumber, diallingNumbersContext->infoVec.at(0));
        asyncContext.callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().AddIccDiallingNumbers(
            asyncContext.slotId, diallingNumbersContext->type, telNumber);
        TELEPHONY_LOGI("NAPI NativeAddIccDiallingNumbers %{public}d", asyncContext.callbackVal);
        asyncContext.context.resolved = asyncContext.callbackVal;
    }
}

void AddIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDiallingNumbers<bool>> context(static_cast<AsyncDiallingNumbers<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, context->asyncContext, "phone book insert failed", true);
}

napi_value AddIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncDiallingNumbers<bool>> diallingNumbers = std::make_unique<AsyncDiallingNumbers<bool>>();
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
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        TelNumbersInfo inputInfo;
        DiallingNumberParaAnalyze(env, object, inputInfo);
        diallingNumbers->infoVec.push_back(std::move(inputInfo));
        diallingNumbers.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeDelIccDiallingNumbers(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncDiallingNumbers<bool> *diallingNumbers = static_cast<AsyncDiallingNumbers<bool> *>(data);
    if (diallingNumbers->infoVec.size() > 0) {
        std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
        GetDiallingNumberInfo(telNumber, diallingNumbers->infoVec.at(0));
        diallingNumbers->asyncContext.callbackVal =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().DelIccDiallingNumbers(
                diallingNumbers->asyncContext.slotId, diallingNumbers->type, telNumber);
        TELEPHONY_LOGI("NAPI NativeDelIccDiallingNumbers %{public}d", diallingNumbers->asyncContext.callbackVal);
        diallingNumbers->asyncContext.context.resolved = diallingNumbers->asyncContext.callbackVal;
    }
}

void DelIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDiallingNumbers<bool>> diallingNumbers(static_cast<AsyncDiallingNumbers<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, diallingNumbers->asyncContext, "phone book delete failed", true);
}

napi_value DelIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncDiallingNumbers<bool>> diallingNumbers = std::make_unique<AsyncDiallingNumbers<bool>>();
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
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        TelNumbersInfo inputInfo;
        DiallingNumberParaAnalyze(env, object, inputInfo);
        diallingNumbers->infoVec.push_back(std::move(inputInfo));
        diallingNumbers.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeUpdateIccDiallingNumbers(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncDiallingNumbers<bool> *diallingNumbers = static_cast<AsyncDiallingNumbers<bool> *>(data);
    AsyncContext<bool> &asyncContext = diallingNumbers->asyncContext;

    if (diallingNumbers->infoVec.size() > 0) {
        std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
        GetDiallingNumberInfo(telNumber, diallingNumbers->infoVec.at(0));
        asyncContext.callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().UpdateIccDiallingNumbers(
            asyncContext.slotId, diallingNumbers->type, telNumber);
        TELEPHONY_LOGI("NAPI NativeUpdateIccDiallingNumbers %{public}d", asyncContext.callbackVal);
        asyncContext.context.resolved = asyncContext.callbackVal;
    }
}

void UpdateIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDiallingNumbers<bool>> context(static_cast<AsyncDiallingNumbers<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, context->asyncContext, "phone book update failed", true);
}

napi_value UpdateIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncDiallingNumbers<bool>> diallingNumbers = std::make_unique<AsyncDiallingNumbers<bool>>();
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
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        TelNumbersInfo inputInfo;
        DiallingNumberParaAnalyze(env, object, inputInfo);
        diallingNumbers->infoVec.push_back(std::move(inputInfo));
        diallingNumbers.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
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

    std::u16string mailName = NapiUtil::ToUtf16(std::data(mailContext->mailName));
    std::u16string mailNumber = NapiUtil::ToUtf16(std::data(mailContext->mailNumber));
    asyncContext.callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetVoiceMailInfo(
        asyncContext.slotId, mailName, mailNumber);
    TELEPHONY_LOGI("NAPI NativeSetVoiceMailInfo %{public}d", asyncContext.callbackVal);
    asyncContext.context.resolved = asyncContext.callbackVal;
}

void SetVoiceMailInfoCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncVoiceMail> context(static_cast<AsyncVoiceMail *>(data));
    NapiAsyncCompleteCallback(env, status, context->asyncContext, "set voice mail number failed", true);
}

napi_value SetVoiceMailInfo(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncVoiceMail> mailContext = std::make_unique<AsyncVoiceMail>();
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
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        mailContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeSendEnvelopeCmd(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext2<bool> *context = static_cast<AsyncContext2<bool> *>(data);
    context->aContext.callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendEnvelopeCmd(
        context->aContext.slotId, std::data(context->inputStr));
    TELEPHONY_LOGI("NAPI NativeSendEnvelopeCmd %{public}d", context->aContext.callbackVal);
    context->aContext.context.resolved = context->aContext.callbackVal;
}

void SendEnvelopeCmdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext2<bool>> context(static_cast<AsyncContext2<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, context->aContext, "Stk Cmd From App Envelope failed", true);
}

napi_value SendEnvelopeCmd(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContext2<bool>> asyncContext = std::make_unique<AsyncContext2<bool>>();
    BaseContext &context = asyncContext->aContext.context;

    auto initPara =
        std::make_tuple(&asyncContext->aContext.slotId, std::data(asyncContext->inputStr), &context.callbackRef);
    AsyncPara para {
        .funcName = "SendEnvelopeCmd",
        .env = env,
        .info = info,
        .execute = NativeSendEnvelopeCmd,
        .complete = SendEnvelopeCmdCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        asyncContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeSendTerminalResponseCmd(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext2<bool> *context = static_cast<AsyncContext2<bool> *>(data);
    context->aContext.callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendTerminalResponseCmd(
        context->aContext.slotId, std::data(context->inputStr));
    TELEPHONY_LOGI("NAPI NativeSendTerminalResponseCmd %{public}d", context->aContext.callbackVal);
    context->aContext.context.resolved = context->aContext.callbackVal;
}

void SendTerminalResponseCmdCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext2<bool>> context(static_cast<AsyncContext2<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, context->aContext, "Stk Cmd From App Envelope failed", true);
}

napi_value SendTerminalResponseCmd(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContext2<bool>> asyncContext = std::make_unique<AsyncContext2<bool>>();
    BaseContext &context = asyncContext->aContext.context;

    auto initPara =
        std::make_tuple(&asyncContext->aContext.slotId, std::data(asyncContext->inputStr), &context.callbackRef);
    AsyncPara para {
        .funcName = "SendTerminalResponseCmd",
        .env = env,
        .info = info,
        .execute = NativeSendTerminalResponseCmd,
        .complete = SendTerminalResponseCmdCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        asyncContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

napi_value GetMaxSimCount(napi_env env, napi_callback_info)
{
    return GetNapiValue(env, DelayedRefSingleton<CoreServiceClient>::GetInstance().GetMaxSimCount());
}

void NativeGetLockState(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncGetLockState *lockContext = static_cast<AsyncGetLockState *>(data);
    AsyncContext<int32_t> &asContext = lockContext->asyncContext;
    asContext.callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetLockState(
        asContext.slotId, static_cast<LockType>(lockContext->lockType));
    TELEPHONY_LOGI("NAPI NativeGetLockState %{public}d", asContext.callbackVal);
    asContext.context.resolved = (asContext.callbackVal == static_cast<int32_t>(LockState::LOCK_ON) ||
        asContext.callbackVal == static_cast<int32_t>(LockState::LOCK_OFF));
}

void GetLockStateCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncGetLockState> context(static_cast<AsyncGetLockState *>(data));
    NapiAsyncCompleteCallback(env, status, context->asyncContext, "get lock state failed");
}

napi_value GetLockState(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncGetLockState> lockStateContext = std::make_unique<AsyncGetLockState>();
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
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        lockStateContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeHasOperatorPrivileges(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    reVal->callbackVal = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasOperatorPrivileges(reVal->slotId);
    TELEPHONY_LOGI("NAPI NativeHasOperatorPrivileges %{public}d", reVal->callbackVal);
    /* transparent return value */
    reVal->context.resolved = true;
}

void HasOperatorPrivilegesCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "has operator privileges failed");
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

    LockStatusResponse response {ERROR_DEFAULT, ERROR_DEFAULT};
    PersoLockInfo lockInfo {
        static_cast<PersoLockType>(asyncContext->pinEnable), NapiUtil::ToUtf16(asyncContext->inStr1.data())};
    bool result = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockSimLock(
        asyncContext->pinContext.slotId, lockInfo, response);
    TELEPHONY_LOGI("NAPI NativeUnlockSimLock %{public}d", result);
    if (result) {
        asyncContext->result = response.result;
        asyncContext->remain = response.remain;
    }
    asyncContext->pinContext.context.resolved = result;
}

void UnlockSimLockCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextPIN> context(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {context->result, context->remain};
    context->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, context->pinContext, "unlock sim lock failed!");
}

napi_value UnlockSimLock(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pinContext->pinContext.context;

    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara = std::make_tuple(&pinContext->pinContext.slotId, &object, &context.callbackRef);
    AsyncPara para {
        .funcName = "UnlockSimLock",
        .env = env,
        .info = info,
        .execute = NativeUnlockSimLock,
        .complete = UnlockSimLockCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara);
    if (result) {
        PersoLockInfoAnalyze(env, object, *pinContext);
        pinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
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
        DECLARE_NAPI_FUNCTION("getVoiceMailIdentifier", GetVoiceMailIdentifier),
        DECLARE_NAPI_FUNCTION("getVoiceMailNumber", GetVoiceMailNumber),
        DECLARE_NAPI_FUNCTION("setVoiceMailInfo", SetVoiceMailInfo),
    };
    return napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

napi_status InitSimInterface(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getISOCountryCodeForSim", GetISOCountryCodeForSim),
        DECLARE_NAPI_FUNCTION("getSimOperatorNumeric", GetSimOperatorNumeric),
        DECLARE_NAPI_FUNCTION("getSimSpn", GetSimSpn),
        DECLARE_NAPI_FUNCTION("getSimState", GetSimState),
        DECLARE_NAPI_FUNCTION("getCardType", GetCardType),
        DECLARE_NAPI_FUNCTION("getSimIccId", GetSimIccId),
        DECLARE_NAPI_FUNCTION("getIMSI", GetIMSI),
        DECLARE_NAPI_FUNCTION("hasSimCard", HasSimCard),
        DECLARE_NAPI_FUNCTION("getSimGid1", GetSimGid1),
        DECLARE_NAPI_FUNCTION("getSimAccountInfo", GetSimAccountInfo),
        DECLARE_NAPI_FUNCTION("isSimActive", IsSimActive),
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
        DECLARE_NAPI_FUNCTION("getMaxSimCount", GetMaxSimCount),
        DECLARE_NAPI_FUNCTION("hasOperatorPrivileges", HasOperatorPrivileges),
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
