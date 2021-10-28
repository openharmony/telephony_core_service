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
#include "napi_sim_type.h"
#include "network_state.h"
#include "sim_card_manager.h"
#include "str_convert.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
std::unique_ptr<SimCardManager> g_simCardManager;

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
    TELEPHONY_LOGD("NAPI_SIM NapiCreateAsyncWork");
    size_t argc = 2;
    napi_value argv[] {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    std::unique_ptr<AsyncContext<T>> asyncContext = std::make_unique<AsyncContext<T>>();
    BaseContext &context = asyncContext->context;
    vecNapiType typeStd {napi_number};
    if (argc == std::size(argv)) {
        typeStd.emplace_back(napi_function);
    }
    auto inParaTp = std::make_tuple(&asyncContext->slotId, &context.callbackRef);
    if (!MatchParameters(env, argv, argc, inParaTp, typeStd)) {
        napi_throw_error(env, nullptr, "type of input parameters error!");
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
napi_value NapiCreateAsyncWork2(
    const AsyncPara &para, BaseContext &context, std::tuple<Ts...> &theTuple, vecNapiType &typeStd)
{
    TELEPHONY_LOGD("NAPI_SIM NapiCreateAsyncWork2");
    napi_env env = para.env;
    if (!(typeStd.size() == sizeof...(Ts))) {
        napi_throw_error(env, nullptr, "Number of input parameters error!");
        return nullptr;
    }

    size_t argc = typeStd.size();
    constexpr size_t arrSize = sizeof...(Ts);
    napi_value argv[arrSize] {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, para.info, &argc, argv, nullptr, nullptr));
    if (argc < typeStd.size()) {
        typeStd.pop_back();
    }

    if (!MatchParameters(env, argv, argc, theTuple, typeStd)) {
        napi_throw_error(env, nullptr, "type of input parameters error!");
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
            env, nullptr, resourceName, para.execute, para.complete, (void *)&context, &context.work));
    return result;
}

template<typename T>
void NapiAsyncCompleteCallback(napi_env env, napi_status status, const AsyncContext<T> &asyncContext,
    std::string errMessage, bool funcHasReturnVal = false)
{
    TELEPHONY_LOGD("NAPI_SIM NapiAsyncCompleteCallback");
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
                (funcHasReturnVal ? NapiUtil::CreateUndefined(env) : GetNapiValue(env, asyncContext.callbackVal));
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, res));
        }
    } else {
        napi_value res =
            (funcHasReturnVal ? NapiUtil::CreateUndefined(env) : GetNapiValue(env, asyncContext.callbackVal));
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

napi_value SubscriptionInfoConversion(napi_env env, const IccAccountInfo &iccAccountInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    napi_set_named_property(env, val, "slotIndex", GetNapiValue(env, iccAccountInfo.slotIndex));
    napi_set_named_property(env, val, "showName", GetNapiValue(env, ToUtf8(iccAccountInfo.displayName)));
    napi_set_named_property(env, val, "showNumber", GetNapiValue(env, ToUtf8(iccAccountInfo.displayNumber)));
    return val;
}

napi_value PinOrPukUnlockConversion(napi_env env, const LockStatusResponse &response)
{
    constexpr int32_t passWordErr = -1;
    napi_value val = nullptr;
    napi_create_object(env, &val);
    napi_set_named_property(env, val, "result", GetNapiValue(env, response.result));
    napi_value res =
        ((response.result == passWordErr) ? GetNapiValue(env, response.remain) : NapiUtil::CreateUndefined(env));
    napi_set_named_property(env, val, "remain", res);
    return val;
}

napi_value DiallingNumbersConversion(napi_env env, const TelNumbersInfo &info)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    napi_set_named_property(env, val, "recordNumber", GetNapiValue(env, info.recordNumber));
    napi_set_named_property(env, val, "alphaTag", GetNapiValue(env, std::data(info.alphaTag)));
    napi_set_named_property(env, val, "number", GetNapiValue(env, std::data(info.number)));
    return val;
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
    TELEPHONY_LOGD("DiallingNumberParaAnalyze info.recordNumber = %{public}d", info.recordNumber);
    TELEPHONY_LOGD("DiallingNumberParaAnalyze info.alphaTag = %{public}s", info.alphaTag.data());
    TELEPHONY_LOGD("DiallingNumberParaAnalyze info.number = %{public}s", info.number.data());
}
} // namespace

static void NativeHasSimCard(napi_env env, void *data)
{
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);

    if (g_simCardManager) {
        reVal->callbackVal = g_simCardManager->HasSimCard(reVal->slotId);
    }
    TELEPHONY_LOGD("hasSimCard %{public}d", reVal->callbackVal);
    /* Transparent return value */
    reVal->context.resolved = true;
}

static void HasSimCardCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "has sim card state failed");
}

static napi_value HasSimCard(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeHasSimCard, HasSimCardCallback>(env, info, "HasSimCard");
}

static void NativeGetDefaultVoiceSlotId(napi_env env, void *data)
{
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);
    asyncContext->callbackVal = DEFAULT_ERROR;
    if (g_simCardManager) {
        asyncContext->callbackVal = g_simCardManager->GetDefaultVoiceSlotId();
    }
    asyncContext->context.resolved = !(asyncContext->callbackVal == DEFAULT_ERROR);
}

static void GetDefaultVoiceSlotIdCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get default voice slot id failed");
}

static napi_value GetDefaultVoiceSlotId(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContext<int32_t>> asyncContext = std::make_unique<AsyncContext<int32_t>>();
    BaseContext &context = asyncContext->context;

    auto initPara = std::make_tuple(&context.callbackRef);
    vecNapiType typeStd {napi_function};
    AsyncPara para {
        .funcName = "GetDefaultVoiceSlotId",
        .env = env,
        .info = info,
        .execute = NativeGetDefaultVoiceSlotId,
        .complete = GetDefaultVoiceSlotIdCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result != nullptr) {
        asyncContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

static void NativeGetIsoForSim(napi_env env, void *data)
{
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    std::string isoCountryCode;
    if (g_simCardManager) {
        isoCountryCode = ToUtf8(g_simCardManager->GetIsoCountryCodeForSim(asyncContext->slotId));
        asyncContext->callbackVal = isoCountryCode;
    }
    asyncContext->context.resolved = !isoCountryCode.empty();
}

static void GetIsoForSimCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get iso country code for sim failed");
}

static napi_value GetIsoCountryCodeForSim(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetIsoForSim, GetIsoForSimCallback>(
        env, info, "GetIsoCountryCodeForSim");
}

static void NativeGetSimOperatorNumeric(napi_env env, void *data)
{
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    std::string simOperNum;
    if (g_simCardManager) {
        simOperNum = ToUtf8(g_simCardManager->GetSimOperatorNumeric(asyncContext->slotId));
        asyncContext->callbackVal = simOperNum;
    }
    asyncContext->context.resolved = !simOperNum.empty();
}

static void GetSimOperatorNumericCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim operator numeric failed");
}

static napi_value GetSimOperatorNumeric(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimOperatorNumeric, GetSimOperatorNumericCallback>(
        env, info, "GetSimOperatorNumeric");
}

static void NativeGetSimSpn(napi_env env, void *data)
{
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    std::string simSpn;
    if (g_simCardManager) {
        simSpn = ToUtf8(g_simCardManager->GetSimSpn(asyncContext->slotId));
        asyncContext->callbackVal = simSpn;
    }
    asyncContext->context.resolved = !simSpn.empty();
}

static void GetSimSpnCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim spn failed");
}

static napi_value GetSimSpn(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimSpn, GetSimSpnCallback>(env, info, "GetSimSpn");
}

static void NativeGetSimState(napi_env env, void *data)
{
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);
    int32_t simState = DEFAULT_ERROR;
    if (g_simCardManager) {
        simState = g_simCardManager->GetSimState(asyncContext->slotId);
    }
    if (simState >= SIM_STATE_UNKNOWN) {
        asyncContext->context.resolved = true;
        asyncContext->callbackVal = simState;
    } else {
        asyncContext->context.resolved = false;
    }
}

static void GetSimStateCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim state failed");
}

static napi_value GetSimState(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<int32_t, NativeGetSimState, GetSimStateCallback>(env, info, "GetSimState");
}

static void NativeGetSimGid1(napi_env env, void *data)
{
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    std::string simGid1;
    if (g_simCardManager) {
        simGid1 = ToUtf8(g_simCardManager->GetSimGid1(asyncContext->slotId));
        asyncContext->callbackVal = simGid1;
    }
    asyncContext->context.resolved = !simGid1.empty();
}

static void GetSimGid1Callback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim gid1 failed");
}

static napi_value GetSimGid1(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimGid1, GetSimGid1Callback>(env, info, "GetSimGid1");
}

static void NativeGetSimIccId(napi_env env, void *data)
{
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    std::string simIccId;
    if (g_simCardManager) {
        simIccId = ToUtf8(g_simCardManager->GetSimIccId(asyncContext->slotId));
        asyncContext->callbackVal = simIccId;
    }
    asyncContext->context.resolved = !simIccId.empty();
}

static void GetSimIccIdCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim icc id failed");
}

static napi_value GetSimIccId(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimIccId, GetSimIccIdCallback>(env, info, "GetSimIccId");
}

static void NativeGetSimAccountInfo(napi_env env, void *data)
{
    AsyncIccAccountInfo *info = static_cast<AsyncIccAccountInfo *>(data);
    bool result = false;
    if (g_simCardManager) {
        IccAccountInfo operInfo;
        result = g_simCardManager->GetSimAccountInfo(info->asyncContext.slotId, operInfo);
        if (result) {
            info->vecInfo.emplace_back(operInfo);
        }
    }
    info->asyncContext.context.resolved = result;
}

static void GetSimAccountInfoCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncIccAccountInfo> info(static_cast<AsyncIccAccountInfo *>(data));
    AsyncContext<napi_value> &asyncContext = info->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal = SubscriptionInfoConversion(env, info->vecInfo.at(0));
    }
    NapiAsyncCompleteCallback(env, status, asyncContext, "get sim subscription info failed");
}

static napi_value GetSimAccountInfo(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncIccAccountInfo> iccAccountInfo = std::make_unique<AsyncIccAccountInfo>();
    BaseContext &context = iccAccountInfo->asyncContext.context;

    auto initPara = std::make_tuple(&iccAccountInfo->asyncContext.slotId, &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_function};
    AsyncPara para {
        .funcName = "GetSimAccountInfo",
        .env = env,
        .info = info,
        .execute = NativeGetSimAccountInfo,
        .complete = GetSimAccountInfoCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result != nullptr) {
        iccAccountInfo.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

static void NativeSetDefaultVoiceSlotId(napi_env env, void *data)
{
    AsyncContext<bool> *reVal = static_cast<AsyncContext<bool> *>(data);
    reVal->callbackVal = false;
    if (g_simCardManager) {
        reVal->callbackVal = g_simCardManager->SetDefaultVoiceSlotId(reVal->slotId);
    }
    reVal->context.resolved = reVal->callbackVal;
}

static void SetDefaultVoiceSlotIdCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<bool>> context(static_cast<AsyncContext<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "set default voice slot id failed", true);
}

static napi_value SetDefaultVoiceSlotId(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<bool, NativeSetDefaultVoiceSlotId, SetDefaultVoiceSlotIdCallback>(
        env, info, "SetDefaultVoiceSlotId");
}

static void NativeUnlockPin(napi_env env, void *data)
{
    AsyncContextPIN *pinContext = static_cast<AsyncContextPIN *>(data);
    bool res = false;
    if (g_simCardManager) {
        LockStatusResponse response {DEFAULT_ERROR, DEFAULT_ERROR};
        res = g_simCardManager->UnlockPin(ToUtf16(pinContext->pin.data()), response, pinContext->pinContext.slotId);
        if (res) {
            pinContext->result = response.result;
            pinContext->remain = response.remain;
        }
    }
    pinContext->pinContext.context.resolved = res;
}

static void UnlockPinCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContextPIN> pinContext(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {pinContext->result, pinContext->remain};
    pinContext->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, pinContext->pinContext, "unlock pin failed");
}

static napi_value UnlockPin(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pinContext->pinContext.context;

    auto initPara =
        std::make_tuple(&pinContext->pinContext.slotId, std::data(pinContext->pin), &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_string, napi_function};
    AsyncPara para {
        .funcName = "UnlockPin",
        .env = env,
        .info = info,
        .execute = NativeUnlockPin,
        .complete = UnlockPinCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result != nullptr) {
        pinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

static void NativeUnlockPuk(napi_env env, void *data)
{
    AsyncContextPIN *pukContext = static_cast<AsyncContextPIN *>(data);
    bool res = false;
    if (g_simCardManager) {
        LockStatusResponse response {DEFAULT_ERROR, DEFAULT_ERROR};
        res = g_simCardManager->UnlockPuk(ToUtf16(pukContext->pin.data()), ToUtf16(pukContext->puk.data()),
            response, pukContext->pinContext.slotId);
        if (res) {
            pukContext->result = response.result;
            pukContext->remain = response.remain;
        }
    }
    pukContext->pinContext.context.resolved = res;
}

static void UnlockPukCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContextPIN> pukContext(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {pukContext->result, pukContext->remain};
    pukContext->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, pukContext->pinContext, "unlock puk failed");
}

static napi_value UnlockPuk(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pinContext->pinContext.context;

    auto initPara = std::make_tuple(&pinContext->pinContext.slotId, std::data(pinContext->pin),
        std::data(pinContext->puk), &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_string, napi_string, napi_function};
    AsyncPara para {
        .funcName = "UnlockPuk",
        .env = env,
        .info = info,
        .execute = NativeUnlockPuk,
        .complete = UnlockPukCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result != nullptr) {
        pinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

static void NativeAlterPin(napi_env env, void *data)
{
    AsyncContextPIN *pinContext = static_cast<AsyncContextPIN *>(data);
    bool res = false;
    if (g_simCardManager) {
        LockStatusResponse response {DEFAULT_ERROR, DEFAULT_ERROR};
        res = g_simCardManager->AlterPin(ToUtf16(pinContext->pin.data()), ToUtf16(pinContext->puk.data()),
            response, pinContext->pinContext.slotId);
        if (res) {
            pinContext->result = response.result;
            pinContext->remain = response.remain;
        }
    }
    pinContext->pinContext.context.resolved = res;
}

static void AlterPinCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContextPIN> pinContext(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {pinContext->result, pinContext->remain};
    pinContext->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, pinContext->pinContext, "alter pin failed");
}

static napi_value AlterPin(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> pinContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = pinContext->pinContext.context;

    auto initPara = std::make_tuple(&pinContext->pinContext.slotId, std::data(pinContext->pin),
        std::data(pinContext->puk), &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_string, napi_string, napi_function};
    AsyncPara para {
        .funcName = "AlterPin",
        .env = env,
        .info = info,
        .execute = NativeAlterPin,
        .complete = AlterPinCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result != nullptr) {
        pinContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

static void NativeSetLockState(napi_env env, void *data)
{
    AsyncContextPIN *lockContext = static_cast<AsyncContextPIN *>(data);
    bool res = false;
    if (g_simCardManager) {
        LockStatusResponse response {DEFAULT_ERROR, DEFAULT_ERROR};
        res = g_simCardManager->SetLockState(
            ToUtf16(lockContext->pin.data()), lockContext->pinEnable, response, lockContext->pinContext.slotId);
        if (res) {
            lockContext->result = response.result;
            lockContext->remain = response.remain;
        }
    }
    lockContext->pinContext.context.resolved = res;
}

static void SetLockStateCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContextPIN> lockContext(static_cast<AsyncContextPIN *>(data));
    const LockStatusResponse res {lockContext->result, lockContext->remain};
    lockContext->pinContext.callbackVal = PinOrPukUnlockConversion(env, res);
    NapiAsyncCompleteCallback(env, status, lockContext->pinContext, "set lock state failed");
}

static napi_value SetLockState(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncContextPIN> lockContext = std::make_unique<AsyncContextPIN>();
    BaseContext &context = lockContext->pinContext.context;

    auto initPara = std::make_tuple(&lockContext->pinContext.slotId, std::data(lockContext->pin),
        &lockContext->pinEnable, &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_string, napi_number, napi_function};
    AsyncPara para {
        .funcName = "SetLockState",
        .env = env,
        .info = info,
        .execute = NativeSetLockState,
        .complete = SetLockStateCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result != nullptr) {
        lockContext.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

static void NativeGetIMSI(napi_env env, void *data)
{
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    std::string strIMSI;
    if (g_simCardManager) {
        strIMSI = ToUtf8(g_simCardManager->GetIMSI(asyncContext->slotId));
        asyncContext->callbackVal = strIMSI;
    }
    asyncContext->context.resolved = !strIMSI.empty();
}

static void GetIMSICallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get IMSI failed");
}

static napi_value GetIMSI(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetIMSI, GetIMSICallback>(env, info, "GetIMSI");
}

void NativeGetSimTelephoneNumber(napi_env env, void *data)
{
    AsyncContext<std::string> *asyncContext = static_cast<AsyncContext<std::string> *>(data);
    asyncContext->callbackVal.clear();
    if (g_simCardManager) {
        asyncContext->callbackVal = ToUtf8(g_simCardManager->GetSimTelephoneNumber(asyncContext->slotId));
    }
    asyncContext->context.resolved = !(asyncContext->callbackVal.empty());
}

void GetSimTelephoneNumberCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    NapiAsyncCompleteCallback(env, status, *context, "get sim telephone number failed");
}

napi_value GetSimTelephoneNumber(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetSimTelephoneNumber, GetSimTelephoneNumberCallback>(
        env, info, "GetSimTelephoneNumber");
}

void NativeQueryIccDiallingNumbers(napi_env env, void *data)
{
    AsyncPhoneBook<napi_value> *phoneBook = static_cast<AsyncPhoneBook<napi_value> *>(data);
    phoneBook->asyncContext.context.resolved = false;
    if (g_simCardManager) {
        std::vector<std::shared_ptr<DiallingNumbersInfo>> result =
            g_simCardManager->QueryIccDiallingNumbers(phoneBook->asyncContext.slotId, phoneBook->type);
        if (!result.empty()) {
            std::vector<TelNumbersInfo> &dialNumbers = phoneBook->infoVec;
            for (const auto &dialNumber : result) {
                TelNumbersInfo info {};
                NapiUtil::ToUtf8(dialNumber->alphaTag_).copy(info.alphaTag.data(), ARRAY_SIZE);
                NapiUtil::ToUtf8(dialNumber->number_).copy(info.number.data(), ARRAY_SIZE);
                info.recordNumber = dialNumber->recordNumber_;
                dialNumbers.push_back(std::move(info));
            }
        }
        phoneBook->asyncContext.context.resolved = true;
    }
}

void QueryIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncPhoneBook<napi_value>> phoneBook(static_cast<AsyncPhoneBook<napi_value> *>(data));
    phoneBook->asyncContext.callbackVal = nullptr;
    napi_create_array(env, &phoneBook->asyncContext.callbackVal);
    for (size_t i = 0; i < phoneBook->infoVec.size(); i++) {
        napi_value val = DiallingNumbersConversion(env, phoneBook->infoVec.at(i));
        napi_set_element(env, phoneBook->asyncContext.callbackVal, i, val);
    }
    NapiAsyncCompleteCallback(env, status, phoneBook->asyncContext, "query icc dialling numbers failed");
}

napi_value QueryIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncPhoneBook<napi_value>> phoneBook = std::make_unique<AsyncPhoneBook<napi_value>>();
    BaseContext &context = phoneBook->asyncContext.context;

    auto initPara = std::make_tuple(&phoneBook->asyncContext.slotId, &phoneBook->type, &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_number, napi_function};
    AsyncPara para {
        .funcName = "QueryIccDiallingNumbers",
        .env = env,
        .info = info,
        .execute = NativeQueryIccDiallingNumbers,
        .complete = QueryIccDiallingNumbersCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result) {
        phoneBook.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeAddIccDiallingNumbers(napi_env env, void *data)
{
    AsyncPhoneBook<bool> *phoneBookContext = static_cast<AsyncPhoneBook<bool> *>(data);
    AsyncContext<bool> &asyncContext = phoneBookContext->asyncContext;
    asyncContext.context.resolved = false;
    if (g_simCardManager) {
        if (phoneBookContext->infoVec.size() > 0) {
            std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
            const TelNumbersInfo &info = phoneBookContext->infoVec.at(0);
            telNumber->recordNumber_ = info.recordNumber;
            telNumber->alphaTag_ = NapiUtil::ToUtf16(info.alphaTag.data());
            telNumber->number_ = NapiUtil::ToUtf16(info.number.data());
            TELEPHONY_LOGD("AddIccDiallingNumbers info.recordNumber = %{public}d", info.recordNumber);
            asyncContext.callbackVal =
                g_simCardManager->AddIccDiallingNumbers(asyncContext.slotId, phoneBookContext->type, telNumber);
            TELEPHONY_LOGD("AddIccDiallingNumbers asyncContext.callbackVal = %{public}d", asyncContext.callbackVal);
            asyncContext.context.resolved = asyncContext.callbackVal;
        }
    }
}

void AddIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncPhoneBook<bool>> context(static_cast<AsyncPhoneBook<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, context->asyncContext, "phone book insert failed", true);
}

napi_value AddIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncPhoneBook<bool>> phoneBook = std::make_unique<AsyncPhoneBook<bool>>();
    BaseContext &context = phoneBook->asyncContext.context;

    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara =
        std::make_tuple(&phoneBook->asyncContext.slotId, &phoneBook->type, &object, &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_number, napi_object, napi_function};

    AsyncPara para {
        .funcName = "AddIccDiallingNumbers",
        .env = env,
        .info = info,
        .execute = NativeAddIccDiallingNumbers,
        .complete = AddIccDiallingNumbersCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result) {
        TelNumbersInfo inputInfo;
        DiallingNumberParaAnalyze(env, object, inputInfo);
        phoneBook->infoVec.push_back(std::move(inputInfo));
        phoneBook.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeDelIccDiallingNumbers(napi_env env, void *data)
{
    AsyncDelPhoneBook *phoneBook = static_cast<AsyncDelPhoneBook *>(data);

    TELEPHONY_LOGD("DelIccDiallingNumbers phoneBook->index = %{public}d", phoneBook->index);
    phoneBook->asyncContext.context.resolved = false;
    if (g_simCardManager) {
        phoneBook->asyncContext.callbackVal = g_simCardManager->DelIccDiallingNumbers(
            phoneBook->asyncContext.slotId, phoneBook->type, phoneBook->index);
        TELEPHONY_LOGD(
            "DelIccDiallingNumbers asyncContext.callbackVal = %{public}d", phoneBook->asyncContext.callbackVal);
        phoneBook->asyncContext.context.resolved = phoneBook->asyncContext.callbackVal;
    }
}

void DelIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncDelPhoneBook> phoneBook(static_cast<AsyncDelPhoneBook *>(data));
    NapiAsyncCompleteCallback(env, status, phoneBook->asyncContext, "phone book delete failed", true);
}

napi_value DelIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncDelPhoneBook> phoneBook = std::make_unique<AsyncDelPhoneBook>();
    BaseContext &context = phoneBook->asyncContext.context;

    auto initPara = std::make_tuple(
        &phoneBook->asyncContext.slotId, &phoneBook->type, &phoneBook->index, &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_number, napi_number, napi_function};
    AsyncPara para {
        .funcName = "DelIccDiallingNumbers",
        .env = env,
        .info = info,
        .execute = NativeDelIccDiallingNumbers,
        .complete = DelIccDiallingNumbersCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result) {
        phoneBook.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

void NativeUpdateIccDiallingNumbers(napi_env env, void *data)
{
    AsyncPhoneBook<bool> *phoneBook = static_cast<AsyncPhoneBook<bool> *>(data);
    AsyncContext<bool> &asyncContext = phoneBook->asyncContext;
    asyncContext.context.resolved = false;
    if (g_simCardManager) {
        if (phoneBook->infoVec.size() > 0) {
            std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
            const TelNumbersInfo &info = phoneBook->infoVec.at(0);
            telNumber->recordNumber_ = info.recordNumber;
            telNumber->alphaTag_ = NapiUtil::ToUtf16(info.alphaTag.data());
            telNumber->number_ = NapiUtil::ToUtf16(info.number.data());
            TELEPHONY_LOGD("UpdateIccDiallingNumbers number_ = %{public}s", info.number.data());
            asyncContext.callbackVal = g_simCardManager->UpdateIccDiallingNumbers(
                asyncContext.slotId, phoneBook->type, telNumber, phoneBook->index);
            TELEPHONY_LOGD(
                "UpdateIccDiallingNumbers asyncContext.callbackVal = %{public}d", asyncContext.callbackVal);
            asyncContext.context.resolved = asyncContext.callbackVal;
        }
    }
}

void UpdateIccDiallingNumbersCallback(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<AsyncPhoneBook<bool>> context(static_cast<AsyncPhoneBook<bool> *>(data));
    NapiAsyncCompleteCallback(env, status, context->asyncContext, "phone book update failed", true);
}

napi_value UpdateIccDiallingNumbers(napi_env env, napi_callback_info info)
{
    std::unique_ptr<AsyncPhoneBook<bool>> phoneBook = std::make_unique<AsyncPhoneBook<bool>>();
    BaseContext &context = phoneBook->asyncContext.context;

    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara = std::make_tuple(
        &phoneBook->asyncContext.slotId, &phoneBook->type, &object, &phoneBook->index, &context.callbackRef);
    vecNapiType typeStd {napi_number, napi_number, napi_object, napi_number, napi_function};

    AsyncPara para {
        .funcName = "UpdateIccDiallingNumbers",
        .env = env,
        .info = info,
        .execute = NativeUpdateIccDiallingNumbers,
        .complete = UpdateIccDiallingNumbersCallback,
    };
    napi_value result = NapiCreateAsyncWork2(para, context, initPara, typeStd);
    if (result) {
        TelNumbersInfo inputInfo;
        DiallingNumberParaAnalyze(env, object, inputInfo);
        phoneBook->infoVec.push_back(std::move(inputInfo));
        phoneBook.release();
        NAPI_CALL(env, napi_queue_async_work(env, context.work));
    }
    return result;
}

EXTERN_C_START
napi_value InitNapiSim(napi_env env, napi_value exports)
{
    g_simCardManager = std::make_unique<SimCardManager>();
    g_simCardManager->ConnectService();
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
        DECLARE_NAPI_FUNCTION("hasSimCard", HasSimCard),
        DECLARE_NAPI_FUNCTION("getSimState", GetSimState),
        DECLARE_NAPI_FUNCTION("getISOCountryCodeForSim", GetIsoCountryCodeForSim),
        DECLARE_NAPI_FUNCTION("getSimOperatorNumeric", GetSimOperatorNumeric),
        DECLARE_NAPI_FUNCTION("getSimSpn", GetSimSpn),
        DECLARE_NAPI_FUNCTION("getIMSI", GetIMSI),
        DECLARE_NAPI_FUNCTION("getSimIccId", GetSimIccId),
        DECLARE_NAPI_FUNCTION("getSimGid1", GetSimGid1),
        DECLARE_NAPI_FUNCTION("getSimAccountInfo", GetSimAccountInfo),
        DECLARE_NAPI_FUNCTION("setDefaultVoiceSlotId", SetDefaultVoiceSlotId),
        DECLARE_NAPI_FUNCTION("getDefaultVoiceSlotId", GetDefaultVoiceSlotId),
        DECLARE_NAPI_FUNCTION("unlockPin", UnlockPin),
        DECLARE_NAPI_FUNCTION("unlockPuk", UnlockPuk),
        DECLARE_NAPI_FUNCTION("alterPin", AlterPin),
        DECLARE_NAPI_FUNCTION("setLockState", SetLockState),
        DECLARE_NAPI_FUNCTION("getSimTelephoneNumber", GetSimTelephoneNumber),
        DECLARE_NAPI_FUNCTION("queryIccDiallingNumbers", QueryIccDiallingNumbers),
        DECLARE_NAPI_FUNCTION("addIccDiallingNumbers", AddIccDiallingNumbers),
        DECLARE_NAPI_FUNCTION("delIccDiallingNumbers", DelIccDiallingNumbers),
        DECLARE_NAPI_FUNCTION("updateIccDiallingNumbers", UpdateIccDiallingNumbers),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_UNKNOWN", simStateUnknown),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_NOT_PRESENT", simStateNotPresent),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_LOCKED", simStateLocked),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_NOT_READY", simStateNotReady),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_READY", simStateReady),
        DECLARE_NAPI_STATIC_PROPERTY("SIM_STATE_LOADED", simStateLoaded),
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
