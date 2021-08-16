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

#include "napi_radio.h"

#include <cstring>
#include <memory>

#include "hilog/log.h"
#include "network_state.h"
#include "radio_network_manager.h"

using namespace OHOS::HiviewDFX;
static constexpr HiLogLabel LABEL = {LOG_CORE, 1, "CoreServiceApi"};

namespace OHOS {
namespace TelephonyNapi {
static std::unique_ptr<RadioNetworkManager> g_radioNetworkManager;
static bool InitRadioNetworkManager()
{
    if (g_radioNetworkManager == nullptr) {
        g_radioNetworkManager = std::make_unique<RadioNetworkManager>();
    }
    return g_radioNetworkManager->IsConnect();
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

static int32_t WrapRadioTech(int32_t radioTechType)
{
    switch (radioTechType) {
        case OHOS::RADIO_TECHNOLOGY_GSM:
            return TelephonyNapi::RADIO_TECHNOLOGY_GSM;
        case OHOS::RADIO_TECHNOLOGY_1XRTT:
            return TelephonyNapi::RADIO_TECHNOLOGY_1XRTT;
        default:
            return TelephonyNapi::RADIO_TECHNOLOGY_UNKNOWN;
    }
}

static int32_t GetDefaultSlotId()
{
    return 1;
}

static napi_value SetPropertyInt32(napi_env env, napi_value object, std::string name, int32_t value)
{
    napi_value peopertyValue = nullptr;
    char *nameChars = GetChars(name);
    NAPI_CALL(env, napi_create_int32(env, value, &peopertyValue));
    NAPI_CALL(env, napi_set_named_property(env, object, nameChars, peopertyValue));
    return object;
}

static void ExecNativeGetRadioTech(const napi_env env, AsyncContext &asyncContext)
{
    int32_t psRadioTech = -1;
    int32_t csRadioTech = -1;
    if (InitRadioNetworkManager()) {
        psRadioTech = g_radioNetworkManager->GetPsRadioTech(asyncContext.slotId);
        csRadioTech = g_radioNetworkManager->GetCsRadioTech(asyncContext.slotId);
        HiLog::Debug(LABEL, "psRadioTech = %{public}d csRadioTech = %{public}d", psRadioTech, csRadioTech);
    }
    if (psRadioTech >= 0 || csRadioTech >= 0) {
        asyncContext.status = RESOLVED;
        int32_t wrappedPsRadioTech = WrapRadioTech(psRadioTech);
        int32_t wrappedCsRadioTech = WrapRadioTech(csRadioTech);
        HiLog::Debug(LABEL, "wrap_psRadioTech = %{public}d wrap_csRadioTech = %{public}d", wrappedPsRadioTech,
            wrappedCsRadioTech);
        napi_create_int32(env, wrappedPsRadioTech, &asyncContext.value[0]);
        napi_create_int32(env, wrappedCsRadioTech, &asyncContext.value[1]);
        asyncContext.valueLen = 2;
        HiLog::Debug(LABEL, "ExecNativeGetRadioTech status RESOLVED end");
    } else {
        HiLog::Debug(LABEL, "ExecNativeGetRadioTech status REJECT");
        asyncContext.status = REJECT;
    }
    HiLog::Debug(LABEL, "ExecNativeGetRadioTech End");
}

static void ExecGetRadioTechCallback(const napi_env env, const napi_status status, AsyncContext &asyncContext)
{
    HiLog::Debug(LABEL, "ExecGetRadioTechCallback start");
    if (asyncContext.deferred) {
        if (asyncContext.status == RESOLVED) {
            HiLog::Debug(LABEL, "ExecGetRadioTechCallback deferred RESOLVED");
            int32_t psRadioTech = 0;
            napi_get_value_int32(env, asyncContext.value[0], &psRadioTech);
            int32_t csRadioTech = 0;
            napi_get_value_int32(env, asyncContext.value[1], &csRadioTech);
            napi_value promiseValue = nullptr;
            napi_create_object(env, &promiseValue);
            SetPropertyInt32(env, promiseValue, "psRadioTech", psRadioTech);
            SetPropertyInt32(env, promiseValue, "csRadioTech", csRadioTech);
            napi_resolve_deferred(env, asyncContext.deferred, promiseValue);
            HiLog::Debug(LABEL, "ExecGetRadioTechCallback deferred RESOLVED END");
        } else {
            napi_value undefined = CreateUndefined(env);
            napi_reject_deferred(env, asyncContext.deferred, undefined);
        }
    } else {
        HiLog::Debug(LABEL, "ExecGetRadioTechCallback no deferred start");
        napi_value callbackValue[2] = {0};
        if (asyncContext.status == RESOLVED) {
            HiLog::Debug(LABEL, "ExecGetRadioTechCallback no deferred RESOLVED");
            callbackValue[0] = CreateUndefined(env);
            int32_t psRadioTech;
            napi_get_value_int32(env, asyncContext.value[0], &psRadioTech);
            int32_t csRadioTech;
            napi_get_value_int32(env, asyncContext.value[1], &csRadioTech);
            napi_value promiseValue = nullptr;
            napi_create_object(env, &promiseValue);
            SetPropertyInt32(env, promiseValue, "psRadioTech", psRadioTech);
            SetPropertyInt32(env, promiseValue, "csRadioTech", csRadioTech);
            callbackValue[1] = promiseValue;
        } else {
            callbackValue[0] = CreateErrorMessage(env, "get sim state failed");
            callbackValue[1] = CreateUndefined(env);
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext.callbackRef, &callback);
	napi_value resultValue = nullptr;
        napi_call_function(env, nullptr, callback, 2, callbackValue, &resultValue);
        HiLog::Debug(LABEL, "ExecGetRadioTechCallback no deferred end");
    }
    napi_delete_reference(env, asyncContext.callbackRef);
    delete &asyncContext;
}

static napi_value GetRadioTech(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    auto asyncContext = new AsyncContext();
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
    napi_create_string_utf8(env, "GetRadioTech", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecNativeGetRadioTech(env, *asyncContext);
        },
        [](napi_env env, napi_status status, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecGetRadioTechCallback(env, status, *asyncContext);
        },
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

static napi_value SetPropertyStringUtf8(napi_env env, napi_value object, std::string name, std::string value)
{
    napi_value propertyName = nullptr;
    napi_value peopertyValue = nullptr;
    char *nameChars = GetChars(name);
    char *valueChars = GetChars(value);
    NAPI_CALL(env, napi_create_string_utf8(env, nameChars, std::strlen(nameChars), &propertyName));
    NAPI_CALL(env, napi_create_string_utf8(env, valueChars, std::strlen(valueChars), &peopertyValue));
    NAPI_CALL(env, napi_set_property(env, object, propertyName, peopertyValue));
    return object;
}

static int32_t WrapNetworkType(SignalInformation::NetworkType type)
{
    switch (type) {
        case SignalInformation::NetworkType::GSM:
            return TelephonyNapi::NETWORK_TYPE_GSM;
        case SignalInformation::NetworkType::CDMA:
            return TelephonyNapi::NETWORK_TYPE_CDMA;
        case SignalInformation::NetworkType::LTE:
            return TelephonyNapi::NETWORK_TYPE_LTE;
        case SignalInformation::NetworkType::TDSCDMA:
            return TelephonyNapi::NETWORK_TYPE_TDSCDMA;
        default:
            return TelephonyNapi::NETWORK_TYPE_UNKNOWN;
    }
}

static bool InitAsyncContext(
    const napi_env env, const size_t parameterCount, const napi_value parameters[], AsyncContext &asyncContext)
{
    HiLog::Error(LABEL, "InitAsyncContext parameterCount=%{public}zu", parameterCount);
    if (parameterCount == TelephonyNapi::NONE_PARAMTER) {
        asyncContext.slotId = GetDefaultSlotId();
        return true;
    } else if (parameterCount == 1) {
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, parameters[0], &valuetype);
        if (valuetype == napi_number) {
            napi_get_value_int32(env, parameters[0], &(asyncContext.slotId));
            HiLog::Error(LABEL, "InitAsyncContext valuetype == napi_number asyncContext.slotId=%{public}d",
                asyncContext.slotId);
            return true;
        } else if (valuetype == napi_function) {
            asyncContext.slotId = GetDefaultSlotId();
            HiLog::Error(LABEL, "InitAsyncContext valuetype == napi_function asyncContext.slotId=%{public}d",
                asyncContext.slotId);
            napi_create_reference(env, parameters[0], 1, &(asyncContext.callbackRef));
            return true;
        }
    } else if (parameterCount == 2) {
        napi_valuetype valueType1 = napi_undefined;
        napi_valuetype valueType2 = napi_undefined;
        napi_typeof(env, parameters[0], &valueType1);
        napi_typeof(env, parameters[1], &valueType2);
        if (valueType1 == napi_number && valueType2 == napi_function) {
            napi_get_value_int32(env, parameters[0], &(asyncContext.slotId));
            napi_create_reference(env, parameters[1], 1, &(asyncContext.callbackRef));
            return true;
        }
    }
    return false;
}

static void ExecNativeGetSignalInfoList(const napi_env env, AsyncContext &asyncContext)
{
    if (InitRadioNetworkManager()) {
        HiLog::Error(LABEL, "ExecNativeGetSignalInfoList ");
        std::vector<sptr<SignalInformation>> signalInfoList =
            g_radioNetworkManager->GetSignalInfoList(asyncContext.slotId);
        asyncContext.status = RESOLVED;
        napi_create_array(env, &(asyncContext.value[0]));
        int i = 0;
        for (sptr<SignalInformation> inforItem : signalInfoList) {
            napi_value info = nullptr;
            napi_create_object(env, &info);
            SetPropertyInt32(env, info, "signalType", WrapNetworkType(inforItem->GetNetworkType()));
            SetPropertyInt32(env, info, "signalLevel", inforItem->GetSignalLevel());
            napi_set_element(env, asyncContext.value[0], i, info);
            ++i;
        }
    } else {
        HiLog::Error(LABEL, "ExecNativeGetSignalInfoList REJECT");
        asyncContext.status = REJECT;
    }
}

static void ExecGetSignalInfoListCallback(napi_env env, napi_status status, AsyncContext &asyncContext)
{
    HiLog::Error(LABEL, "ExecGetSignalInfoListCallback");
    if (asyncContext.deferred) {
        if (asyncContext.status == RESOLVED) {
            napi_resolve_deferred(env, asyncContext.deferred, asyncContext.value[0]);
        } else {
            napi_value undefined = CreateUndefined(env);
            napi_reject_deferred(env, asyncContext.deferred, undefined);
        }
        napi_delete_async_work(env, asyncContext.work);
    } else {
        napi_value callbackValue[2] = {0};
        if (asyncContext.status == RESOLVED) {
            callbackValue[0] = CreateUndefined(env);
            callbackValue[1] = asyncContext.value[0];
        } else {
            callbackValue[0] = CreateErrorMessage(env, "get signal info list failed");
            callbackValue[1] = CreateUndefined(env);
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext.callbackRef, &callback);
	napi_value resultValue = nullptr;
        napi_call_function(env, nullptr, callback, 2, callbackValue, &resultValue);
        napi_delete_reference(env, asyncContext.callbackRef);
    }
    delete &asyncContext;
}

static napi_value GetSignalInfoList(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    HiLog::Error(LABEL, "GetSignalInfoList ");

    auto asyncContext = new AsyncContext();
    if (!InitAsyncContext(env, argc, argv, *asyncContext)) {
        NAPI_ASSERT(env, false, "type mismatch");
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "GetSignalInfoList", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecNativeGetSignalInfoList(env, *asyncContext);
        },
        [](napi_env env, napi_status status, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecGetSignalInfoListCallback(env, status, *asyncContext);
        },
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

static void ExecNativeGetNetworkState(napi_env env, AsyncContext &asyncContext)
{
    HiLog::Debug(LABEL, "ExecNativeGetNetworkState start");
    sptr<NetworkState> networkState = nullptr;
    if (InitRadioNetworkManager()) {
        networkState = g_radioNetworkManager->GetNetworkStatus(GetDefaultSlotId());
        HiLog::Debug(LABEL, "ExecNativeGetNetworkState GetNetworkStatus end");
    }
    if (networkState != nullptr) {
        asyncContext.status = RESOLVED;
        napi_create_object(env, &asyncContext.value[0]);
        SetPropertyStringUtf8(env, asyncContext.value[0], "longOperatorName", networkState->GetLongOperatorName());
        SetPropertyStringUtf8(
            env, asyncContext.value[0], "shortOperatorName", networkState->GetShortOperatorName());
        SetPropertyStringUtf8(env, asyncContext.value[0], "plmnNumeric", networkState->GetPlmnNumeric());
        SetPropertyInt32(env, asyncContext.value[0], "isRoaming", networkState->IsRoaming() ? 1 : 0);
        SetPropertyInt32(env, asyncContext.value[0], "regStatus", networkState->GetRegStatus());
        SetPropertyInt32(env, asyncContext.value[0], "isEmergency", networkState->IsEmergency());
        HiLog::Debug(LABEL, "longOperatorName = %{public}s", networkState->GetLongOperatorName().c_str());
        HiLog::Debug(LABEL, "shortOperatorName = %{public}s", networkState->GetShortOperatorName().c_str());
        HiLog::Debug(LABEL, "plmnNumeric = %{public}s", networkState->GetPlmnNumeric().c_str());
        HiLog::Debug(LABEL, "isRoaming = %{public}d", networkState->IsRoaming());
        HiLog::Debug(LABEL, "regStatus = %{public}d", networkState->GetRegStatus());
        HiLog::Debug(LABEL, "isEmergency = %{public}d", networkState->IsEmergency());
    } else {
        asyncContext.status = REJECT;
    }
}

static void ExecGetNetworkStateCallback(napi_env env, napi_status status, AsyncContext &asyncContext)
{
    if (asyncContext.deferred) {
        if (asyncContext.status == RESOLVED) {
            napi_resolve_deferred(env, asyncContext.deferred, asyncContext.value[0]);
        } else {
            napi_value undefined = CreateUndefined(env);
            napi_reject_deferred(env, asyncContext.deferred, undefined);
        }
    } else {
        napi_value callbackValue[2] = {0};
        if (asyncContext.status == RESOLVED) {
            callbackValue[0] = CreateUndefined(env);
            callbackValue[1] = asyncContext.value[0];
        } else {
            callbackValue[0] = CreateErrorMessage(env, "get net work state failed");
            callbackValue[1] = CreateUndefined(env);
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, asyncContext.callbackRef, &callback);
	napi_value resultValue = nullptr;
        napi_call_function(env, nullptr, callback, 2, callbackValue, &resultValue);
    }
    napi_delete_reference(env, asyncContext.callbackRef);
    delete &asyncContext;
}

static napi_value GetNetworkStatus(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    NAPI_ASSERT(env, argc >= 1, "requires at least 1 parameter");
    auto asyncContext = new AsyncContext();
    if (!InitAsyncContext(env, argc, argv, *asyncContext)) {
        NAPI_ASSERT(env, false, "type mismatch");
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &asyncContext->deferred, &result);
    } else {
        napi_get_undefined(env, &result);
    }
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "GetNetworkStatus", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecNativeGetNetworkState(env, *asyncContext);
        },
        [](napi_env env, napi_status status, void *data) -> void {
            auto asyncContext = (AsyncContext *)data;
            ExecGetNetworkStateCallback(env, status, *asyncContext);
        },
        (void *)asyncContext, &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work);
    return result;
}

static napi_value createInt32Value(napi_env env, int32_t value)
{
    napi_value staticValue = nullptr;
    napi_create_int32(env, value, &staticValue);
    return staticValue;
}

EXTERN_C_START
napi_value InitNapiRadioNetwork(napi_env env, napi_value exports)
{
    napi_value radioTechnologyUnknown = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_UNKNOWN));
    napi_value radioTechnologyGsm = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_GSM));
    napi_value radioTechnology1Xrtt = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_GSM));
    napi_value radioTechnologyWcdma = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_1XRTT));
    napi_value radioTechnologyHspa = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_WCDMA));
    napi_value radioTechnologyhspap = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_HSPA));
    napi_value radioTechnologyTdscdma = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_HSPAP));
    napi_value radioTechnologyEvdo = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_TD_SCDMA));
    napi_value radioTechnologyEhrdp = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_EHRPD));
    napi_value radioTechnologyLte = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_LTE));
    napi_value radioTechnologyLteCa = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_LTE_CA));
    napi_value radioTechnologyIwlan = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_IWLAN));
    napi_value radioTechnologyNr = createInt32Value(env, static_cast<int32_t>(RADIO_TECHNOLOGY_NR));
    napi_value netWorkTypeUnknown = createInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_UNKNOWN));
    napi_value netWorkTypeGsm = createInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_GSM));
    napi_value netWorkTypeCdma = createInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_CDMA));
    napi_value netWorkTypeWcdma = createInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_WCDMA));
    napi_value netWorkTypeTdscdma = createInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_TDSCDMA));
    napi_value netWorkTypeLte = createInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_LTE));
    napi_value netWorkTypeNr = createInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_NR));
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getRadioTech", GetRadioTech),
        DECLARE_NAPI_FUNCTION("getSignalInformation", GetSignalInfoList),
        DECLARE_NAPI_FUNCTION("getNetworkState", GetNetworkStatus),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_UNKNOWN", radioTechnologyUnknown),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_GSM", radioTechnologyGsm),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_1XRTT", radioTechnology1Xrtt),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_WCDMA", radioTechnologyWcdma),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_HSPA", radioTechnologyHspa),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_HSPAP", radioTechnologyhspap),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_TD_SCDMA", radioTechnologyTdscdma),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_EVDO", radioTechnologyEvdo),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_EHRPD", radioTechnologyEhrdp),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_LTE", radioTechnologyLte),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_LTE_CA", radioTechnologyLteCa),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_IWLAN", radioTechnologyIwlan),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_NR", radioTechnologyNr),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_UNKNOWN", netWorkTypeUnknown),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_GSM", netWorkTypeGsm),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_CDMA", netWorkTypeCdma),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_WCDMA", netWorkTypeWcdma),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_TDSCDMA", netWorkTypeTdscdma),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_LTE", netWorkTypeLte),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_NR", netWorkTypeNr)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END

static napi_module _radioModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = InitNapiRadioNetwork,
    .nm_modname = "libtelephony_radio.z.so",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void RegisterRadioNetworkModule(void)
{
    napi_module_register(&_radioModule);
}
} // namespace TelephonyNapi
} // namespace OHOS
