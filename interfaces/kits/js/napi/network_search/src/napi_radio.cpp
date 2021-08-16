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
#include "radio_network_manager.h"
#include "get_network_search_mode_callback.h"
#include "set_network_search_mode_callback.h"
#include "get_radio_status_callback.h"
#include "set_radio_status_callback.h"
#include "get_network_search_info_callback.h"
#include "telephony_log_wrapper.h"
#include "core_manager.h"

namespace OHOS {
namespace Telephony {
static int32_t WrapRadioTech(int32_t radioTechType)
{
    switch (radioTechType) {
        case RADIO_TECHNOLOGY_GSM:
            return RADIO_TECH_GSM;
        case RADIO_TECHNOLOGY_LTE:
            return RADIO_TECH_LTE;
        case RADIO_TECHNOLOGY_WCDMA:
            return RADIO_TECH_WCDMA;
        default:
            return RADIO_TECH_UNKNOWN;
    }
}

static int32_t GetDefaultSlotId()
{
    return CoreManager::DEFAULT_SLOT_ID;
}

static void NativeGetRadioTech(napi_env env, void *data)
{
    auto asyncContext = static_cast<RadioTechContext *>(data);
    int32_t psRadioTech = DEFAULT_ERROR;
    int32_t csRadioTech = DEFAULT_ERROR;
    psRadioTech = RadioNetworkManager::GetPsRadioTech(asyncContext->slotId);
    csRadioTech = RadioNetworkManager::GetCsRadioTech(asyncContext->slotId);
    if (psRadioTech >= 0 || csRadioTech >= 0) {
        asyncContext->resolved = true;
        asyncContext->csTech = WrapRadioTech(csRadioTech);
        asyncContext->psTech = WrapRadioTech(psRadioTech);
    } else {
        asyncContext->resolved = false;
    }
}

static void GetRadioTechCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGD("GetRadioTechCallback start");
    auto asyncContext = (RadioTechContext *)data;
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "psRadioTech", asyncContext->psTech);
        NapiUtil::SetPropertyInt32(env, callbackValue, "csRadioTech", asyncContext->csTech);
        NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    } else {
        if (asyncContext->callbackRef != nullptr) {
            napi_value recv = NapiUtil::CreateUndefined(env);
            napi_value callbackFunc = nullptr;
            napi_get_reference_value(env, asyncContext->callbackRef, &callbackFunc);
            napi_value callbackValues[] = {nullptr, nullptr};
            callbackValues[0] = NapiUtil::CreateErrorMessage(env, "get radio tech failed");
            napi_create_object(env, &callbackValues[1]);
            napi_value psTechValue = NapiUtil::CreateUndefined(env);
            napi_value csTechValue = NapiUtil::CreateUndefined(env);
            napi_set_named_property(env, callbackValues[1], "psRadioTech", psTechValue);
            napi_set_named_property(env, callbackValues[1], "csRadioTech", csTechValue);
            napi_value result = nullptr;
            napi_call_function(env, recv, callbackFunc, std::size(callbackValues), callbackValues, &result);
            napi_delete_reference(env, asyncContext->callbackRef);
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
            asyncContext = nullptr;
        } else {
            callbackValue = NapiUtil::CreateErrorMessage(env, "get radio tech failed");
            NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
        }
    }
    TELEPHONY_LOGD("GetRadioTechCallback end");
}

static bool MatchGetRadioTechParameter(napi_env env, const napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 1: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number});
        }
        case 2: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number, napi_function});
        }
        default: {
            return false;
        }
    }
}

static napi_value GetRadioTech(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchGetRadioTechParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<RadioTechContext>().release();
    if (parameterCount == 1) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetRadioTech", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeGetRadioTech, GetRadioTechCallback,
            (void *)asyncContext, &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

static int32_t WrapNetworkType(const sptr<SignalInformation> signalInfo)
{
    if (signalInfo != nullptr) {
        auto type = signalInfo->GetNetworkType();
        switch (type) {
            case SignalInformation::NetworkType::GSM:
                return NETWORK_TYPE_GSM;
            case SignalInformation::NetworkType::CDMA:
                return NETWORK_TYPE_CDMA;
            case SignalInformation::NetworkType::LTE:
                return NETWORK_TYPE_LTE;
            case SignalInformation::NetworkType::TDSCDMA:
                return NETWORK_TYPE_TDSCDMA;
            default:
                return NETWORK_TYPE_UNKNOWN;
        }
    }
    return NETWORK_TYPE_UNKNOWN;
}

static void NativeGetSignalInfoList(napi_env env, void *data)
{
    auto asyncContext = static_cast<SignalInfoListContext *>(data);
    asyncContext->signalInfoList = RadioNetworkManager::GetSignalInfoList(asyncContext->slotId);
    TELEPHONY_LOGD("NativeGetSignalInfoList size = %{public}zu", asyncContext->signalInfoList.size());
    asyncContext->resolved = true;
}

static void GetSignalInfoListCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<SignalInfoListContext *>(data);
    TELEPHONY_LOGD("GetSignalInfoListCallback size = %{public}zu,resolved = %{public}d",
        asyncContext->signalInfoList.size(), asyncContext->resolved);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_array(env, &callbackValue);
        int i = 0;
        for (sptr<SignalInformation> infoItem : asyncContext->signalInfoList) {
            napi_value info = nullptr;
            napi_create_object(env, &info);
            int32_t signalType = WrapNetworkType(infoItem);
            NapiUtil::SetPropertyInt32(env, info, "signalType", signalType);
            int32_t signalLevel = 0;
            if (infoItem != nullptr) {
                signalLevel = infoItem->GetSignalLevel();
            }
            NapiUtil::SetPropertyInt32(env, info, "signalLevel", signalLevel);
            napi_set_element(env, callbackValue, i, info);
            i++;
            TELEPHONY_LOGD(
                "GetSignalInfoListCallback when resovled signalType  = %{public}d, signalLevel = %{public}d",
                signalType, signalLevel);
        }
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "get signal info list failed");
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
}

static bool MatchGetSignalInfoListParameter(napi_env env, napi_value parameter[], size_t parameterCount)
{
    switch (parameterCount) {
        case 1: {
            return NapiUtil::MatchParameters(env, parameter, {napi_number});
        }
        case 2: {
            return NapiUtil::MatchParameters(env, parameter, {napi_number, napi_function});
        }
        default: {
            return false;
        }
    }
}

static napi_value GetSignalInfoList(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchGetSignalInfoListParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SignalInfoListContext>().release();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &(asyncContext->slotId)));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext, "GetSignalInfoList", NativeGetSignalInfoList, GetSignalInfoListCallback);
}

static int32_t WrapRegStatus(int32_t state)
{
    switch (state) {
        case REG_STATE_IN_SERVICE: {
            return REGISTRATION_STATE_IN_SERVICE;
        }
        case REG_STATE_NO_SERVICE: {
            return REGISTRATION_STATE_NO_SERVICE;
        }
        case REG_STATE_EMERGENCY_ONLY: {
            return REGISTRATION_STATE_EMERGENCY_CALL_ONLY;
        }
        default: {
            return REGISTRATION_STATE_POWER_OFF;
        }
    }
}

static int32_t WrapRegState(int32_t nativeState)
{
    switch (nativeState) {
        case REG_STATE_NO_SERVICE:
        case REG_STATE_SEARCH: {
            return REGISTRATION_STATE_NO_SERVICE;
        }
        case REG_STATE_IN_SERVICE: {
            return REGISTRATION_STATE_IN_SERVICE;
        }
        case REG_STATE_EMERGENCY_ONLY: {
            return REGISTRATION_STATE_EMERGENCY_CALL_ONLY;
        }
        case REG_STATE_UNKNOWN: {
            return REGISTRATION_STATE_POWER_OFF;
        }
        default:
            return REGISTRATION_STATE_POWER_OFF;
    }
}

static void NativeGetNetworkState(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetStateContext *>(data);
    sptr<NetworkState> networkState = nullptr;
    networkState = RadioNetworkManager::GetNetworkState(asyncContext->slotId);
    if (networkState != nullptr) {
        asyncContext->resolved = true;
        asyncContext->regStatus = WrapRegState(networkState->GetRegStatus());
        asyncContext->longOperatorName = networkState->GetLongOperatorName();
        asyncContext->shortOperatorName = networkState->GetShortOperatorName();
        asyncContext->plmnNumeric = networkState->GetPlmnNumeric();
        asyncContext->isRoaming = networkState->IsRoaming();
        asyncContext->isEmergency = networkState->IsEmergency();
    } else {
        asyncContext->resolved = false;
    }
}

static void GetNetworkStateCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<GetStateContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyStringUtf8(env, callbackValue, "longOperatorName", asyncContext->longOperatorName);
        NapiUtil::SetPropertyStringUtf8(env, callbackValue, "shortOperatorName", asyncContext->shortOperatorName);
        NapiUtil::SetPropertyStringUtf8(env, callbackValue, "plmnNumeric", asyncContext->plmnNumeric);
        NapiUtil::SetPropertyBoolean(env, callbackValue, "isRoaming", asyncContext->isRoaming);
        NapiUtil::SetPropertyInt32(env, callbackValue, "regStatus", WrapRegStatus(asyncContext->regStatus));
        NapiUtil::SetPropertyInt32(env, callbackValue, "nsaState", asyncContext->nsaState);
        NapiUtil::SetPropertyBoolean(env, callbackValue, "isCaActive", asyncContext->isCaActive);
        NapiUtil::SetPropertyBoolean(env, callbackValue, "isEmergency", asyncContext->isEmergency);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "get network state null");
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
}

static bool MatchGetNetworkStateParameter(napi_env env, napi_value parameter[], size_t parameterCount)
{
    switch (parameterCount) {
        case 0: {
            return true;
        }
        case 1: {
            return NapiUtil::MatchParameters(env, parameter, {napi_number}) ||
                NapiUtil::MatchParameters(env, parameter, {napi_function});
        }
        case 2: {
            return NapiUtil::MatchParameters(env, parameter, {napi_number, napi_function});
        }
        default: {
            return false;
        }
    }
}

static napi_value GetNetworkState(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchGetNetworkStateParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetStateContext>().release();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], 1, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext, "GetNetworkState", NativeGetNetworkState, GetNetworkStateCallback);
}

static void NativeGetNetworkSelectionMode(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetSelectModeContext *>(data);
    bool getResult = false;
    std::unique_ptr<GetNetworkSearchModeCallback> callback =
        std::make_unique<GetNetworkSearchModeCallback>(env, asyncContext->thisVarRef, asyncContext);
    getResult = RadioNetworkManager::GetNetworkSelectionMode(asyncContext->slotId, callback.release());
    asyncContext->resolved = getResult;
}

static void GetNetworkSelectionModeCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = (GetSelectModeContext *)data;
    if (!asyncContext->resolved) {
        if (asyncContext->deferred != nullptr) {
            napi_value errorMessage = NapiUtil::CreateErrorMessage(env, "get network selection mode error. ");
            napi_reject_deferred(env, asyncContext->deferred, errorMessage);
        } else {
            napi_value callbackValues[2] = {0};
            callbackValues[0] = NapiUtil::CreateErrorMessage(env, "get network selection mode error. ");
            callbackValues[1] = NapiUtil::CreateUndefined(env);
            napi_value callback = nullptr;
            napi_value result = nullptr;
            napi_value undefind = nullptr;
            napi_get_undefined(env, &undefind);
            napi_get_reference_value(env, asyncContext->callbackRef, &callback);
            napi_call_function(env, undefind, callback, std::size(callbackValues), callbackValues, &result);
            napi_delete_reference(env, asyncContext->callbackRef);
        }
        napi_delete_async_work(env, asyncContext->work);
        delete asyncContext;
    }
    TELEPHONY_LOGD("GetNetworkSelectionModeCallback end");
}

static napi_value GetNetworkSelectionMode(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchGetRadioTechParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetSelectModeContext>().release();
    NAPI_CALL(env, napi_create_reference(env, thisVar, 1, &asyncContext->thisVarRef));
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetNetworkSelectionMode", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeGetNetworkSelectionMode,
            GetNetworkSelectionModeCallback, (void *)asyncContext, &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

static void NativeGetNetworkSearchInformation(napi_env env, void *data)
{
    auto context = static_cast<GetSearchInfoContext *>(data);
    std::unique_ptr<GetNetworkSearchInfoCallback> callback =
        std::make_unique<GetNetworkSearchInfoCallback>(env, context->thisVarRef, context);
    context->isSendRequest = RadioNetworkManager::GetNetworkSearchResult(context->slotId, callback.release());
    context->resolved = context->isSendRequest;
}

static void GetNetworkSearchInformationCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<GetSearchInfoContext *>(data);
    if (!asyncContext->resolved) {
        if (asyncContext->deferred != nullptr) {
            napi_value errorMessage = NapiUtil::CreateErrorMessage(env, "get network search info error.");
            napi_reject_deferred(env, asyncContext->deferred, errorMessage);
        } else {
            napi_value callbackValues[2] = {0};
            callbackValues[0] = NapiUtil::CreateErrorMessage(env, "get network search info error.");
            callbackValues[1] = NapiUtil::CreateUndefined(env);
            napi_value callback = nullptr;
            napi_value result = nullptr;
            napi_value undefind = nullptr;
            napi_get_undefined(env, &undefind);
            napi_get_reference_value(env, asyncContext->callbackRef, &callback);
            napi_call_function(env, undefind, callback, std::size(callbackValues), callbackValues, &result);
            napi_delete_reference(env, asyncContext->callbackRef);
        }
        napi_delete_async_work(env, asyncContext->work);
        delete asyncContext;
    }
    TELEPHONY_LOGD("GetNetworkSelectionModeCallback end");
}

static bool MatchGetNetworkSearchInformation(napi_env env, const napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 1: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number});
        }
        case 2: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number, napi_function});
        }
        default: {
            return false;
        }
    }
}

static napi_value GetNetworkSearchInformation(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchGetNetworkSearchInformation(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetSearchInfoContext>().release();
    NAPI_CALL(env, napi_create_reference(env, thisVar, 1, &asyncContext->thisVarRef));
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext, "GetNetworkSearchInformation",
        NativeGetNetworkSearchInformation, GetNetworkSearchInformationCallback);
}

static bool HasNamedPropertyType(
    napi_env env, napi_value object, napi_valuetype type, const std::string &propertyName)
{
    bool hasProperty = false;
    napi_has_named_property(env, object, propertyName.c_str(), &hasProperty);
    if (hasProperty) {
        napi_value value = nullptr;
        napi_get_named_property(env, object, propertyName.c_str(), &value);
        return NapiUtil::MatchValueType(env, value, type);
    }
    return false;
}

static std::string GetStringProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    napi_value value = nullptr;
    napi_status getNameStatus = napi_get_named_property(env, object, propertyName.c_str(), &value);
    if (getNameStatus == napi_ok) {
        char chars[BUF_SIZE] = {0};
        size_t charLength = 0;
        napi_status getStringStatus = napi_get_value_string_utf8(env, value, chars, BUF_SIZE, &charLength);
        if (getStringStatus == napi_ok && charLength > 0) {
            return std::string(chars, charLength);
        }
    }
    return "";
}

static napi_value GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    napi_value value = nullptr;
    napi_get_named_property(env, object, propertyName.c_str(), &value);
    return value;
}

static bool MatchSetNetworkSelectionModeParameters(napi_env env, napi_value parameters[], size_t parameterCount)
{
    int32_t count = parameterCount;
    TELEPHONY_LOGD("start MatchSetNetworkSelectionModeParameters parameterCount = %{public}d", count);
    switch (parameterCount) {
        case 1: {
            if (!NapiUtil::MatchParameters(env, parameters, {napi_object})) {
                return false;
            }
            break;
        }
        case 2: {
            if (!NapiUtil::MatchParameters(env, parameters, {napi_object, napi_function})) {
                TELEPHONY_LOGD("start MatchSetNetworkSelectionModeParameters not match two parameter");
                return false;
            }
            break;
        }
        default:
            return false;
    }
    bool hasSlotId = HasNamedPropertyType(env, parameters[0], napi_number, "slotId");
    bool hasSelectMode = HasNamedPropertyType(env, parameters[0], napi_number, "selectMode");
    bool hasNetworkInformation = HasNamedPropertyType(env, parameters[0], napi_object, "networkInformation");
    bool hasResumeSelection = HasNamedPropertyType(env, parameters[0], napi_boolean, "resumeSelection");
    if (hasSlotId && hasSelectMode && hasNetworkInformation && hasResumeSelection) {
        napi_value networkInfoValue = GetNamedProperty(env, parameters[0], "networkInformation");
        if (networkInfoValue != nullptr) {
            bool hasOperatorName = HasNamedPropertyType(env, networkInfoValue, napi_string, "operatorName");
            bool hasOperatorNumeric = HasNamedPropertyType(env, networkInfoValue, napi_string, "operatorNumeric");
            bool hasState = HasNamedPropertyType(env, networkInfoValue, napi_number, "state");
            bool hasRadioTech = HasNamedPropertyType(env, networkInfoValue, napi_string, "radioTech");
            return hasOperatorName && hasOperatorNumeric && hasState && hasRadioTech;
        }
    }
    return false;
}

static int32_t WrapJsSelectMode(int32_t jsSelectMode)
{
    switch (jsSelectMode) {
        case NETWORK_SELECTION_AUTOMATIC:
            return NATIVE_NETWORK_SELECTION_AUTOMATIC;
        case NETWORK_SELECTION_MANUAL:
            return NATIVE_NETWORK_SELECTION_MANUAL;
        default:
            return DEFAULT_ERROR;
    }
}

const static std::string GSM = "GSM";
const static std::string GPRS = "GPRS";
const static std::string WCDMA = "WCDMA";
const static std::string LTE = "LTE";
static int32_t GetRatTechValue(std::string ratTechStr)
{
    if (GSM.compare(ratTechStr) == 0 || GPRS.compare(ratTechStr)) {
        return NETWORK_GSM_OR_GPRS;
    }
    if (WCDMA.compare(ratTechStr) == 0) {
        return NETWORK_WCDMA;
    }
    if (LTE.compare(ratTechStr) == 0) {
        return NETWORK_LTE;
    }
    return NETWORK_LTE;
}

static int32_t WrapPlmnState(int32_t jsState)
{
    switch (jsState) {
        case NETWORK_AVAILABLE: {
            return NETWORK_PLMN_STATE_AVAILABLE;
        }
        case NETWORK_CURRENT: {
            return NETWORK_PLMN_STATE_REGISTERED;
        }
        case NETWORK_FORBIDDEN: {
            return NETWORK_PLMN_STATE_FORBIDDEN;
        }
        default: {
            return NETWORK_PLMN_STATE_UNKNOWN;
        }
    }
}

static void NativeSetNetworkSelectionMode(napi_env env, void *data)
{
    auto asyncContext = static_cast<SetSelectModeContext *>(data);
    TELEPHONY_LOGD("NativeSetNetworkSelectionMode selectMode = %{public}d", asyncContext->selectMode);
    sptr<NetworkInformation> networkInfo = std::make_unique<NetworkInformation>().release();
    networkInfo->SetOperateInformation(asyncContext->operatorName, "", asyncContext->operatorNumeric,
        WrapPlmnState(asyncContext->state), GetRatTechValue(asyncContext->radioTech));
    TELEPHONY_LOGD("NativeSetNetworkSelectionMode operatorName = %{public}s", asyncContext->operatorName.c_str());
    std::unique_ptr<SetNetworkSearchModeCallback> callback =
        std::make_unique<SetNetworkSearchModeCallback>(env, asyncContext->thisVarRef, asyncContext);
    bool setResult = RadioNetworkManager::SetNetworkSelectionMode(asyncContext->slotId, asyncContext->selectMode,
        networkInfo, asyncContext->resumeSelection, callback.release());
    asyncContext->resolved = setResult;
    TELEPHONY_LOGD("NativeSetNetworkSelectionMode setResult = %{public}d", setResult);
}

static void SetNetworkSelectionModeCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGD("SetNetworkSelectionModeCallback start");
    auto asyncContext = static_cast<SetSelectModeContext *>(data);
    if (!asyncContext->resolved) {
        if (asyncContext->deferred != nullptr) {
            napi_value errorMessage = NapiUtil::CreateErrorMessage(env, "set network selection mode error. ");
            napi_reject_deferred(env, asyncContext->deferred, errorMessage);
        } else if (asyncContext->callbackRef != nullptr) {
            napi_value callbackValues[2] = {0};
            callbackValues[0] = asyncContext->resolved ?
                NapiUtil::CreateUndefined(env) :
                NapiUtil::CreateErrorMessage(env, "SetPreferredNetworkMode err");
            callbackValues[1] = NapiUtil::CreateUndefined(env);
            napi_value callback = nullptr;
            napi_value result = nullptr;
            napi_value undefind = nullptr;
            napi_get_undefined(env, &undefind);
            napi_get_reference_value(env, asyncContext->callbackRef, &callback);
            napi_call_function(env, undefind, callback, std::size(callbackValues), callbackValues, &result);
            napi_delete_reference(env, asyncContext->callbackRef);
            TELEPHONY_LOGD("SetNetworkSelectionModeCallback callback end");
        }
        napi_delete_async_work(env, asyncContext->work);
        delete asyncContext;
    }
    TELEPHONY_LOGD("SetNetworkSelectionModeCallback end");
}

static void ParseNetworkSelectionParameter(napi_env env, napi_value object, SetSelectModeContext &context)
{
    napi_value slotIdValue = GetNamedProperty(env, object, "slotId");
    if (slotIdValue != nullptr) {
        napi_get_value_int32(env, slotIdValue, &context.slotId);
    }
    int32_t jsSelectMode = static_cast<int32_t>(NETWORK_SELECTION_UNKNOWN);
    napi_value selecModeValue = GetNamedProperty(env, object, "selectMode");
    if (selecModeValue != nullptr) {
        napi_get_value_int32(env, selecModeValue, &jsSelectMode);
    }
    TELEPHONY_LOGD("ParseNetworkSelectionParameter jsSelectMode = %{public}d", jsSelectMode);
    context.selectMode = WrapJsSelectMode(jsSelectMode);
    napi_value resumeValue = GetNamedProperty(env, object, "resumeSelection");
    if (resumeValue != nullptr) {
        napi_get_value_bool(env, resumeValue, &context.resumeSelection);
    }
    napi_value networkInfoValue = GetNamedProperty(env, object, "networkInformation");
    if (networkInfoValue != nullptr) {
        context.operatorName = GetStringProperty(env, networkInfoValue, "operatorName");
        context.operatorNumeric = GetStringProperty(env, networkInfoValue, "operatorNumeric");
        napi_value stateValue = GetNamedProperty(env, networkInfoValue, "state");
        if (stateValue != nullptr) {
            napi_get_value_int32(env, stateValue, &context.state);
        }
        context.radioTech = GetStringProperty(env, networkInfoValue, "radioTech");
    }
    TELEPHONY_LOGD("ParseNetworkSelectionParameter end");
}

static napi_value SetNetworkSelectionMode(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchSetNetworkSelectionModeParameters(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SetSelectModeContext>().release();
    napi_create_reference(env, thisVar, 1, &asyncContext->thisVarRef);
    ParseNetworkSelectionParameter(env, parameters[0], *asyncContext);
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext, "SetNetworkSelectionMode", NativeSetNetworkSelectionMode,
        SetNetworkSelectionModeCallback);
}

static void NativeGetCountryCode(napi_env env, void *data)
{
    auto context = static_cast<GetISOCountryCodeContext *>(data);
    context->countryCode = NapiUtil::ToUtf8(RadioNetworkManager::GetIsoCountryCodeForNetwork(context->slotId));
    TELEPHONY_LOGD("NativeGetCountryCode countryCode = %{public}s", context->countryCode.c_str());
    if (context->countryCode.empty()) {
        context->resolved = false;
    } else {
        context->resolved = true;
    }
}

static void GetCountryCodeCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetISOCountryCodeContext *>(data);
    napi_value callbackValue = nullptr;
    if (status == napi_ok) {
        if (context->resolved) {
            napi_create_string_utf8(env, context->countryCode.c_str(), context->countryCode.size(), &callbackValue);
        } else {
            callbackValue = NapiUtil::CreateErrorMessage(env, "get iso country code error");
        }
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(
            env, "get iso country code error,napi_status = " + std ::to_string(status));
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static bool MatchGetISOCountryCodeForNetworkParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 1: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number});
        }
        case 2: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number, napi_function});
        }
        default:
            return false;
    }
}

static napi_value GetISOCountryCodeForNetwork(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchGetISOCountryCodeForNetworkParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetISOCountryCodeContext>().release();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext, "GetISOCountryCodeForNetwork", NativeGetCountryCode, GetCountryCodeCallback);
}

static bool MatchIsRadioOnParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 1: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number});
        }
        case 2: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number, napi_function});
        }
        default:
            return false;
    }
}
static void NativeIsRadioOn(napi_env env, void *data)
{
    auto asyncContext = static_cast<IsRadioOnContext *>(data);
    bool getResult = false;
    std::unique_ptr<GetRadioStatusCallback> callback =
        std::make_unique<GetRadioStatusCallback>(env, asyncContext->thisVarRef, asyncContext);
    getResult = RadioNetworkManager::GetRadioState(asyncContext->slotId, callback.release());
    TELEPHONY_LOGD("NativeIsRadioOn getResult = %{public}d", getResult);
    asyncContext->resolved = getResult;
}

static void IsRadioOnCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGD("IsRadioOnCallback start");
    auto asyncContext = static_cast<IsRadioOnContext *>(data);
    if (!asyncContext->resolved) {
        if (asyncContext->deferred != nullptr) {
            napi_value errorMessage = NapiUtil::CreateErrorMessage(env, "get radio status failed.");
            napi_reject_deferred(env, asyncContext->deferred, errorMessage);
            TELEPHONY_LOGD("IsRadioOnCallback promise reject end");
        } else if (asyncContext->callbackRef != nullptr) {
            napi_value undefind = NapiUtil::CreateUndefined(env);
            napi_value callback = nullptr;
            napi_get_reference_value(env, asyncContext->callbackRef, &callback);
            napi_value callbackValues[] = {
                NapiUtil::CreateErrorMessage(env, "get radio status failed."), NapiUtil::CreateUndefined(env)};
            napi_value result = nullptr;
            napi_call_function(env, undefind, callback, std::size(callbackValues), callbackValues, &result);
            napi_delete_reference(env, asyncContext->callbackRef);
            TELEPHONY_LOGD("IsRadioOnCallback callback reject end");
        }
        napi_delete_async_work(env, asyncContext->work);
        delete asyncContext;
    }
    TELEPHONY_LOGD("IsRadioOnCallback end");
}

static napi_value IsRadioOn(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchIsRadioOnParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<IsRadioOnContext>().release();
    NAPI_CALL(env, napi_create_reference(env, thisVar, 1, &asyncContext->thisVarRef));
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext, "IsRadioOn", NativeIsRadioOn, IsRadioOnCallback);
}

static void NativeTurnOnRadio(napi_env env, void *data)
{
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    bool setResult = false;
    std::unique_ptr<SetRadioStatusCallback> callback =
        std::make_unique<SetRadioStatusCallback>(env, asyncContext->thisVarRef, asyncContext);
    setResult = RadioNetworkManager::SetRadioState(asyncContext->slotId, true, callback.release());
    asyncContext->resolved = setResult;
}

static void TurnOnRadioCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGD("TurnOnRadioCallback start");
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    if (!asyncContext->resolved) {
        if (asyncContext->deferred != nullptr) {
            napi_value errorMessage = NapiUtil::CreateErrorMessage(env, "set radio status failed.");
            napi_reject_deferred(env, asyncContext->deferred, errorMessage);
            TELEPHONY_LOGD("TurnOnRadioCallback promise reject end");
        } else if (asyncContext->callbackRef != nullptr) {
            napi_value undefind = NapiUtil::CreateUndefined(env);
            napi_value callback = nullptr;
            napi_get_reference_value(env, asyncContext->callbackRef, &callback);
            napi_value callbackValues[] = {NapiUtil::CreateErrorMessage(env, "set radio status failed.")};
            napi_value result = nullptr;
            napi_call_function(env, undefind, callback, std::size(callbackValues), callbackValues, &result);
            napi_delete_reference(env, asyncContext->callbackRef);
            TELEPHONY_LOGD("TurnOnRadioCallback callback reject end");
        }
        napi_delete_async_work(env, asyncContext->work);
        delete asyncContext;
    }
    TELEPHONY_LOGD("TurnOnRadioCallback end");
}

static bool MatchSwitchRadioParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 1: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number});
        }
        case 2: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number, napi_function});
        }
        default:
            return false;
    }
}

static napi_value TurnOnRadio(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchSwitchRadioParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SwitchRadioContext>().release();
    NAPI_CALL(env, napi_create_reference(env, thisVar, 1, &asyncContext->thisVarRef));
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext, "TurnOnRadio", NativeTurnOnRadio, TurnOnRadioCallback);
}

static void NativeTurnOffRadio(napi_env env, void *data)
{
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    bool setResult = false;
    std::unique_ptr<SetRadioStatusCallback> callback =
        std::make_unique<SetRadioStatusCallback>(env, asyncContext->thisVarRef, asyncContext);
    setResult = RadioNetworkManager::SetRadioState(asyncContext->slotId, false, callback.release());
    asyncContext->resolved = setResult;
}

static void TurnOffRadioCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGD("TurnOffRadioCallback start");
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    if (!asyncContext->resolved) {
        if (asyncContext->deferred != nullptr) {
            napi_value errorMessage = NapiUtil::CreateErrorMessage(env, "set radio status failed.");
            napi_reject_deferred(env, asyncContext->deferred, errorMessage);
            TELEPHONY_LOGD("TurnOffRadioCallback promise reject end");
        } else if (asyncContext->callbackRef != nullptr) {
            napi_value undefind = NapiUtil::CreateUndefined(env);
            napi_value callback = nullptr;
            napi_get_reference_value(env, asyncContext->callbackRef, &callback);
            napi_value callbackValues[] = {NapiUtil::CreateErrorMessage(env, "set radio status failed.")};
            napi_value result = nullptr;
            napi_call_function(env, undefind, callback, std::size(callbackValues), callbackValues, &result);
            napi_delete_reference(env, asyncContext->callbackRef);
            TELEPHONY_LOGD("TurnOffRadioCallback callback reject end");
        }
        napi_delete_async_work(env, asyncContext->work);
        delete asyncContext;
    }
    TELEPHONY_LOGD("TurnOffRadioCallback end");
}

static napi_value TurnOffRadio(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchSwitchRadioParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SwitchRadioContext>().release();
    NAPI_CALL(env, napi_create_reference(env, thisVar, 1, &asyncContext->thisVarRef));
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext, "TurnOffRadio", NativeTurnOffRadio, TurnOffRadioCallback);
}

static napi_value InitEnumRadioType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_UNKNOWN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_GSM", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_1XRTT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_1XRTT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_WCDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_HSPA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_HSPA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_HSPAP", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_HSPAP))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_TD_SCDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_TD_SCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_EVDO", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_EVDO))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_EHRPD", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_EHRPD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_LTE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_LTE_CA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_LTE_CA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_IWLAN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_IWLAN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_NR", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RADIO_TECH_NR))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumNetworkType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_UNKNOWN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_GSM", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_CDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_WCDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_TDSCDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_LTE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_NR", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_TYPE_NR))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumRegStatus(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("REGISTRATION_STATE_NO_SERVICE",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_NO_SERVICE))),
        DECLARE_NAPI_STATIC_PROPERTY("REGISTRATION_STATE_IN_SERVICE",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_IN_SERVICE))),
        DECLARE_NAPI_STATIC_PROPERTY("REGISTRATION_STATE_EMERGENCY_CALL_ONLY",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_EMERGENCY_CALL_ONLY))),
        DECLARE_NAPI_STATIC_PROPERTY("REGISTRATION_STATE_POWER_OFF",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_POWER_OFF))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumNsaState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "NSA_STATE_NOT_SUPPORT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NSA_STATE_NOT_SUPPORT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NSA_STATE_NO_DETECT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NSA_STATE_NO_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_CONNECTED_DETECT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NSA_STATE_CONNECTED_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NSA_STATE_IDLE_DETECT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NSA_STATE_IDLE_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_DUAL_CONNECTED",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NSA_STATE_DUAL_CONNECTED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NSA_STATE_SA_ATTACHED", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NSA_STATE_SA_ATTACHED))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumNetworkSelectionMode(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_SELECTION_UNKNOWN",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_SELECTION_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_SELECTION_AUTOMATIC",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_SELECTION_AUTOMATIC))),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_SELECTION_MANUAL",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_SELECTION_MANUAL))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumNetworkInformationState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_UNKNOWN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_AVAILABLE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_AVAILABLE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_CURRENT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_CURRENT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_FORBIDDEN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_FORBIDDEN))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

EXTERN_C_START
napi_value InitNapiRadioNetwork(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getRadioTech", GetRadioTech),
        DECLARE_NAPI_FUNCTION("getSignalInformation", GetSignalInfoList),
        DECLARE_NAPI_FUNCTION("getNetworkState", GetNetworkState),
        DECLARE_NAPI_FUNCTION("setNetworkSelectionMode", SetNetworkSelectionMode),
        DECLARE_NAPI_FUNCTION("getNetworkSelectionMode", GetNetworkSelectionMode),
        DECLARE_NAPI_FUNCTION("getNetworkSearchInformation", GetNetworkSearchInformation),
        DECLARE_NAPI_FUNCTION("getISOCountryCodeForNetwork", GetISOCountryCodeForNetwork),
        DECLARE_NAPI_FUNCTION("isRadioOn", IsRadioOn),
        DECLARE_NAPI_FUNCTION("turnOnRadio", TurnOnRadio),
        DECLARE_NAPI_FUNCTION("turnOffRadio", TurnOffRadio),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    InitEnumRadioType(env, exports);
    InitEnumNetworkType(env, exports);
    InitEnumRegStatus(env, exports);
    InitEnumNsaState(env, exports);
    InitEnumNetworkSelectionMode(env, exports);
    InitEnumNetworkInformationState(env, exports);
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
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterRadioNetworkModule(void)
{
    napi_module_register(&_radioModule);
}
} // namespace Telephony
} // namespace OHOS