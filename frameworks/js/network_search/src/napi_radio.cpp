/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include <chrono>
#include <cstring>
#include <memory>
#include <unistd.h>

#include "core_service_client.h"
#include "get_network_search_info_callback.h"
#include "get_network_search_mode_callback.h"
#include "get_preferred_network_callback.h"
#include "get_radio_state_callback.h"
#include "napi_ims_reg_info_callback_manager.h"
#include "set_network_search_mode_callback.h"
#include "set_preferred_network_callback.h"
#include "set_radio_state_callback.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t DEFAULT_REF_COUNT = 1;
constexpr int16_t PARAMETER_COUNT_ZERO = 0;
constexpr int16_t PARAMETER_COUNT_ONE = 1;
constexpr int16_t PARAMETER_COUNT_TWO = 2;
constexpr int16_t PARAMETER_COUNT_THREE = 3;
constexpr int16_t PARAMETER_COUNT_FOUR = 4;
constexpr int32_t INVALID_VALUE = -1;

static constexpr const char *GET_TELEPHONY_STATE = "ohos.permission.GET_TELEPHONY_STATE";
static constexpr const char *SET_TELEPHONY_STATE = "ohos.permission.SET_TELEPHONY_STATE";
static constexpr const char *LOCATION = "ohos.permission.LOCATION";
static constexpr const char *GET_NETWORK_INFO = "ohos.permission.GET_NETWORK_INFO";

static int32_t WrapRadioTech(int32_t radioTechType)
{
    RadioTech techType = static_cast<RadioTech>(radioTechType);
    switch (techType) {
        case RadioTech::RADIO_TECHNOLOGY_GSM:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_GSM);
        case RadioTech::RADIO_TECHNOLOGY_LTE:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_LTE);
        case RadioTech::RADIO_TECHNOLOGY_WCDMA:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_WCDMA);
        case RadioTech::RADIO_TECHNOLOGY_1XRTT:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_1XRTT);
        case RadioTech::RADIO_TECHNOLOGY_HSPA:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_HSPA);
        case RadioTech::RADIO_TECHNOLOGY_HSPAP:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_HSPAP);
        case RadioTech::RADIO_TECHNOLOGY_TD_SCDMA:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_TD_SCDMA);
        case RadioTech::RADIO_TECHNOLOGY_EVDO:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_EVDO);
        case RadioTech::RADIO_TECHNOLOGY_EHRPD:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_EHRPD);
        case RadioTech::RADIO_TECHNOLOGY_LTE_CA:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_LTE_CA);
        case RadioTech::RADIO_TECHNOLOGY_IWLAN:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_IWLAN);
        case RadioTech::RADIO_TECHNOLOGY_NR:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_NR);
        default:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_UNKNOWN);
    }
}

static int32_t WrapSignalInformationType(SignalInformation::NetworkType type)
{
    switch (type) {
        case SignalInformation::NetworkType::GSM:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_GSM);
        case SignalInformation::NetworkType::CDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_CDMA);
        case SignalInformation::NetworkType::LTE:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_LTE);
        case SignalInformation::NetworkType::WCDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_WCDMA);
        case SignalInformation::NetworkType::TDSCDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_TDSCDMA);
        case SignalInformation::NetworkType::NR:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_NR);
        default:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
    }
}

static int32_t GetDefaultSlotId()
{
    return DEFAULT_SIM_SLOT_ID;
}

static inline bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
}

static void NativeGetRadioTech(napi_env env, void *data)
{
    auto asyncContext = static_cast<RadioTechContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetRadioTech slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t psRadioTech = static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_INVALID);
    int32_t csRadioTech = static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_INVALID);
    int32_t psResult =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPsRadioTech(asyncContext->slotId, psRadioTech);
    int32_t csResult =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCsRadioTech(asyncContext->slotId, csRadioTech);
    if (psResult == TELEPHONY_SUCCESS && csResult == TELEPHONY_SUCCESS) {
        asyncContext->resolved = true;
        asyncContext->csTech = WrapRadioTech(csRadioTech);
        asyncContext->psTech = WrapRadioTech(psRadioTech);
    }
    asyncContext->errorCode = csResult;
}

static void GetRadioTechCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<RadioTechContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "psRadioTech", asyncContext->psTech);
        NapiUtil::SetPropertyInt32(env, callbackValue, "csRadioTech", asyncContext->csTech);
    } else {
        JsError error =
            NapiUtil::ConverErrorMessageWithPermissionForJs(asyncContext->errorCode, "getRadioTech", GET_NETWORK_INFO);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("GetRadioTechCallback end");
}

static bool MatchGetRadioTechParameter(napi_env env, const napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static napi_value GetRadioTech(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchGetRadioTechParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetRadioTech parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<RadioTechContext>();
    if (asyncContext == nullptr) {
        TELEPHONY_LOGE("GetRadioTech asyncContext is nullptr.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetRadioTech", NativeGetRadioTech, GetRadioTechCallback);
}

static void NativeGetSignalInfoList(napi_env env, void *data)
{
    auto asyncContext = static_cast<SignalInfoListContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetSignalInfoList slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSignalInfoList(
        asyncContext->slotId, asyncContext->signalInfoList);
    TELEPHONY_LOGI("NativeGetSignalInfoList size = %{public}zu", asyncContext->signalInfoList.size());
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->resolved = true;
    }
}

static void GetSignalInfoListCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<SignalInfoListContext *>(data);
    TELEPHONY_LOGI("GetSignalInfoListCallback size = %{public}zu, resolved = %{public}d",
        asyncContext->signalInfoList.size(), asyncContext->resolved);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_array(env, &callbackValue);
        int i = 0;
        for (sptr<SignalInformation> infoItem : asyncContext->signalInfoList) {
            napi_value info = nullptr;
            napi_create_object(env, &info);
            int32_t signalType = static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
            int32_t signalLevel = 0;
            int32_t signalIntensity = 0;
            if (infoItem != nullptr) {
                signalType = WrapSignalInformationType(infoItem->GetNetworkType());
                signalLevel = infoItem->GetSignalLevel();
                signalIntensity = infoItem->GetSignalIntensity();
            }
            NapiUtil::SetPropertyInt32(env, info, "signalType", signalType);
            NapiUtil::SetPropertyInt32(env, info, "signalLevel", signalLevel);
            NapiUtil::SetPropertyInt32(env, info, "dBm", signalIntensity);
            napi_set_element(env, callbackValue, i, info);
            i++;
            TELEPHONY_LOGI(
                "GetSignalInfoListCallback signalType:%{public}d, signalIntensity:%{public}d, signalLevel:%{public}d",
                signalType, signalIntensity, signalLevel);
        }
    } else {
        JsError error = NapiUtil::ConverErrorMessageForJs(asyncContext->errorCode);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("GetSignalInfoListCallback end");
}

static bool MatchGetSignalInfoListParameter(napi_env env, napi_value parameter[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static napi_value GetSignalInfoList(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchGetSignalInfoListParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetSignalInfoList parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<SignalInfoListContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &(asyncContext->slotId)));
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetSignalInfoList", NativeGetSignalInfoList, GetSignalInfoListCallback);
}

static int32_t WrapRegState(int32_t nativeState)
{
    RegServiceState state = static_cast<RegServiceState>(nativeState);
    switch (state) {
        case RegServiceState::REG_STATE_IN_SERVICE: {
            return RegStatus::REGISTRATION_STATE_IN_SERVICE;
        }
        case RegServiceState::REG_STATE_EMERGENCY_ONLY: {
            return RegStatus::REGISTRATION_STATE_EMERGENCY_CALL_ONLY;
        }
        case RegServiceState::REG_STATE_POWER_OFF: {
            return RegStatus::REGISTRATION_STATE_POWER_OFF;
        }
        default:
            return RegStatus::REGISTRATION_STATE_NO_SERVICE;
    }
}

static void NativeGetNetworkState(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetStateContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetNetworkState slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    sptr<NetworkState> networkState = nullptr;
    asyncContext->errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkState(asyncContext->slotId, networkState);
    if (asyncContext->errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("NativeGetNetworkState errorCode = %{public}d", asyncContext->errorCode);
        return;
    }
    if (networkState == nullptr) {
        TELEPHONY_LOGE("NativeGetNetworkState networkState is nullptr");
        asyncContext->errorCode = ERROR_NATIVE_API_EXECUTE_FAIL;
        return;
    }
    asyncContext->resolved = true;
    asyncContext->regStatus = static_cast<int32_t>(networkState->GetRegStatus());
    asyncContext->longOperatorName = networkState->GetLongOperatorName();
    asyncContext->shortOperatorName = networkState->GetShortOperatorName();
    asyncContext->plmnNumeric = networkState->GetPlmnNumeric();
    asyncContext->isRoaming = networkState->IsRoaming();
    asyncContext->isEmergency = networkState->IsEmergency();
    asyncContext->csRoamingStatus = static_cast<int32_t>(networkState->GetCsRoamingStatus());
    asyncContext->psRoamingStatus = static_cast<int32_t>(networkState->GetPsRoamingStatus());
    asyncContext->cfgTech = static_cast<int32_t>(networkState->GetCfgTech());
    TELEPHONY_LOGI("NativeGetNetworkState resolved is true.");
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
        NapiUtil::SetPropertyInt32(env, callbackValue, "regState", WrapRegState(asyncContext->regStatus));
        NapiUtil::SetPropertyInt32(env, callbackValue, "nsaState", asyncContext->nsaState);
        NapiUtil::SetPropertyInt32(env, callbackValue, "cfgTech", WrapRadioTech(asyncContext->cfgTech));
        NapiUtil::SetPropertyBoolean(env, callbackValue, "isCaActive", asyncContext->isCaActive);
        NapiUtil::SetPropertyBoolean(env, callbackValue, "isEmergency", asyncContext->isEmergency);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            asyncContext->errorCode, "getNetworkState", GET_NETWORK_INFO);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
}

static bool MatchGetNetworkStateParameter(napi_env env, napi_value parameter[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ZERO: {
            return true;
        }
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number }) ||
                   NapiUtil::MatchParameters(env, parameter, { napi_function });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static bool MatchGetIMEIParameter(napi_env env, napi_value parameter[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ZERO: {
            return true;
        }
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number }) ||
                   NapiUtil::MatchParameters(env, parameter, { napi_function });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static bool MatchGetNrOptionModeParameter(napi_env env, napi_value parameter[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ZERO: {
            return true;
        }
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number }) ||
                   NapiUtil::MatchParameters(env, parameter, { napi_function });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static bool MatchIsNrSupportedParameter(napi_env env, napi_value parameter[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ZERO: {
            return true;
        }
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameter, { napi_number });
        }
        default: {
            return false;
        }
    }
}

static napi_value GetNetworkState(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchGetNetworkStateParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetNetworkState parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetStateContext>();
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetNetworkState", NativeGetNetworkState, GetNetworkStateCallback);
}

static void NativeGetNetworkSelectionMode(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetSelectModeContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetNetworkSelectionMode slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<GetNetworkSearchModeCallback> callback =
        std::make_unique<GetNetworkSearchModeCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkSelectionMode(
        asyncContext->slotId, callback.release());
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->cv.wait_for(
            callbackLock, std::chrono::seconds(WAIT_TIME_SECOND), [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeGetNetworkSelectionMode after callback end");
    }
    TELEPHONY_LOGI("NativeGetNetworkSelectionMode end");
}

static void GetNetworkSelectionModeCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<GetSelectModeContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_int32(env, asyncContext->selectMode, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageForJs(asyncContext->errorCode);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("GetNetworkSelectionModeCallback end");
}

static napi_value GetNetworkSelectionMode(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchGetRadioTechParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetNetworkSelectionMode parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetSelectModeContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "GetNetworkSelectionMode",
        NativeGetNetworkSelectionMode, GetNetworkSelectionModeCallback);
}

static void NativeGetNetworkSearchInformation(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetSearchInfoContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetNetworkSearchInformation slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<GetNetworkSearchInfoCallback> callback =
        std::make_unique<GetNetworkSearchInfoCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkSearchInformation(
        asyncContext->slotId, callback.release());
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->cv.wait_for(
            callbackLock, std::chrono::seconds(WAIT_TIME_SECOND), [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeGetNetworkSearchInformation after callback end");
    }
    TELEPHONY_LOGI("NativeGetNetworkSearchInformation end");
}

static int32_t WrapToJsPlmnState(int32_t nativeState)
{
    NetworkPlmnState state = static_cast<NetworkPlmnState>(nativeState);
    switch (state) {
        case NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE: {
            return NETWORK_AVAILABLE;
        }
        case NetworkPlmnState::NETWORK_PLMN_STATE_REGISTERED: {
            return NETWORK_CURRENT;
        }
        case NetworkPlmnState::NETWORK_PLMN_STATE_FORBIDDEN: {
            return NETWORK_FORBIDDEN;
        }
        default: {
            return NETWORK_UNKNOWN;
        }
    }
}

static std::string GetRadioTechName(int32_t radioTech)
{
    NetworkRat tech = static_cast<NetworkRat>(radioTech);
    switch (tech) {
        case NetworkRat::NETWORK_GSM_OR_GPRS: {
            return "GSM";
        }
        case NetworkRat::NETWORK_WCDMA: {
            return "WCDMA";
        }
        case NetworkRat::NETWORK_LTE: {
            return "LTE";
        }
        default: {
            return "";
        }
    }
}

static void GetNetworkSearchInformationCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<GetSearchInfoContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        int32_t searchResultSize = asyncContext->searchResult->GetNetworkSearchInformationSize();
        TELEPHONY_LOGI("GetNetworkSearchInformationCallback SearchResultSize = %{public}d", searchResultSize);
        napi_create_object(env, &callbackValue);
        bool isNetworkSearchSuccess = searchResultSize > 0;
        NapiUtil::SetPropertyBoolean(env, callbackValue, "isNetworkSearchSuccess", isNetworkSearchSuccess);
        napi_value searchResultArray = nullptr;
        napi_create_array(env, &searchResultArray);
        std::vector<NetworkInformation> resultList = asyncContext->searchResult->GetNetworkSearchInformation();
        int32_t resultListSize = static_cast<int32_t>(resultList.size());
        TELEPHONY_LOGI("GetNetworkSearchInformationCallback SearchResultSize = %{public}d", searchResultSize);
        for (int32_t i = 0; i < resultListSize; i++) {
            napi_value info = nullptr;
            napi_create_object(env, &info);
            NapiUtil::SetPropertyStringUtf8(env, info, "operatorName", resultList[i].GetOperatorLongName());
            NapiUtil::SetPropertyStringUtf8(env, info, "operatorNumeric", resultList[i].GetOperatorNumeric());
            NapiUtil::SetPropertyInt32(env, info, "state", WrapToJsPlmnState(resultList[i].GetNetworkState()));
            NapiUtil::SetPropertyStringUtf8(env, info, "radioTech", GetRadioTechName(resultList[i].GetRadioTech()));
            napi_set_element(env, searchResultArray, i, info);
        }
        napi_set_named_property(env, callbackValue, "networkSearchResult", searchResultArray);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            asyncContext->errorCode, "getNetworkSearchInformation", GET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("GetNetworkSearchInformationCallback end");
}

static bool MatchGetNetworkSearchInformation(napi_env env, const napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static napi_value GetNetworkSearchInformation(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchGetNetworkSearchInformation(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetNetworkSearchInformation parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetSearchInfoContext>().release();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext, "GetNetworkSearchInformation",
        NativeGetNetworkSearchInformation, GetNetworkSearchInformationCallback);
}

static bool HasNamedPropertyType(napi_env env, napi_value object, napi_valuetype type, const std::string &propertyName)
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
        char chars[BUF_SIZE] = { 0 };
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
    TELEPHONY_LOGI("start MatchSetNetworkSelectionModeParameters parameterCount = %{public}lu",
        static_cast<unsigned long>(parameterCount));
    switch (parameterCount) {
        case PARAMETER_COUNT_ONE: {
            if (!NapiUtil::MatchParameters(env, parameters, { napi_object })) {
                return false;
            }
            break;
        }
        case PARAMETER_COUNT_TWO: {
            if (!NapiUtil::MatchParameters(env, parameters, { napi_object, napi_function })) {
                TELEPHONY_LOGI("start MatchSetNetworkSelectionModeParameters not match two parameter");
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

static int32_t GetRatTechValue(std::string ratTechStr)
{
    if (!GSM.compare(ratTechStr) || GPRS.compare(ratTechStr)) {
        return static_cast<int32_t>(NetworkRat::NETWORK_GSM_OR_GPRS);
    }
    if (!WCDMA.compare(ratTechStr)) {
        return static_cast<int32_t>(NetworkRat::NETWORK_WCDMA);
    }
    if (!LTE.compare(ratTechStr)) {
        return static_cast<int32_t>(NetworkRat::NETWORK_LTE);
    }
    return static_cast<int32_t>(NetworkRat::NETWORK_LTE);
}

static int32_t WrapPlmnState(int32_t jsState)
{
    switch (jsState) {
        case NETWORK_AVAILABLE: {
            return static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_AVAILABLE);
        }
        case NETWORK_CURRENT: {
            return static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_REGISTERED);
        }
        case NETWORK_FORBIDDEN: {
            return static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_FORBIDDEN);
        }
        default: {
            return static_cast<int32_t>(NetworkPlmnState::NETWORK_PLMN_STATE_UNKNOWN);
        }
    }
}

static void NativeSetNetworkSelectionMode(napi_env env, void *data)
{
    auto asyncContext = static_cast<SetSelectModeContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeSetNetworkSelectionMode slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    TELEPHONY_LOGI("NativeSetNetworkSelectionMode selectMode = %{public}d", asyncContext->selectMode);
    sptr<NetworkInformation> networkInfo = std::make_unique<NetworkInformation>().release();
    networkInfo->SetOperateInformation(asyncContext->operatorName, "", asyncContext->operatorNumeric,
        WrapPlmnState(asyncContext->state), GetRatTechValue(asyncContext->radioTech));
    TELEPHONY_LOGI("NativeSetNetworkSelectionMode operatorName = %{public}s", asyncContext->operatorName.c_str());
    std::unique_ptr<SetNetworkSearchModeCallback> callback =
        std::make_unique<SetNetworkSearchModeCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetNetworkSelectionMode(
        asyncContext->slotId, asyncContext->selectMode, networkInfo, asyncContext->resumeSelection, callback.release());
    TELEPHONY_LOGI("NativeSetNetworkSelectionMode errorCode = %{public}d", asyncContext->errorCode);
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->cv.wait_for(
            callbackLock, std::chrono::seconds(WAIT_TIME_SECOND), [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeSetNetworkSelectionMode after callback end");
    }
    TELEPHONY_LOGI("NativeSetNetworkSelectionMode end");
}

static void SetNetworkSelectionModeCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<SetSelectModeContext *>(data);
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->resolved = asyncContext->setResult;
    }
    TELEPHONY_LOGI("SetNetworkSelectionModeCallback resolved = %{public}d", asyncContext->resolved);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            asyncContext->errorCode, "setNetworkSelectionMode", SET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle1ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("SetNetworkSelectionModeCallback end");
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
    TELEPHONY_LOGI("ParseNetworkSelectionParameter jsSelectMode = %{public}d", jsSelectMode);
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
    TELEPHONY_LOGI("ParseNetworkSelectionParameter end");
}

static napi_value SetNetworkSelectionMode(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchSetNetworkSelectionModeParameters(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("SetNetworkSelectionMode parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<SetSelectModeContext>();
    ParseNetworkSelectionParameter(env, parameters[0], *asyncContext);
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "SetNetworkSelectionMode",
        NativeSetNetworkSelectionMode, SetNetworkSelectionModeCallback);
}

static void NativeGetCountryCode(napi_env env, void *data)
{
    auto context = static_cast<GetISOCountryCodeContext *>(data);
    if (!IsValidSlotId(context->slotId)) {
        TELEPHONY_LOGE("NativeGetCountryCode slotId is invalid");
        context->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string countryCode;
    context->errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetIsoCountryCodeForNetwork(context->slotId, countryCode);
    context->countryCode = NapiUtil::ToUtf8(countryCode);
    TELEPHONY_LOGI("NativeGetCountryCode countryCode = %{public}s", context->countryCode.c_str());
    if (context->errorCode == TELEPHONY_SUCCESS) {
        context->resolved = true;
    }
}

static void GetCountryCodeCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetISOCountryCodeContext *>(data);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_create_string_utf8(env, context->countryCode.c_str(), context->countryCode.size(), &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageForJs(context->errorCode);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static bool MatchGetISOCountryCodeForNetworkParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_function });
        }
        default:
            return false;
    }
}

static napi_value GetISOCountryCodeForNetwork(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchGetISOCountryCodeForNetworkParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetISOCountryCodeForNetwork parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetISOCountryCodeContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetISOCountryCodeForNetwork", NativeGetCountryCode, GetCountryCodeCallback);
}

static bool MatchIsRadioOnParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ZERO: {
            return true;
        }
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_function }) ||
                   NapiUtil::MatchParameters(env, parameters, { napi_number });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_function });
        }
        default:
            return false;
    }
}

static void NativeIsRadioOn(napi_env env, void *data)
{
    auto asyncContext = static_cast<IsRadioOnContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeIsRadioOn slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<GetRadioStateCallback> callback = std::make_unique<GetRadioStateCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetRadioState(asyncContext->slotId, callback.release());
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->cv.wait_for(
            callbackLock, std::chrono::seconds(WAIT_TIME_SECOND), [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeIsRadioOn after callback end");
    }
    TELEPHONY_LOGI("NativeIsRadioOn end");
}

static void IsRadioOnCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<IsRadioOnContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_boolean(env, asyncContext->isRadioOn, &callbackValue);
    } else {
        JsError error =
            NapiUtil::ConverErrorMessageWithPermissionForJs(asyncContext->errorCode, "isRadioOn", GET_NETWORK_INFO);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("IsRadioOnCallback end");
}

static napi_value IsRadioOn(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchIsRadioOnParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("IsRadioOn parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<IsRadioOnContext>();
    if (asyncContext == nullptr) {
        TELEPHONY_LOGE("IsRadioOn asyncContext is nullptr.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
            TELEPHONY_LOGI("IsRadioOn context->slotId = %{public}d", asyncContext->slotId);
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "IsRadioOn", NativeIsRadioOn, IsRadioOnCallback);
}

static void NativeTurnOnRadio(napi_env env, void *data)
{
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeTurnOnRadio slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<SetRadioStateCallback> callback = std::make_unique<SetRadioStateCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetRadioState(
        asyncContext->slotId, true, callback.release());
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->cv.wait_for(
            callbackLock, std::chrono::seconds(WAIT_TIME_SECOND), [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeTurnOnRadio after callback end");
    }
    TELEPHONY_LOGI("NativeTurnOnRadio end");
}

static void TurnOnRadioCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            asyncContext->errorCode, "turnOnRadio", SET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle1ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("TurnOnRadioCallback end");
}

static bool MatchSwitchRadioParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ZERO: {
            return true;
        }
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number }) ||
                   NapiUtil::MatchParameters(env, parameters, { napi_function });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_function });
        }
        default:
            return false;
    }
}

static napi_value TurnOnRadio(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchIsRadioOnParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("TurnOnRadio parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<SwitchRadioContext>();
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
            TELEPHONY_LOGI("TurnOnRadio context->slotId = %{public}d", asyncContext->slotId);
        } else {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "TurnOnRadio", NativeTurnOnRadio, TurnOnRadioCallback);
}

static void NativeTurnOffRadio(napi_env env, void *data)
{
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeTurnOffRadio slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<SetRadioStateCallback> callback = std::make_unique<SetRadioStateCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetRadioState(
        asyncContext->slotId, false, callback.release());
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->cv.wait_for(
            callbackLock, std::chrono::seconds(WAIT_TIME_SECOND), [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeTurnOffRadio after callback end");
    }
    TELEPHONY_LOGI("NativeTurnOffRadio end");
}

static void TurnOffRadioCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            asyncContext->errorCode, "turnOffRadio", SET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle1ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("TurnOffRadioCallback end");
}

static napi_value TurnOffRadio(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchIsRadioOnParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("TurnOffRadio parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<SwitchRadioContext>();
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
            TELEPHONY_LOGI("IsRadioOn context->slotId = %{public}d", asyncContext->slotId);
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "TurnOffRadio", NativeTurnOffRadio, TurnOffRadioCallback);
}

static void NativeGetOperatorName(napi_env env, void *data)
{
    auto context = static_cast<GetOperatorNameContext *>(data);
    if (!IsValidSlotId(context->slotId)) {
        TELEPHONY_LOGE("NativeGetOperatorName slotId is invalid");
        context->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string u16OperatorName = u"";
    context->errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorName(context->slotId, u16OperatorName);
    std::string operatorName = NapiUtil::ToUtf8(u16OperatorName);
    TELEPHONY_LOGI("NativeGetOperatorName operatorName = %{public}s", operatorName.c_str());
    if (context->errorCode == TELEPHONY_ERR_SUCCESS) {
        context->resolved = true;
        context->operatorNameLength = (operatorName.size() < BUF_SIZE) ? operatorName.size() : BUF_SIZE;
        for (size_t i = 0; i < context->operatorNameLength; i++) {
            context->operatorName[i] = operatorName.at(i);
        }
    }
}

static void GetOperatorNameCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetOperatorNameContext *>(data);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_create_string_utf8(env, context->operatorName, context->operatorNameLength, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageForJs(context->errorCode);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static bool MatchGetOperatorNameParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_function });
        }
        default:
            return false;
    }
}

static napi_value GetOperatorName(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchGetOperatorNameParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetOperatorName parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetOperatorNameContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetOperatorName", NativeGetOperatorName, GetOperatorNameCallback);
}

static void NativeSetPreferredNetwork(napi_env env, void *data)
{
    auto asyncContext = static_cast<PreferredNetworkModeContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeSetPreferredNetwork slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    auto setPreferredNetworkCallback = std::make_unique<SetPreferredNetworkCallback>(asyncContext);
    OHOS::sptr<INetworkSearchCallback> callback(setPreferredNetworkCallback.release());
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetPreferredNetwork(
        asyncContext->slotId, asyncContext->preferredNetworkMode, callback);
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->cv.wait_for(
            callbackLock, std::chrono::seconds(WAIT_TIME_SECOND), [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeTurnOffRadio after callback end");
    }
}

static void SetPreferredNetworkCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<PreferredNetworkModeContext *>(data);
    TELEPHONY_LOGI("SetPreferredNetworkCallback resolved = %{public}d", context->resolved);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            context->errorCode, "setPreferredNetwork", SET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    TELEPHONY_LOGI("SetPreferredNetworkCallback end");
    NapiUtil::Handle1ValueCallback(env, context, callbackValue);
}

static bool MatchSetPreferredNetworkParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_number });
        }
        case PARAMETER_COUNT_THREE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_number, napi_function });
        }
        default:
            return false;
    }
}

static napi_value SetPreferredNetwork(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_THREE;
    napi_value parameters[PARAMETER_COUNT_THREE] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchSetPreferredNetworkParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("SetPreferredNetwork parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<PreferredNetworkModeContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    NAPI_CALL(env, napi_get_value_int32(env, parameters[1], &asyncContext->preferredNetworkMode));
    if (parameterCount == PARAMETER_COUNT_THREE) {
        NAPI_CALL(env, napi_create_reference(env, parameters[2], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "SetPreferredNetworkMode", NativeSetPreferredNetwork, SetPreferredNetworkCallback);
}

static void NativeGetPreferredNetwork(napi_env env, void *data)
{
    auto asyncContext = static_cast<PreferredNetworkModeContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetPreferredNetwork slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    auto getPreferredNetworkCallback = std::make_unique<GetPreferredNetworkCallback>(asyncContext);
    OHOS::sptr<INetworkSearchCallback> callback(getPreferredNetworkCallback.release());
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPreferredNetwork(asyncContext->slotId, callback);
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->cv.wait_for(
            callbackLock, std::chrono::seconds(WAIT_TIME_SECOND), [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeGetPreferredNetwork after callback end");
    }
}

static void GetPreferredNetworkCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<PreferredNetworkModeContext *>(data);
    TELEPHONY_LOGI("GetPreferredNetworkCallback resolved = %{public}d", context->resolved);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_create_int32(env, context->preferredNetworkMode, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            context->errorCode, "getPreferredNetwork", GET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    TELEPHONY_LOGI("GetPreferredNetworkCallback end");
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static bool MatchGetPreferredNetworkParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_ONE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number });
        }
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_function });
        }
        default:
            return false;
    }
}

static napi_value GetPreferredNetwork(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchGetPreferredNetworkParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("SendUpdateCellLocationRequest parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<PreferredNetworkModeContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetPreferredNetworkMode", NativeGetPreferredNetwork, GetPreferredNetworkCallback);
}

void NativeGetIMEI(napi_env env, void *data)
{
    auto context = static_cast<GetIMEIContext *>(data);
    if (!IsValidSlotId(context->slotId)) {
        TELEPHONY_LOGE("NativeGetIMEI slotId is invalid");
        context->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string imei = u"";
    context->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetImei(context->slotId, imei);
    if (context->errorCode == TELEPHONY_SUCCESS) {
        context->resolved = true;
        context->getIMEIResult = NapiUtil::ToUtf8(imei);
        TELEPHONY_LOGI("NativeGetIMEI len = %{public}lu", static_cast<unsigned long>(context->getIMEIResult.length()));
    }
}

void GetIMEICallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetIMEIContext *>(data);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_create_string_utf8(env, context->getIMEIResult.c_str(), context->getIMEIResult.size(), &callbackValue);
    } else {
        JsError error =
            NapiUtil::ConverErrorMessageWithPermissionForJs(context->errorCode, "getIMEI", GET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static napi_value GetIMEI(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchGetIMEIParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetIMEI parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetIMEIContext>();
    if (asyncContext == nullptr) {
        TELEPHONY_LOGE("GetIMEI asyncContext is nullptr.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "GetIMEI", NativeGetIMEI, GetIMEICallback);
}

void NativeGetMEID(napi_env env, void *data)
{
    auto context = static_cast<GetMEIDContext *>(data);
    if (!IsValidSlotId(context->slotId)) {
        TELEPHONY_LOGE("NativeGetMEID slotId is invalid");
        context->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string meid = u"";
    context->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetMeid(context->slotId, meid);
    if (context->errorCode == TELEPHONY_SUCCESS) {
        context->resolved = true;
        context->getMEIDResult = NapiUtil::ToUtf8(meid);
        TELEPHONY_LOGI("NativeGetMEID len = %{public}lu", static_cast<unsigned long>(context->getMEIDResult.length()));
    }
}

void GetMEIDCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetMEIDContext *>(data);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_create_string_utf8(env, context->getMEIDResult.c_str(), context->getMEIDResult.size(), &callbackValue);
    } else {
        JsError error =
            NapiUtil::ConverErrorMessageWithPermissionForJs(context->errorCode, "getMEID", GET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static napi_value GetMEID(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchGetIMEIParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetMEID parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetMEIDContext>();
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
            TELEPHONY_LOGI("NativeGetMEID context->slotId = %{public}d", asyncContext->slotId);
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "getMEID", NativeGetMEID, GetMEIDCallback);
}

static void NativeSendUpdateCellLocationRequest(napi_env env, void *data)
{
    auto asyncContext = static_cast<SendUpdateCellLocationRequest *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeSendUpdateCellLocationRequest slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    asyncContext->errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().SendUpdateCellLocationRequest(asyncContext->slotId);
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->resolved = true;
    }
    TELEPHONY_LOGI("NativeSendUpdateCellLocationRequest end");
}

static void SendUpdateCellLocationRequestCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<SendUpdateCellLocationRequest *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            asyncContext->errorCode, "sendUpdateCellLocationRequest", LOCATION);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle1ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("SendUpdateCellLocationRequestCallback end");
}

static napi_value SendUpdateCellLocationRequest(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchSwitchRadioParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("SendUpdateCellLocationRequest parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<SwitchRadioContext>();
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "SendUpdateCellLocationRequest",
        NativeSendUpdateCellLocationRequest, SendUpdateCellLocationRequestCallback);
}

static int32_t WrapCellInformationType(const sptr<CellInformation> CellInfo)
{
    if (CellInfo != nullptr) {
        auto type = CellInfo->GetNetworkType();
        switch (type) {
            case CellInformation::CellType::CELL_TYPE_GSM:
                return static_cast<int32_t>(NetworkType::NETWORK_TYPE_GSM);
            case CellInformation::CellType::CELL_TYPE_WCDMA:
                return static_cast<int32_t>(NetworkType::NETWORK_TYPE_WCDMA);
            case CellInformation::CellType::CELL_TYPE_LTE:
                return static_cast<int32_t>(NetworkType::NETWORK_TYPE_LTE);
            case CellInformation::CellType::CELL_TYPE_TDSCDMA:
                return static_cast<int32_t>(NetworkType::NETWORK_TYPE_TDSCDMA);
            case CellInformation::CellType::CELL_TYPE_CDMA:
                return static_cast<int32_t>(NetworkType::NETWORK_TYPE_CDMA);
            case CellInformation::CellType::CELL_TYPE_NR:
                return static_cast<int32_t>(NetworkType::NETWORK_TYPE_NR);
            default:
                return static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
        }
    }
    return static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
}

void JudgmentDataGsm(napi_env env, napi_value data, sptr<CellInformation> infoItem)
{
    auto gsmCellInfo = static_cast<GsmCellInformation *>(infoItem.GetRefPtr());
    if (gsmCellInfo != nullptr) {
        NapiUtil::SetPropertyInt32(env, data, "lac", gsmCellInfo->GetLac());
        NapiUtil::SetPropertyInt32(env, data, "cellId", gsmCellInfo->GetCellId());
        NapiUtil::SetPropertyInt32(env, data, "arfcn", gsmCellInfo->GetArfcn());
        NapiUtil::SetPropertyInt32(env, data, "bsic", gsmCellInfo->GetBsic());
        NapiUtil::SetPropertyStringUtf8(env, data, "mcc", gsmCellInfo->GetMcc());
        NapiUtil::SetPropertyStringUtf8(env, data, "mnc", gsmCellInfo->GetMnc());
    }
}

void JudgmentDataLte(napi_env env, napi_value data, sptr<CellInformation> infoItem)
{
    auto lteCellInfo = static_cast<LteCellInformation *>(infoItem.GetRefPtr());
    if (lteCellInfo != nullptr) {
        NapiUtil::SetPropertyInt32(env, data, "cgi", 0);
        NapiUtil::SetPropertyInt32(env, data, "pci", lteCellInfo->GetPci());
        NapiUtil::SetPropertyInt32(env, data, "tac", lteCellInfo->GetTac());
        NapiUtil::SetPropertyInt32(env, data, "earfcn", lteCellInfo->GetArfcn());
        NapiUtil::SetPropertyInt32(env, data, "bandwidth", 0);
        NapiUtil::SetPropertyStringUtf8(env, data, "mcc", lteCellInfo->GetMcc());
        NapiUtil::SetPropertyStringUtf8(env, data, "mnc", lteCellInfo->GetMnc());
        NapiUtil::SetPropertyBoolean(env, data, "isSupportEndc", false);
    }
}

void JudgmentDataWcdma(napi_env env, napi_value data, sptr<CellInformation> infoItem)
{
    auto wcdmaCellInfo = static_cast<WcdmaCellInformation *>(infoItem.GetRefPtr());
    if (wcdmaCellInfo != nullptr) {
        NapiUtil::SetPropertyInt32(env, data, "lac", wcdmaCellInfo->GetLac());
        NapiUtil::SetPropertyInt32(env, data, "cellId", wcdmaCellInfo->GetCellId());
        NapiUtil::SetPropertyInt32(env, data, "psc", wcdmaCellInfo->GetPsc());
        NapiUtil::SetPropertyInt32(env, data, "uarfcn", 0);
        NapiUtil::SetPropertyStringUtf8(env, data, "mcc", wcdmaCellInfo->GetMcc());
        NapiUtil::SetPropertyStringUtf8(env, data, "mnc", wcdmaCellInfo->GetMnc());
    }
}

void JudgmentDataCdma(napi_env env, napi_value data, sptr<CellInformation> infoItem)
{
    auto cdmaCellInfo = static_cast<CdmaCellInformation *>(infoItem.GetRefPtr());
    if (cdmaCellInfo != nullptr) {
        NapiUtil::SetPropertyInt32(env, data, "baseId", cdmaCellInfo->GetBaseId());
        NapiUtil::SetPropertyInt32(env, data, "latitude", cdmaCellInfo->GetLatitude());
        NapiUtil::SetPropertyInt32(env, data, "longitude", cdmaCellInfo->GetLongitude());
        NapiUtil::SetPropertyInt32(env, data, "nid", cdmaCellInfo->GetNid());
        NapiUtil::SetPropertyInt32(env, data, "sid", cdmaCellInfo->GetSid());
    }
}

void JudgmentDataTdscdma(napi_env env, napi_value data, sptr<CellInformation> infoItem)
{
    auto tdscdmaCellInfo = static_cast<TdscdmaCellInformation *>(infoItem.GetRefPtr());
    if (tdscdmaCellInfo != nullptr) {
        NapiUtil::SetPropertyInt32(env, data, "lac", tdscdmaCellInfo->GetLac());
        NapiUtil::SetPropertyInt32(env, data, "cellId", tdscdmaCellInfo->GetCellId());
        NapiUtil::SetPropertyInt32(env, data, "cpid", tdscdmaCellInfo->GetCpid());
        NapiUtil::SetPropertyInt32(env, data, "uarfcn", tdscdmaCellInfo->GetArfcn());
        NapiUtil::SetPropertyStringUtf8(env, data, "mcc", tdscdmaCellInfo->GetMcc());
        NapiUtil::SetPropertyStringUtf8(env, data, "mnc", tdscdmaCellInfo->GetMnc());
    }
}

void JudgmentDataNr(napi_env env, napi_value data, sptr<CellInformation> infoItem)
{
    auto nrCellCellInfo = static_cast<NrCellInformation *>(infoItem.GetRefPtr());
    if (nrCellCellInfo != nullptr) {
        NapiUtil::SetPropertyInt32(env, data, "nrArfcn", nrCellCellInfo->GetArfcn());
        NapiUtil::SetPropertyInt32(env, data, "pci", nrCellCellInfo->GetPci());
        NapiUtil::SetPropertyInt32(env, data, "tac", nrCellCellInfo->GetTac());
        NapiUtil::SetPropertyInt32(env, data, "nci", nrCellCellInfo->GetNci());
        NapiUtil::SetPropertyStringUtf8(env, data, "mcc", nrCellCellInfo->GetMcc());
        NapiUtil::SetPropertyStringUtf8(env, data, "mnc", nrCellCellInfo->GetMnc());
    }
}

napi_value JudgmentData(napi_env env, sptr<CellInformation> infoItem, CellInformation::CellType cellType)
{
    napi_value data = nullptr;
    napi_create_object(env, &data);
    switch (cellType) {
        case CellInformation::CellType::CELL_TYPE_GSM: {
            JudgmentDataGsm(env, data, infoItem);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_LTE: {
            JudgmentDataLte(env, data, infoItem);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_WCDMA: {
            JudgmentDataWcdma(env, data, infoItem);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_CDMA: {
            JudgmentDataCdma(env, data, infoItem);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_TDSCDMA: {
            JudgmentDataTdscdma(env, data, infoItem);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_NR: {
            JudgmentDataNr(env, data, infoItem);
            break;
        }
        default:
            break;
    }
    return data;
}

static void NativeGetCellInformation(napi_env env, void *data)
{
    auto asyncContext = static_cast<CellInformationContext *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetCellInformation slotId is invalid");
        asyncContext->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    asyncContext->cellInformations.clear();
    asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCellInfoList(
        asyncContext->slotId, asyncContext->cellInformations);
    TELEPHONY_LOGI("NativeGetCellInformation len = %{public}lu",
        static_cast<unsigned long>(asyncContext->cellInformations.size()));
    if (asyncContext->errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("NativeGetCellInformation errorCode = %{public}d", asyncContext->errorCode);
        return;
    }
    if (asyncContext->cellInformations.size() == 0) {
        TELEPHONY_LOGE("NativeGetCellInformation cellInformations is empty.");
        asyncContext->errorCode = ERROR_NATIVE_API_EXECUTE_FAIL;
        return;
    }
    asyncContext->resolved = true;
}

void GetCellInformationCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<CellInformationContext *>(data);
    TELEPHONY_LOGI("GetCellInformationCallback size = %{public}zu,resolved = %{public}d",
        asyncContext->cellInformations.size(), asyncContext->resolved);
    if (asyncContext->resolved) {
        napi_create_array(env, &(asyncContext->callbackValue));
        int i = 0;
        for (sptr<CellInformation> infoItem : asyncContext->cellInformations) {
            napi_value info = nullptr;
            napi_create_object(env, &info);
            NapiUtil::SetPropertyBoolean(env, info, "isCamped", true);
            uint64_t timeStamp = 0;
            int32_t signalIntensity = 0;
            int32_t signalLevel = 0;
            CellInformation::CellType cellType = CellInformation::CellType::CELL_TYPE_NONE;
            if (infoItem != nullptr) {
                timeStamp = infoItem->GetTimeStamp();
                signalLevel = infoItem->GetSignalLevel();
                signalIntensity = infoItem->GetSignalIntensity();
                cellType = infoItem->GetNetworkType();
            }
            NapiUtil::SetPropertyInt32(env, info, "timeStamp", timeStamp);
            NapiUtil::SetPropertyInt32(env, info, "networkType", WrapCellInformationType(infoItem));
            napi_value signalInformation = nullptr;
            napi_create_object(env, &signalInformation);
            int32_t signalType = WrapCellInformationType(infoItem);
            NapiUtil::SetPropertyInt32(env, signalInformation, "signalType", signalType);
            NapiUtil::SetPropertyInt32(env, signalInformation, "signalLevel", signalLevel);
            NapiUtil::SetPropertyInt32(env, signalInformation, "dBm", signalIntensity);
            std::string name = "signalInformation";
            napi_set_named_property(env, info, name.c_str(), signalInformation);
            napi_set_named_property(env, info, "data", JudgmentData(env, infoItem, cellType));
            napi_set_element(env, asyncContext->callbackValue, i, info);
            ++i;
        }
    } else {
        JsError error =
            NapiUtil::ConverErrorMessageWithPermissionForJs(asyncContext->errorCode, "getCellInformation", LOCATION);
        asyncContext->callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, asyncContext->callbackValue);
    TELEPHONY_LOGI("GetCellInformationCallback end");
}

static napi_value GetCellInformation(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchGetNetworkStateParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetCellInformation parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = new CellInformationContext();
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetCellInformation", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, NativeGetCellInformation,
                       GetCellInformationCallback, static_cast<void *>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

static void NativeGetPrimarySlotId(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetPrimarySlotIdContext *>(data);
    asyncContext->errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPrimarySlotId(asyncContext->slotId);
    TELEPHONY_LOGI("GetPrimarySlotId = %{public}d", asyncContext->slotId);
    if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
        asyncContext->resolved = true;
    }
}

void GetPrimarySlotIdCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<GetPrimarySlotIdContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_int32(env, asyncContext->slotId, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageForJs(asyncContext->errorCode);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
}

static napi_value GetPrimarySlotId(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_ONE;
    napi_value parameters[PARAMETER_COUNT_ONE] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchSwitchRadioParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetPrimarySlotId parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<SwitchRadioContext>();
    if (parameterCount == PARAMETER_COUNT_ONE) {
        NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetPrimarySlotId", NativeGetPrimarySlotId, GetPrimarySlotIdCallback);
}

static void NativeGetUniqueDeviceId(napi_env env, void *data)
{
    auto context = static_cast<GetUniqueDeviceIdContext *>(data);
    if (!IsValidSlotId(context->slotId)) {
        TELEPHONY_LOGE("NativeGetUniqueDeviceId slotId is invalid");
        context->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::u16string deviceId = u"";
    context->errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetUniqueDeviceId(context->slotId, deviceId);
    if (context->errorCode == TELEPHONY_SUCCESS) {
        context->resolved = true;
        context->getUniqueDeviceId = NapiUtil::ToUtf8(deviceId);
        TELEPHONY_LOGI("NativeGetUniqueDeviceId len = %{public}lu",
            static_cast<unsigned long>(context->getUniqueDeviceId.length()));
    }
}

void GetUniqueDeviceIdCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetUniqueDeviceIdContext *>(data);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_create_string_utf8(
            env, context->getUniqueDeviceId.c_str(), context->getUniqueDeviceId.size(), &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            context->errorCode, "getUniqueDeviceId", GET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static napi_value GetUniqueDeviceId(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchGetIMEIParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetUniqueDeviceId parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetIMEIContext>();
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetUniqueDeviceId", NativeGetUniqueDeviceId, GetUniqueDeviceIdCallback);
}

static int32_t WrapNrOptionMode(NrMode type)
{
    switch (type) {
        case NrMode::NR_MODE_UNKNOWN:
            return static_cast<int32_t>(NR_OPTION_UNKNOWN);
        case NrMode::NR_MODE_NSA_ONLY:
            return static_cast<int32_t>(NR_OPTION_NSA_ONLY);
        case NrMode::NR_MODE_SA_ONLY:
            return static_cast<int32_t>(NR_OPTION_SA_ONLY);
        case NrMode::NR_MODE_NSA_AND_SA:
            return static_cast<int32_t>(NR_OPTION_NSA_AND_SA);
        default:
            return static_cast<int32_t>(NR_OPTION_UNKNOWN);
    }
}

static void NativeGetNrOptionMode(napi_env env, void *data)
{
    auto context = static_cast<GetNrOptionModeContext *>(data);
    if (!IsValidSlotId(context->slotId)) {
        TELEPHONY_LOGE("NativeGetNrOptionMode slotId is invalid");
        context->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    NrMode type = NrMode::NR_MODE_UNKNOWN;
    context->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNrOptionMode(context->slotId, type);
    context->nrOptionMode = WrapNrOptionMode(type);
    if (context->errorCode == TELEPHONY_SUCCESS) {
        TELEPHONY_LOGI("NativeGetNrOptionMode nrOptionMode = %{public}d", context->nrOptionMode);
        context->resolved = true;
    }
}

static void GetNrOptionModeCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetNrOptionModeContext *>(data);
    TELEPHONY_LOGI("GetNrOptionModeCallback resolved = %{public}d", context->resolved);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_create_int32(env, context->nrOptionMode, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageForJs(context->errorCode);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static napi_value GetNrOptionMode(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    if (!MatchGetNrOptionModeParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("GetNrOptionMode parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetNrOptionModeContext>();
    if (parameterCount == PARAMETER_COUNT_ZERO) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == PARAMETER_COUNT_ONE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetNrOptionMode", NativeGetNrOptionMode, GetNrOptionModeCallback);
}

static napi_value IsNrSupported(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_ONE;
    napi_value parameters[PARAMETER_COUNT_ONE] = { 0 };
    void *data = nullptr;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    bool isNrSupported = false;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchIsNrSupportedParameter(env, parameters, parameterCount), "type mismatch");
    int32_t slotId = SIM_SLOT_0;

    switch (parameterCount) {
        case PARAMETER_COUNT_ZERO: {
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPrimarySlotId(slotId);
            if (slotId == INVALID_VALUE) {
                TELEPHONY_LOGE("get primary slot id failed.");
                napi_get_boolean(env, isNrSupported, &result);
                return result;
            }
            isNrSupported = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsNrSupported(slotId);
            break;
        }
        case PARAMETER_COUNT_ONE: {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &slotId));
            if (!IsValidSlotId(slotId)) {
                TELEPHONY_LOGE("IsNrSupported slotId is invalid");
                napi_get_boolean(env, isNrSupported, &result);
                return result;
            }
            if (slotId == SIM_SLOT_0) {
                isNrSupported = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsNrSupported(SIM_SLOT_0);
            } else if (slotId == SIM_SLOT_1) {
                isNrSupported = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsNrSupported(SIM_SLOT_1);
            }
            break;
        }
        default:
            break;
    }
    napi_get_boolean(env, isNrSupported, &result);
    return result;
}

static void NativeSetPrimarySlotId(napi_env env, void *data)
{
    auto context = static_cast<SetPrimarySlotIdContext *>(data);
    if (!IsValidSlotId(context->slotId)) {
        TELEPHONY_LOGE("NativeSetPrimarySlotId slotId is invalid");
        context->errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    context->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetPrimarySlotId(context->slotId);
    TELEPHONY_LOGI("context->errorCode = %{public}d", context->errorCode);
    if (context->errorCode == TELEPHONY_ERR_SUCCESS) {
        context->resolved = true;
    }
}

static void SetPrimarySlotIdCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<SetPrimarySlotIdContext *>(data);
    napi_value callbackValue = nullptr;
    if (context->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            context->errorCode, "setPrimarySlotId", SET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle1ValueCallback(env, context, callbackValue);
}

static napi_value SetPrimarySlotId(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_TWO;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchGetISOCountryCodeForNetworkParameter(env, parameters, parameterCount)) {
        TELEPHONY_LOGE("SetPrimarySlotId parameter matching failed.");
        NapiUtil::ThrowParameterError(env);
        return nullptr;
    }
    auto asyncContext = std::make_unique<SetPrimarySlotIdContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == PARAMETER_COUNT_TWO) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "SetPrimarySlotId", NativeSetPrimarySlotId, SetPrimarySlotIdCallback);
}

static void NativeGetImsRegInfo(napi_env env, void *data)
{
    auto context = static_cast<GetImsRegInfoContext *>(data);
    if (!IsValidSlotId(context->slotId)) {
        TELEPHONY_LOGE("NativeGetImsRegInfo slotId is invalid");
        context->errorCode = TELEPHONY_ERR_SLOTID_INVALID;
        return;
    }
    context->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetImsRegStatus(
        context->slotId, static_cast<ImsServiceType>(context->imsSrvType), context->imsRegInfo);
    TELEPHONY_LOGI("result is %{public}d", context->errorCode);
    context->resolved = (context->errorCode == TELEPHONY_SUCCESS);
}

static void GetImsRegInfoCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("status = %{public}d", status);
    auto context = static_cast<GetImsRegInfoContext *>(data);
    napi_value callbackValue = nullptr;
    JsError error = {};
    if (status == napi_ok) {
        TELEPHONY_LOGI("context->resolved = %{public}d", context->resolved);
        if (context->resolved) {
            napi_create_object(env, &callbackValue);
            NapiUtil::SetPropertyInt32(
                env, callbackValue, "imsRegState", static_cast<int32_t>(context->imsRegInfo.imsRegState));
            NapiUtil::SetPropertyInt32(
                env, callbackValue, "imsRegTech", static_cast<int32_t>(context->imsRegInfo.imsRegTech));
        } else {
            error = NapiUtil::ConverErrorMessageWithPermissionForJs(
                context->errorCode, "getImsRegInfo", GET_TELEPHONY_STATE);
            callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
        }
    } else {
        error = NapiUtil::ConverErrorMessageWithPermissionForJs(
            ERROR_NATIVE_API_EXECUTE_FAIL, "getImsRegInfo", GET_TELEPHONY_STATE);
        callbackValue = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static bool MatchGetImsRegInfoParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_TWO: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_number });
        }
        case PARAMETER_COUNT_THREE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_number, napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static void ReportFunctionFailed(napi_env env, int32_t resultCode, std::string funcName)
{
    JsError error = {};
    switch (resultCode) {
        case TELEPHONY_ERR_PERMISSION_ERR:
            error = NapiUtil::ConverErrorMessageWithPermissionForJs(resultCode, funcName, GET_TELEPHONY_STATE);
            break;
        default:
            error = NapiUtil::ConverErrorMessageForJs(resultCode);
            break;
    }
    NapiUtil::ThrowError(env, error.errorCode, error.errorMessage);
}

static napi_value GetImsRegInfo(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_THREE;
    napi_value parameters[PARAMETER_COUNT_THREE] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    if (!MatchGetImsRegInfoParameter(env, parameters, parameterCount)) {
        ReportFunctionFailed(env, ERROR_PARAMETER_COUNTS_INVALID, "GetImsRegInfo");
        return nullptr;
    }
    auto asyncContext = std::make_unique<GetImsRegInfoContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[ARRAY_INDEX_FIRST], &asyncContext->slotId));
    NAPI_CALL(env, napi_get_value_int32(env, parameters[ARRAY_INDEX_SECOND], &asyncContext->imsSrvType));
    if (parameterCount == PARAMETER_COUNT_THREE) {
        NAPI_CALL(env,
            napi_create_reference(env, parameters[ARRAY_INDEX_THIRD], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetImsRegInfo", NativeGetImsRegInfo, GetImsRegInfoCallback);
}

static bool RegisterImsRegStateCallback(
    napi_env env, napi_value thisVar, int32_t slotId, int32_t imsSrvType, napi_value argv[])
{
    ImsRegStateCallback stateCallback;
    stateCallback.env = env;
    stateCallback.slotId = slotId;
    stateCallback.imsSrvType = static_cast<ImsServiceType>(imsSrvType);
    napi_create_reference(env, thisVar, DATA_LENGTH_ONE, &(stateCallback.thisVar));
    napi_create_reference(env, argv[ARRAY_INDEX_FOURTH], DEFAULT_REF_COUNT, &(stateCallback.callbackRef));

    int32_t ret =
        DelayedSingleton<NapiImsRegInfoCallbackManager>::GetInstance()->RegisterImsRegStateCallback(stateCallback);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Register imsRegState callback failed");
        ReportFunctionFailed(env, ret, "on_imsRegStateChange");
        return false;
    }
    return true;
}

static bool MatchObserverOnParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_FOUR: {
            return NapiUtil::MatchParameters(env, parameters, { napi_string, napi_number, napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static bool MatchObserverOffParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case PARAMETER_COUNT_THREE: {
            return NapiUtil::MatchParameters(env, parameters, { napi_string, napi_number, napi_number });
        }
        case PARAMETER_COUNT_FOUR: {
            return NapiUtil::MatchParameters(env, parameters, { napi_string, napi_number, napi_number, napi_function });
        }
        default: {
            return false;
        }
    }
}

static bool IsValidImsSrvType(napi_env env, int32_t imsSrvType, const std::string &funcName)
{
    bool flag = true;
    switch (imsSrvType) {
        case ImsServiceType::TYPE_VOICE:
        case ImsServiceType::TYPE_VIDEO:
        case ImsServiceType::TYPE_UT:
        case ImsServiceType::TYPE_SMS:
            break;
        default:
            TELEPHONY_LOGE("imsSrvType %{public}d is invalid", imsSrvType);
            ReportFunctionFailed(env, TELEPHONY_ERR_ARGUMENT_INVALID, funcName);
            flag = false;
            break;
    }

    return flag;
}

static napi_value ObserverOn(napi_env env, napi_callback_info info)
{
    size_t argc = PARAMETER_COUNT_FOUR;
    napi_value argv[PARAMETER_COUNT_FOUR];
    napi_value thisVar;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL) != napi_ok) {
        TELEPHONY_LOGE("Can not get thisVar value");
        return nullptr;
    }
    if (!MatchObserverOnParameter(env, argv, argc)) {
        ReportFunctionFailed(env, ERROR_PARAMETER_COUNTS_INVALID, "on_imsRegStateChange");
        return nullptr;
    }
    size_t strLength = 0;
    char callbackType[INFO_MAXIMUM_LIMIT + 1];
    if (napi_get_value_string_utf8(env, argv[ARRAY_INDEX_FIRST], callbackType, INFO_MAXIMUM_LIMIT, &strLength) !=
        napi_ok) {
        TELEPHONY_LOGE("Can not get callbackType value");
        return nullptr;
    }
    std::string tmpStr = callbackType;
    if (tmpStr.compare("imsRegStateChange") != 0) {
        TELEPHONY_LOGE("callbackType is not imsRegStateChange and is %{public}s", tmpStr.c_str());
        ReportFunctionFailed(env, TELEPHONY_ERR_ARGUMENT_INVALID, "on_imsRegStateChange");
        return nullptr;
    }
    int32_t slotId;
    if (napi_get_value_int32(env, argv[ARRAY_INDEX_SECOND], &slotId) != napi_ok) {
        TELEPHONY_LOGE("Can not get slotId value");
        return nullptr;
    }
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        ReportFunctionFailed(env, TELEPHONY_ERR_ARGUMENT_INVALID, "on_imsRegStateChange");
        return nullptr;
    }
    int32_t imsSrvType;
    if (napi_get_value_int32(env, argv[ARRAY_INDEX_THIRD], &imsSrvType) != napi_ok) {
        TELEPHONY_LOGE("Can not get imsSrvType value");
        return nullptr;
    }
    if (!IsValidImsSrvType(env, imsSrvType, "on_imsRegStateChange")) {
        return nullptr;
    }
    if (!RegisterImsRegStateCallback(env, thisVar, slotId, imsSrvType, argv)) {
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

static bool UnregisterImsRegStateCallback(napi_env env, int32_t slotId, ImsServiceType imsSrvType)
{
    int32_t ret = DelayedSingleton<NapiImsRegInfoCallbackManager>::GetInstance()->UnregisterImsRegStateCallback(
        env, slotId, imsSrvType);
    if (ret != TELEPHONY_SUCCESS) {
        ReportFunctionFailed(env, ret, "off_imsRegStateChange");
        return false;
    }
    return true;
}

static napi_value ObserverOff(napi_env env, napi_callback_info info)
{
    size_t argc = PARAMETER_COUNT_FOUR;
    napi_value argv[PARAMETER_COUNT_FOUR];
    napi_value thisVar;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL) != napi_ok) {
        TELEPHONY_LOGE("Can not get thisVar value");
        return nullptr;
    }
    if (!MatchObserverOffParameter(env, argv, argc)) {
        ReportFunctionFailed(env, ERROR_PARAMETER_COUNTS_INVALID, "off_imsRegStateChange");
        return nullptr;
    }
    size_t strLength = 0;
    char callbackType[INFO_MAXIMUM_LIMIT + 1];
    if (napi_get_value_string_utf8(env, argv[ARRAY_INDEX_FIRST], callbackType, INFO_MAXIMUM_LIMIT, &strLength) !=
        napi_ok) {
        TELEPHONY_LOGE("Can not get callbackType value");
        return nullptr;
    }
    std::string tmpStr = callbackType;
    if (tmpStr.compare("imsRegStateChange") != 0) {
        TELEPHONY_LOGE("callbackType is not imsRegStateChange and is %{public}s", tmpStr.c_str());
        ReportFunctionFailed(env, TELEPHONY_ERR_ARGUMENT_INVALID, "off_imsRegStateChange");
        return nullptr;
    }
    int32_t slotId;
    if (napi_get_value_int32(env, argv[ARRAY_INDEX_SECOND], &slotId) != napi_ok) {
        TELEPHONY_LOGE("Can not get slotId value");
        return nullptr;
    }
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        ReportFunctionFailed(env, TELEPHONY_ERR_ARGUMENT_INVALID, "off_imsRegStateChange");
        return nullptr;
    }
    int32_t imsSrvType;
    if (napi_get_value_int32(env, argv[ARRAY_INDEX_THIRD], &imsSrvType) != napi_ok) {
        TELEPHONY_LOGE("Can not get imsSrvType value");
        return nullptr;
    }
    if (!IsValidImsSrvType(env, imsSrvType, "off_imsRegStateChange")) {
        return nullptr;
    }
    if (!UnregisterImsRegStateCallback(env, slotId, static_cast<ImsServiceType>(imsSrvType))) {
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value InitEnumRadioType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_UNKNOWN",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_GSM", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_1XRTT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_1XRTT))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_HSPA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_HSPA))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_HSPAP",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_HSPAP))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_TD_SCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_TD_SCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_EVDO",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_EVDO))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_EHRPD",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_EHRPD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_LTE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_LTE_CA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_LTE_CA))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_IWLAN",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_IWLAN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_NR", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_NR))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumNetworkType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_UNKNOWN",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_GSM", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_CDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_WCDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_TDSCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_LTE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_NR", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_NR))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumRegStatus(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "REG_STATE_NO_SERVICE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_NO_SERVICE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REG_STATE_IN_SERVICE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_IN_SERVICE))),
        DECLARE_NAPI_STATIC_PROPERTY("REG_STATE_EMERGENCY_CALL_ONLY",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_EMERGENCY_CALL_ONLY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REG_STATE_POWER_OFF", NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_POWER_OFF))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumNsaState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_NOT_SUPPORT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_NOT_SUPPORT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NSA_STATE_NO_DETECT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_NO_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_CONNECTED_DETECT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_CONNECTED_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_IDLE_DETECT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_IDLE_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_DUAL_CONNECTED",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_DUAL_CONNECTED))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_SA_ATTACHED",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_SA_ATTACHED))),
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
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_SELECTION_MANUAL", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_SELECTION_MANUAL))),
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

static napi_value InitEnumPreferredNetwork(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_AUTO",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_AUTO))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_EVDO",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_EVDO))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(
                env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumNrOptionMode(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "NR_OPTION_UNKNOWN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NR_OPTION_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NR_OPTION_NSA_ONLY", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NR_OPTION_NSA_ONLY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NR_OPTION_SA_ONLY", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NR_OPTION_SA_ONLY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NR_OPTION_NSA_AND_SA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NR_OPTION_NSA_AND_SA))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumImsRegState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "IMS_UNREGISTERED", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_UNREGISTERED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "IMS_REGISTERED", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REGISTERED))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumImsRegTech(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "REGISTRATION_TECH_NONE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REG_TECH_NONE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REGISTRATION_TECH_LTE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REG_TECH_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REGISTRATION_TECH_IWLAN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REG_TECH_IWLAN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REGISTRATION_TECH_NR", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REG_TECH_NR))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value InitEnumImsServiceType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("TYPE_VOICE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(TYPE_VOICE))),
        DECLARE_NAPI_STATIC_PROPERTY("TYPE_VIDEO", NapiUtil::ToInt32Value(env, static_cast<int32_t>(TYPE_VIDEO))),
        DECLARE_NAPI_STATIC_PROPERTY("TYPE_UT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(TYPE_UT))),
        DECLARE_NAPI_STATIC_PROPERTY("TYPE_SMS", NapiUtil::ToInt32Value(env, static_cast<int32_t>(TYPE_SMS))),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_value CreateEnumConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, &data);
    napi_value global = nullptr;
    napi_get_global(env, &global);
    return thisArg;
}

static napi_value CreateRadioType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_UNKNOWN",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_GSM", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_1XRTT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_1XRTT))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_HSPA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_HSPA))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_HSPAP",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_HSPAP))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_TD_SCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_TD_SCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_EVDO",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_EVDO))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_EHRPD",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_EHRPD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_LTE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_LTE_CA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_LTE_CA))),
        DECLARE_NAPI_STATIC_PROPERTY("RADIO_TECHNOLOGY_IWLAN",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_IWLAN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RADIO_TECHNOLOGY_NR", NapiUtil::ToInt32Value(env, static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_NR))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "RadioType", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr, sizeof(desc) / sizeof(*desc),
        desc, &result);
    napi_set_named_property(env, exports, "RadioType", result);

    return exports;
}

static napi_value CreateNetworkType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_UNKNOWN",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_GSM", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_CDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_WCDMA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_TYPE_TDSCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_LTE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TYPE_NR", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NetworkType::NETWORK_TYPE_NR))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "NetworkType", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result);
    napi_set_named_property(env, exports, "NetworkType", result);
    return exports;
}

static napi_value CreateRegStatus(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "REG_STATE_NO_SERVICE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_NO_SERVICE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REG_STATE_IN_SERVICE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_IN_SERVICE))),
        DECLARE_NAPI_STATIC_PROPERTY("REG_STATE_EMERGENCY_CALL_ONLY",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_EMERGENCY_CALL_ONLY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REG_STATE_POWER_OFF", NapiUtil::ToInt32Value(env, static_cast<int32_t>(REGISTRATION_STATE_POWER_OFF))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "RegState", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr, sizeof(desc) / sizeof(*desc),
        desc, &result);
    napi_set_named_property(env, exports, "RegState", result);
    return exports;
}

static napi_value CreateNsaState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_NOT_SUPPORT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_NOT_SUPPORT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NSA_STATE_NO_DETECT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_NO_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_CONNECTED_DETECT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_CONNECTED_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_IDLE_DETECT",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_IDLE_DETECT))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_DUAL_CONNECTED",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_DUAL_CONNECTED))),
        DECLARE_NAPI_STATIC_PROPERTY("NSA_STATE_SA_ATTACHED",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NsaState::NSA_STATE_SA_ATTACHED))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "NsaState", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr, sizeof(desc) / sizeof(*desc),
        desc, &result);
    napi_set_named_property(env, exports, "NsaState", result);
    return exports;
}

static napi_value CreateNetworkSelectionMode(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_SELECTION_UNKNOWN",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_SELECTION_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_SELECTION_AUTOMATIC",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_SELECTION_AUTOMATIC))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_SELECTION_MANUAL", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NETWORK_SELECTION_MANUAL))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "NetworkSelectionMode", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result);
    napi_set_named_property(env, exports, "NetworkSelectionMode", result);
    return exports;
}

static napi_value CreateNetworkInformationState(napi_env env, napi_value exports)
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
    napi_value result = nullptr;
    napi_define_class(env, "NetworkInformationState", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result);
    napi_set_named_property(env, exports, "NetworkInformationState", result);
    return exports;
}

static napi_value CreatePreferredNetwork(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_AUTO",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_AUTO))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_EVDO",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_EVDO))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_LTE_TDSCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_LTE_TDSCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM",
            NapiUtil::ToInt32Value(env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM))),
        DECLARE_NAPI_STATIC_PROPERTY("PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA",
            NapiUtil::ToInt32Value(
                env, static_cast<int32_t>(PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "PreferredNetworkMode", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result);
    napi_set_named_property(env, exports, "PreferredNetworkMode", result);
    return exports;
}

static napi_value CreateNrOptionMode(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "NR_OPTION_UNKNOWN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NR_OPTION_UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NR_OPTION_NSA_ONLY", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NR_OPTION_NSA_ONLY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NR_OPTION_SA_ONLY", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NR_OPTION_SA_ONLY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NR_OPTION_NSA_AND_SA", NapiUtil::ToInt32Value(env, static_cast<int32_t>(NR_OPTION_NSA_AND_SA))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "NrOptionMode", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result);
    napi_set_named_property(env, exports, "NrOptionMode", result);
    return exports;
}

static napi_value CreateImsServiceType(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("TYPE_VOICE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(TYPE_VOICE))),
        DECLARE_NAPI_STATIC_PROPERTY("TYPE_VIDEO", NapiUtil::ToInt32Value(env, static_cast<int32_t>(TYPE_VIDEO))),
        DECLARE_NAPI_STATIC_PROPERTY("TYPE_UT", NapiUtil::ToInt32Value(env, static_cast<int32_t>(TYPE_UT))),
        DECLARE_NAPI_STATIC_PROPERTY("TYPE_SMS", NapiUtil::ToInt32Value(env, static_cast<int32_t>(TYPE_SMS))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "ImsServiceType", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result);
    napi_set_named_property(env, exports, "ImsServiceType", result);
    return exports;
}

static napi_value CreateImsRegTech(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "REGISTRATION_TECH_NONE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REG_TECH_NONE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REGISTRATION_TECH_LTE", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REG_TECH_LTE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REGISTRATION_TECH_IWLAN", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REG_TECH_IWLAN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "REGISTRATION_TECH_NR", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REG_TECH_NR))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "ImsRegTech", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr, sizeof(desc) / sizeof(*desc),
        desc, &result);
    napi_set_named_property(env, exports, "ImsRegTech", result);
    return exports;
}

static napi_value CreateImsRegState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "IMS_UNREGISTERED", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_UNREGISTERED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "IMS_REGISTERED", NapiUtil::ToInt32Value(env, static_cast<int32_t>(IMS_REGISTERED))),
    };
    napi_value result = nullptr;
    napi_define_class(env, "ImsRegState", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result);
    napi_set_named_property(env, exports, "ImsRegState", result);
    return exports;
}

static napi_value CreateFunctions(napi_env env, napi_value exports)
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
        DECLARE_NAPI_FUNCTION("getOperatorName", GetOperatorName),
        DECLARE_NAPI_FUNCTION("setPreferredNetwork", SetPreferredNetwork),
        DECLARE_NAPI_FUNCTION("getPreferredNetwork", GetPreferredNetwork),
        DECLARE_NAPI_FUNCTION("getIMEI", GetIMEI),
        DECLARE_NAPI_FUNCTION("getMEID", GetMEID),
        DECLARE_NAPI_FUNCTION("sendUpdateCellLocationRequest", SendUpdateCellLocationRequest),
        DECLARE_NAPI_FUNCTION("getCellInformation", GetCellInformation),
        DECLARE_NAPI_FUNCTION("getPrimarySlotId", GetPrimarySlotId),
        DECLARE_NAPI_FUNCTION("getUniqueDeviceId", GetUniqueDeviceId),
        DECLARE_NAPI_FUNCTION("getNrOptionMode", GetNrOptionMode),
        DECLARE_NAPI_FUNCTION("isNrSupported", IsNrSupported),
        DECLARE_NAPI_FUNCTION("setPrimarySlotId", SetPrimarySlotId),
        DECLARE_NAPI_FUNCTION("getImsRegInfo", GetImsRegInfo),
        DECLARE_NAPI_FUNCTION("on", ObserverOn),
        DECLARE_NAPI_FUNCTION("off", ObserverOff),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

EXTERN_C_START
napi_value InitNapiRadioNetwork(napi_env env, napi_value exports)
{
    CreateFunctions(env, exports);
    InitEnumRadioType(env, exports);
    InitEnumNetworkType(env, exports);
    InitEnumRegStatus(env, exports);
    InitEnumNsaState(env, exports);
    InitEnumNetworkSelectionMode(env, exports);
    InitEnumNetworkInformationState(env, exports);
    InitEnumPreferredNetwork(env, exports);
    InitEnumNrOptionMode(env, exports);
    InitEnumImsRegState(env, exports);
    InitEnumImsRegTech(env, exports);
    InitEnumImsServiceType(env, exports);
    CreateImsServiceType(env, exports);
    CreateImsRegTech(env, exports);
    CreateImsRegState(env, exports);
    CreateNrOptionMode(env, exports);
    CreatePreferredNetwork(env, exports);
    CreateNetworkInformationState(env, exports);
    CreateNetworkSelectionMode(env, exports);
    CreateNsaState(env, exports);
    CreateRegStatus(env, exports);
    CreateNetworkType(env, exports);
    CreateRadioType(env, exports);
    return exports;
}
EXTERN_C_END

static napi_module _radioModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = InitNapiRadioNetwork,
    .nm_modname = "telephony.radio",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterRadioNetworkModule(void)
{
    napi_module_register(&_radioModule);
}
} // namespace Telephony
} // namespace OHOS
