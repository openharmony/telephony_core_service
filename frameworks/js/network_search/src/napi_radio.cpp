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
#include <chrono>
#include <unistd.h>

#include "telephony_log_wrapper.h"
#include "get_network_search_mode_callback.h"
#include "set_network_search_mode_callback.h"
#include "get_radio_state_callback.h"
#include "set_radio_state_callback.h"
#include "get_network_search_info_callback.h"
#include "get_preferred_network_callback.h"
#include "set_preferred_network_callback.h"
#include "core_service_client.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t DEFAULT_REF_COUNT = 1;
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

static napi_value ParseErrorValue(napi_env env, const int32_t rilErrorCode, const std::string &funcName)
{
    TELEPHONY_LOGI("rilErrorCode = %{public}d", rilErrorCode);
    switch (rilErrorCode) {
        case HRIL_ERR_NULL_POINT:
            return NapiUtil::CreateErrorMessage(env, funcName + " error because hril err null point", rilErrorCode);
        case HRIL_ERR_SUCCESS:
            return NapiUtil::CreateUndefined(env);
        case HRIL_ERR_GENERIC_FAILURE:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err generic failure", rilErrorCode);
        case HRIL_ERR_INVALID_PARAMETER:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err invalid parameter", rilErrorCode);
        case HRIL_ERR_CMD_SEND_FAILURE:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err cmd send failure", rilErrorCode);
        case HRIL_ERR_CMD_NO_CARRIER:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err cmd no carrier", rilErrorCode);
        case HRIL_ERR_INVALID_RESPONSE:
            return NapiUtil::CreateErrorMessage(
                env, funcName + " error because hril err invalid response", rilErrorCode);
        case HRIL_ERR_REPEAT_STATUS:
            return NapiUtil::CreateErrorMessage(env, funcName + " error because hril err repeat status", rilErrorCode);
        default:
            return NapiUtil::CreateErrorMessage(env, funcName + " ", rilErrorCode);
    }
}

static void NativeGetRadioTech(napi_env env, void *data)
{
    auto asyncContext = static_cast<RadioTechContext *>(data);
    int32_t psRadioTech = DEFAULT_ERROR;
    int32_t csRadioTech = DEFAULT_ERROR;
    psRadioTech = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPsRadioTech(asyncContext->slotId);
    csRadioTech = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCsRadioTech(asyncContext->slotId);
    auto napiRadioTechUnknown = static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_UNKNOWN);
    if ((psRadioTech >= napiRadioTechUnknown) && (csRadioTech >= napiRadioTechUnknown)) {
        asyncContext->resolved = true;
        asyncContext->csTech = WrapRadioTech(csRadioTech);
        asyncContext->psTech = WrapRadioTech(psRadioTech);
    } else {
        asyncContext->resolved = false;
    }
}

static void GetRadioTechCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("GetRadioTechCallback start");
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
    TELEPHONY_LOGI("GetRadioTechCallback end");
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
    auto asyncContext = std::make_unique<RadioTechContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetRadioTech", NativeGetRadioTech, GetRadioTechCallback);
}

static void NativeGetSignalInfoList(napi_env env, void *data)
{
    auto asyncContext = static_cast<SignalInfoListContext *>(data);
    asyncContext->signalInfoList =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSignalInfoList(asyncContext->slotId);
    TELEPHONY_LOGI("NativeGetSignalInfoList size = %{public}zu", asyncContext->signalInfoList.size());
    asyncContext->resolved = true;
}

static void GetSignalInfoListCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("GetSignalInfoListCallback start");
    auto asyncContext = static_cast<SignalInfoListContext *>(data);
    TELEPHONY_LOGI("GetSignalInfoListCallback size = %{public}zu,resolved = %{public}d",
        asyncContext->signalInfoList.size(), asyncContext->resolved);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_array(env, &callbackValue);
        int i = 0;
        for (sptr<SignalInformation> infoItem : asyncContext->signalInfoList) {
            napi_value info = nullptr;
            napi_create_object(env, &info);
            int32_t signalType = static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
            if (infoItem) {
                signalType = WrapSignalInformationType(infoItem->GetNetworkType());
            }
            NapiUtil::SetPropertyInt32(env, info, "signalType", signalType);
            int32_t signalLevel = 0;
            if (infoItem != nullptr) {
                signalLevel = infoItem->GetSignalLevel();
            }
            NapiUtil::SetPropertyInt32(env, info, "signalLevel", signalLevel);
            napi_set_element(env, callbackValue, i, info);
            i++;
            TELEPHONY_LOGI(
                "GetSignalInfoListCallback when resovled signalType  = %{public}d, signalLevel = %{public}d",
                signalType, signalLevel);
        }
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "get signal info list failed");
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("GetSignalInfoListCallback end");
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
    auto asyncContext = std::make_unique<SignalInfoListContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &(asyncContext->slotId)));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetSignalInfoList", NativeGetSignalInfoList, GetSignalInfoListCallback);
}

static int32_t WrapRegState(int32_t nativeState)
{
    RegServiceState state = static_cast<RegServiceState>(nativeState);
    switch (state) {
        case RegServiceState::REG_STATE_NO_SERVICE: {
            return RegStatus::REGISTRATION_STATE_NO_SERVICE;
        }
        case RegServiceState::REG_STATE_IN_SERVICE: {
            return RegStatus::REGISTRATION_STATE_IN_SERVICE;
        }
        case RegServiceState::REG_STATE_EMERGENCY_ONLY: {
            return RegStatus::REGISTRATION_STATE_EMERGENCY_CALL_ONLY;
        }
        case RegServiceState::REG_STATE_UNKNOWN: {
            return RegStatus::REGISTRATION_STATE_POWER_OFF;
        }
        default:
            return RegStatus::REGISTRATION_STATE_POWER_OFF;
    }
}

static void NativeGetNetworkState(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetStateContext *>(data);
    sptr<NetworkState> networkState = nullptr;
    networkState = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkState(asyncContext->slotId);
    if (networkState != nullptr) {
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
        NapiUtil::SetPropertyInt32(env, callbackValue, "regState", WrapRegState(asyncContext->regStatus));
        NapiUtil::SetPropertyInt32(env, callbackValue, "nsaState", asyncContext->nsaState);
        NapiUtil::SetPropertyInt32(env, callbackValue, "cfgTech", WrapRadioTech(asyncContext->cfgTech));
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

static bool MatchGetIMEIParameter(napi_env env, napi_value parameter[], size_t parameterCount)
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

static bool MatchGetNrOptionModeParameter(napi_env env, napi_value parameter[], size_t parameterCount)
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

static bool MatchIsNrSupportedParameter(napi_env env, napi_value parameter[], size_t parameterCount)
{
    switch (parameterCount) {
        case 0: {
            return true;
        }
        case 1: {
            return NapiUtil::MatchParameters(env, parameter, {napi_number});
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
    auto asyncContext = std::make_unique<GetStateContext>();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetNetworkState", NativeGetNetworkState, GetNetworkStateCallback);
}

static void NativeGetNetworkSelectionMode(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetSelectModeContext *>(data);
    std::unique_ptr<GetNetworkSearchModeCallback> callback =
        std::make_unique<GetNetworkSearchModeCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->sendRequest = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkSelectionMode(
        asyncContext->slotId, callback.release());
    if (asyncContext->sendRequest) {
        asyncContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeGetNetworkSelectionMode after callback end");
    }
    TELEPHONY_LOGI("NativeGetNetworkSelectionMode end");
}

static void GetNetworkSelectionModeCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = (GetSelectModeContext *)data;
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_int32(env, asyncContext->selectMode, &callbackValue);
    } else {
        callbackValue = ParseErrorValue(env, asyncContext->errorCode, " get network selection mode");
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("GetNetworkSelectionModeCallback end");
}

static napi_value GetNetworkSelectionMode(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchGetRadioTechParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetSelectModeContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "GetNetworkSelectionMode",
        NativeGetNetworkSelectionMode, GetNetworkSelectionModeCallback);
}

static void NativeGetNetworkSearchInformation(napi_env env, void *data)
{
    auto asyncContext = static_cast<GetSearchInfoContext *>(data);
    std::unique_ptr<GetNetworkSearchInfoCallback> callback =
        std::make_unique<GetNetworkSearchInfoCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->sendRequest = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkSearchInformation(
        asyncContext->slotId, callback.release());
    if (asyncContext->sendRequest) {
        asyncContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [asyncContext] { return asyncContext->callbackEnd; });
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
        callbackValue = ParseErrorValue(env, asyncContext->errorCode, "get network search info");
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("GetNetworkSearchInformationCallback end");
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
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
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
    TELEPHONY_LOGI("start MatchSetNetworkSelectionModeParameters parameterCount = %{public}d", parameterCount);
    switch (parameterCount) {
        case 1: {
            if (!NapiUtil::MatchParameters(env, parameters, {napi_object})) {
                return false;
            }
            break;
        }
        case 2: {
            if (!NapiUtil::MatchParameters(env, parameters, {napi_object, napi_function})) {
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
    TELEPHONY_LOGI("NativeSetNetworkSelectionMode selectMode = %{public}d", asyncContext->selectMode);
    sptr<NetworkInformation> networkInfo = std::make_unique<NetworkInformation>().release();
    networkInfo->SetOperateInformation(asyncContext->operatorName, "", asyncContext->operatorNumeric,
        WrapPlmnState(asyncContext->state), GetRatTechValue(asyncContext->radioTech));
    TELEPHONY_LOGI("NativeSetNetworkSelectionMode operatorName = %{public}s", asyncContext->operatorName.c_str());
    std::unique_ptr<SetNetworkSearchModeCallback> callback =
        std::make_unique<SetNetworkSearchModeCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->sendRequest =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().SetNetworkSelectionMode(asyncContext->slotId,
            asyncContext->selectMode, networkInfo, asyncContext->resumeSelection, callback.release());
    TELEPHONY_LOGI("NativeSetNetworkSelectionMode setResult = %{public}d", asyncContext->sendRequest);
    if (asyncContext->sendRequest) {
        asyncContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeSetNetworkSelectionMode after callback end");
    }
    TELEPHONY_LOGI("NativeSetNetworkSelectionMode end");
}

static void SetNetworkSelectionModeCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("SetNetworkSelectionModeCallback start");
    auto asyncContext = static_cast<SetSelectModeContext *>(data);
    if (asyncContext->sendRequest) {
        asyncContext->resolved = asyncContext->setResult;
        TELEPHONY_LOGI("SetNetworkSelectionModeCallback resolved = %{public}d", asyncContext->resolved);
    } else {
        asyncContext->resolved = false;
    }
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        callbackValue = ParseErrorValue(env, asyncContext->errorCode, "set network selection mode");
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
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchSetNetworkSelectionModeParameters(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SetSelectModeContext>();
    ParseNetworkSelectionParameter(env, parameters[0], *asyncContext);
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "SetNetworkSelectionMode",
        NativeSetNetworkSelectionMode, SetNetworkSelectionModeCallback);
}

static void NativeGetCountryCode(napi_env env, void *data)
{
    auto context = static_cast<GetISOCountryCodeContext *>(data);
    context->countryCode = NapiUtil::ToUtf8(
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetIsoCountryCodeForNetwork(context->slotId));
    TELEPHONY_LOGI("NativeGetCountryCode countryCode = %{public}s", context->countryCode.c_str());
    context->resolved = true;
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
        callbackValue =
            NapiUtil::CreateErrorMessage(env, "get iso country code error,napi_status = " + std ::to_string(status));
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
    auto asyncContext = std::make_unique<GetISOCountryCodeContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetISOCountryCodeForNetwork", NativeGetCountryCode, GetCountryCodeCallback);
}

static bool MatchIsRadioOnParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 0: {
            return true;
        }
        case 1: {
            return NapiUtil::MatchParameters(env, parameters, {napi_function}) ||
                   NapiUtil::MatchParameters(env, parameters, {napi_number});
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
    std::unique_ptr<GetRadioStateCallback> callback = std::make_unique<GetRadioStateCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->sendRequest =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetRadioState(asyncContext->slotId, callback.release());
    if (asyncContext->sendRequest) {
        asyncContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeIsRadioOn after callback end");
    }
    TELEPHONY_LOGI("NativeIsRadioOn end");
}

static void IsRadioOnCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("IsRadioOnCallback start");
    auto asyncContext = static_cast<IsRadioOnContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_boolean(env, asyncContext->isRadioOn, &callbackValue);
    } else {
        callbackValue = ParseErrorValue(env, asyncContext->errorCode, "get radio status");
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("IsRadioOnCallback end");
}

static napi_value IsRadioOn(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchIsRadioOnParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<IsRadioOnContext>();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
            TELEPHONY_LOGI("IsRadioOn context->slotId = %{public}d", asyncContext->slotId);
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "IsRadioOn", NativeIsRadioOn, IsRadioOnCallback);
}

static void NativeTurnOnRadio(napi_env env, void *data)
{
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    std::unique_ptr<SetRadioStateCallback> callback = std::make_unique<SetRadioStateCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    TELEPHONY_LOGI("NativeTurnOnRadio start");
    asyncContext->sendRequest = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetRadioState(
        asyncContext->slotId, true, callback.release());
    if (asyncContext->sendRequest) {
        asyncContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeTurnOnRadio after callback end");
    }
    TELEPHONY_LOGI("NativeTurnOnRadio end");
}

static void TurnOnRadioCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("TurnOnRadioCallback start");
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        callbackValue = ParseErrorValue(env, asyncContext->errorCode, "turn on radio");
    }
    NapiUtil::Handle1ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("TurnOnRadioCallback end");
}

static bool MatchSwitchRadioParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 0: {
            return true;
        }
        case 1: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number}) ||
                NapiUtil::MatchParameters(env, parameters, {napi_function});
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
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchIsRadioOnParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SwitchRadioContext>();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
            TELEPHONY_LOGI("IsRadioOn context->slotId = %{public}d", asyncContext->slotId);
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "TurnOnRadio", NativeTurnOnRadio, TurnOnRadioCallback);
}

static void NativeTurnOffRadio(napi_env env, void *data)
{
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    std::unique_ptr<SetRadioStateCallback> callback = std::make_unique<SetRadioStateCallback>(asyncContext);
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->sendRequest = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetRadioState(
        asyncContext->slotId, false, callback.release());
    if (asyncContext->sendRequest) {
        asyncContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [asyncContext] { return asyncContext->callbackEnd; });
        TELEPHONY_LOGI("NativeTurnOffRadio after callback end");
    }
    TELEPHONY_LOGI("NativeTurnOffRadio end");
}

static void TurnOffRadioCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("TurnOffRadioCallback start");
    auto asyncContext = static_cast<SwitchRadioContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        callbackValue = ParseErrorValue(env, asyncContext->errorCode, "turn off radio");
    }
    NapiUtil::Handle1ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("TurnOffRadioCallback end");
}

static napi_value TurnOffRadio(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchIsRadioOnParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SwitchRadioContext>();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
            TELEPHONY_LOGI("IsRadioOn context->slotId = %{public}d", asyncContext->slotId);
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "TurnOffRadio", NativeTurnOffRadio, TurnOffRadioCallback);
}

static void NativeGetOperatorName(napi_env env, void *data)
{
    auto context = static_cast<GetOperatorNameContext *>(data);
    std::u16string u16OperatorName =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorName(context->slotId);
    std::string operatorName = NapiUtil::ToUtf8(u16OperatorName);
    TELEPHONY_LOGI("NativeGetOperatorName operatorName = %{public}s", operatorName.c_str());
    context->resolved = true;
    if (context->resolved) {
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
        callbackValue = NapiUtil::CreateErrorMessage(env, "get operator name failed");
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static bool MatchGetOperatorNameParameter(napi_env env, napi_value parameters[], size_t parameterCount)
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

static napi_value GetOperatorName(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchGetOperatorNameParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetOperatorNameContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetOperatorName", NativeGetOperatorName, GetOperatorNameCallback);
}

static void NativeSetPreferredNetwork(napi_env env, void *data)
{
    auto asyncContext = static_cast<PreferredNetworkModeContext *>(data);
    auto setPreferredNetworkCallback = std::make_unique<SetPreferredNetworkCallback>(asyncContext);
    OHOS::sptr<INetworkSearchCallback> callback(setPreferredNetworkCallback.release());
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->sendRequest = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetPreferredNetwork(
        asyncContext->slotId, asyncContext->preferredNetworkMode, callback);
    if ((asyncContext->slotId != 0) && (asyncContext->slotId != 1)) {
        asyncContext->resolved = false;
        asyncContext->errorCode = SLOTID_INPUT_ERROR;
    } else {
        if (asyncContext->sendRequest) {
            asyncContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
                [asyncContext] { return asyncContext->callbackEnd; });
            TELEPHONY_LOGI("NativeTurnOffRadio after callback end");
        } else {
            asyncContext->resolved = false;
            asyncContext->errorCode = HRIL_ERR_CMD_SEND_FAILURE;
        }
    }
}

static void SetPreferredNetworkCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<PreferredNetworkModeContext *>(data);
    TELEPHONY_LOGI("SetPreferredNetworkCallback resolved = %{public}d", context->resolved);
    napi_value callbackValue = nullptr;
    if (status == napi_ok) {
        if (context->resolved) {
            napi_get_undefined(env, &callbackValue);
        } else {
            if (context->errorCode == SLOTID_INPUT_ERROR) {
                callbackValue = ParseErrorValue(env, context->errorCode, "slotId input error");
            } else if (context->errorCode == ENUMERATION_INPUT_ERROR) {
                callbackValue = ParseErrorValue(env, context->errorCode, "enumeration input error");
            } else {
                callbackValue = ParseErrorValue(env, context->errorCode, "set preferred network mode error");
            }
        }
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(
            env, "set preferred network error because napi_status = " + std::to_string(status));
    }
    TELEPHONY_LOGI("SetPreferredNetworkCallback end");
    NapiUtil::Handle1ValueCallback(env, context, callbackValue);
}

static bool MatchSetPreferredNetworkParameter(napi_env env, napi_value parameters[], size_t parameterCount)
{
    switch (parameterCount) {
        case 2: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number, napi_number});
        }
        case 3: {
            return NapiUtil::MatchParameters(env, parameters, {napi_number, napi_number, napi_function});
        }
        default:
            return false;
    }
}

static napi_value SetPreferredNetwork(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 3;
    napi_value parameters[3] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchSetPreferredNetworkParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<PreferredNetworkModeContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    NAPI_CALL(env, napi_get_value_int32(env, parameters[1], &asyncContext->preferredNetworkMode));
    if (parameterCount == 3) {
        NAPI_CALL(env, napi_create_reference(env, parameters[2], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "SetPreferredNetworkMode",
        NativeSetPreferredNetwork, SetPreferredNetworkCallback);
}

static void NativeGetPreferredNetwork(napi_env env, void *data)
{
    auto asyncContext = static_cast<PreferredNetworkModeContext *>(data);
    auto getPreferredNetworkCallback = std::make_unique<GetPreferredNetworkCallback>(asyncContext);
    OHOS::sptr<INetworkSearchCallback> callback(getPreferredNetworkCallback.release());
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->sendRequest =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPreferredNetwork(asyncContext->slotId, callback);
    if ((asyncContext->slotId != 0) && (asyncContext->slotId != 1)) {
        asyncContext->resolved = false;
        asyncContext->errorCode = SLOTID_INPUT_ERROR;
    } else {
        if (asyncContext->sendRequest) {
            asyncContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
                [asyncContext] { return asyncContext->callbackEnd; });
            TELEPHONY_LOGI("GetPreferredNetwork after callback end");
        } else {
            asyncContext->resolved = false;
            asyncContext->errorCode = HRIL_ERR_CMD_SEND_FAILURE;
        }
    }
}

static void GetPreferredNetworkCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<PreferredNetworkModeContext *>(data);
    TELEPHONY_LOGI("GetPreferredNetworkCallback resolved = %{public}d", context->resolved);
    napi_value callbackValue = nullptr;
    if (status == napi_ok) {
        if (context->resolved) {
            napi_create_int32(env, context->preferredNetworkMode, &callbackValue);
        } else {
            if (context->errorCode == SLOTID_INPUT_ERROR) {
                callbackValue = ParseErrorValue(env, context->errorCode, "slotId input error");
            } else {
                callbackValue = ParseErrorValue(env, context->errorCode, "get preferred network mode");
            }
        }
    } else {
        context->resolved = false;
        callbackValue = NapiUtil::CreateErrorMessage(
            env, "get preferred network error because napi_status = " + std::to_string(status));
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static bool MatchGetPreferredNetworkParameter(napi_env env, napi_value parameters[], size_t parameterCount)
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

static napi_value GetPreferredNetwork(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchGetPreferredNetworkParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<PreferredNetworkModeContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "GetPreferredNetworkMode",
        NativeGetPreferredNetwork, GetPreferredNetworkCallback);
}

void NativeGetIMEI(napi_env env, void *data)
{
    auto context = static_cast<GetIMEIContext *>(data);
    context->getIMEIResult =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetImei(context->slotId));
    context->resolved = true;
}

void GetIMEICallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetIMEIContext *>(data);
    napi_value callbackValue = nullptr;
    if (status == napi_ok) {
        if (context->resolved) {
            napi_create_string_utf8(
                env, context->getIMEIResult.c_str(), context->getIMEIResult.size(), &callbackValue);
        } else {
            callbackValue = NapiUtil::CreateErrorMessage(env, "getIMEI error");
        }
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "getIMEI error,napi_status = " + std ::to_string(status));
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static napi_value GetIMEI(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchGetIMEIParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetIMEIContext>();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "GetIMEI", NativeGetIMEI, GetIMEICallback);
}

void NativeGetMEID(napi_env env, void *data)
{
    auto context = static_cast<GetMEIDContext *>(data);
    context->getMEIDResult =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetMeid(context->slotId));
    TELEPHONY_LOGI("NativeGetMEID context->slotId = %{public}d", context->slotId);
    context->resolved = true;
}

void GetMEIDCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetMEIDContext *>(data);
    napi_value callbackValue = nullptr;
    if (status == napi_ok) {
        if (context->resolved) {
            napi_create_string_utf8(
                env, context->getMEIDResult.c_str(), context->getMEIDResult.size(), &callbackValue);
        } else {
            callbackValue = NapiUtil::CreateErrorMessage(env, "getMEID error");
        }
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "getMEID error,napi_status = " + std ::to_string(status));
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static napi_value GetMEID(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchGetIMEIParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetMEIDContext>();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
            TELEPHONY_LOGI("NativeGetMEID context->slotId = %{public}d", asyncContext->slotId);
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(env, asyncContext.release(), "getMEID", NativeGetMEID, GetMEIDCallback);
}

static void NativeSendUpdateCellLocationRequest(napi_env env, void *data)
{
    auto asyncContext = static_cast<SendUpdateCellLocationRequest *>(data);
    asyncContext->sendRequest =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().SendUpdateCellLocationRequest(SIM_SLOT_0);
    TELEPHONY_LOGI("asyncContext->sendRequest = %{public}d", asyncContext->sendRequest);
    asyncContext->resolved = true;
    TELEPHONY_LOGI("NativeSendUpdateCellLocationRequest end");
}

static void SendUpdateCellLocationRequestCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("SendUpdateCellLocationRequestCallback start");
    auto asyncContext = static_cast<SendUpdateCellLocationRequest *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_get_undefined(env, &callbackValue);
    } else {
        callbackValue = ParseErrorValue(env, asyncContext->errorCode, "turn on radio");
    }
    NapiUtil::Handle1ValueCallback(env, asyncContext, callbackValue);
    TELEPHONY_LOGI("SendUpdateCellLocationRequestCallback end");
}

static napi_value SendUpdateCellLocationRequest(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[1] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchSwitchRadioParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SwitchRadioContext>();
    if (parameterCount == 1) {
        NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
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
    auto asyncContext = (CellInformationContext *)data;
    asyncContext->cellInformations =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCellInfoList(asyncContext->slotId);
    asyncContext->resolved = true;
}

void GetCellInformationCallback(napi_env env, napi_status status, void *data)
{
    TELEPHONY_LOGI("GetCellInformationCallback start");
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
            int32_t signalLevel = 0;
            CellInformation::CellType cellType = CellInformation::CellType::CELL_TYPE_NONE;
            if (infoItem != nullptr) {
                timeStamp = infoItem->GetTimeStamp();
                signalLevel = infoItem->GetSignalLevel();
                cellType = infoItem->GetNetworkType();
            }
            NapiUtil::SetPropertyInt32(env, info, "timeStamp", timeStamp);
            NapiUtil::SetPropertyInt32(env, info, "networkType", WrapCellInformationType(infoItem));
            napi_value signalInformation = nullptr;
            napi_create_object(env, &signalInformation);
            int32_t signalType = WrapCellInformationType(infoItem);
            NapiUtil::SetPropertyInt32(env, signalInformation, "signalType", signalType);
            NapiUtil::SetPropertyInt32(env, signalInformation, "signalLevel", signalLevel);
            std::string name = "signalInformation";
            napi_set_named_property(env, info, name.c_str(), signalInformation);
            napi_set_named_property(env, info, "data", JudgmentData(env, infoItem, cellType));
            napi_set_element(env, asyncContext->callbackValue, i, info);
            ++i;
        }
    } else {
        asyncContext->callbackValue = NapiUtil::CreateErrorMessage(env, " signalInformation err");
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, asyncContext->callbackValue);
    TELEPHONY_LOGI("GetCellInformationCallback end");
}

static napi_value GetCellInformation(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchGetNetworkStateParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = new CellInformationContext();
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
    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetCellInformation", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeGetCellInformation, GetCellInformationCallback,
            (void *)asyncContext, &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return result;
}

static void NativeGetPrimarySlotId(napi_env env, void *data)
{
    auto asyncContext = (GetPrimarySlotIdContext *)data;
    asyncContext->slotId = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPrimarySlotId();
    TELEPHONY_LOGI("GetPrimarySlotId  = %{public}d", asyncContext->slotId);
    asyncContext->resolved = (asyncContext->slotId >= 0);
}

void GetPrimarySlotIdCallback(napi_env env, napi_status status, void *data)
{
    auto asyncContext = static_cast<GetPrimarySlotIdContext *>(data);
    napi_value callbackValue = nullptr;
    if (asyncContext->resolved) {
        napi_create_int32(env, asyncContext->slotId, &callbackValue);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, " GetPrimarySlotI error");
    }
    NapiUtil::Handle2ValueCallback(env, asyncContext, callbackValue);
}

static napi_value GetPrimarySlotId(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 1;
    napi_value parameters[1] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchSwitchRadioParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SwitchRadioContext>();
    if (parameterCount == 1) {
        NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetPrimarySlotId", NativeGetPrimarySlotId, GetPrimarySlotIdCallback);
}

static void NativeGetUniqueDeviceId(napi_env env, void *data)
{
    auto context = static_cast<GetUniqueDeviceIdContext *>(data);
    context->getUniqueDeviceId =
        NapiUtil::ToUtf8(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetUniqueDeviceId(context->slotId));
    TELEPHONY_LOGI("NativeGetUniqueDeviceId len = %{public}d", context->getUniqueDeviceId.length());
    context->resolved = true;
}

void GetUniqueDeviceIdCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetUniqueDeviceIdContext *>(data);
    napi_value callbackValue = nullptr;
    if (status == napi_ok) {
        if (context->resolved) {
            napi_create_string_utf8(
                env, context->getUniqueDeviceId.c_str(), context->getUniqueDeviceId.size(), &callbackValue);
        } else {
            callbackValue = NapiUtil::CreateErrorMessage(env, "GetUniqueDeviceId error");
        }
    } else {
        callbackValue =
            NapiUtil::CreateErrorMessage(env, "GetUniqueDeviceId error,napi_status = " + std ::to_string(status));
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static napi_value GetUniqueDeviceId(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchGetIMEIParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetIMEIContext>();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
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
    context->nrOptionMode =
        WrapNrOptionMode(DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNrOptionMode(context->slotId));
    context->resolved = true;
    TELEPHONY_LOGI("NativeGetNrOptionMode nrOptionMode = %{public}d", context->nrOptionMode);
}

static void GetNrOptionModeCallback(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<GetNrOptionModeContext *>(data);
    TELEPHONY_LOGI("GetNrOptionModeCallback resolved = %{public}d", context->resolved);
    napi_value callbackValue = nullptr;
    if (status == napi_ok) {
        if (context->resolved) {
            napi_create_int32(env, context->nrOptionMode, &callbackValue);
        } else {
            if (context->errorCode == SLOTID_INPUT_ERROR) {
                callbackValue = ParseErrorValue(env, context->errorCode, "slotId input error");
            } else {
                callbackValue = ParseErrorValue(env, context->errorCode, "get nrOptionMode mode err");
            }
        }
    } else {
        callbackValue = ParseErrorValue(env, context->errorCode, "getNrOptionMod0 error");
    }
    NapiUtil::Handle2ValueCallback(env, context, callbackValue);
}

static napi_value GetNrOptionMode(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchGetNrOptionModeParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<GetNrOptionModeContext>();
    if (parameterCount == 0) {
        asyncContext->slotId = GetDefaultSlotId();
    } else if (parameterCount == 1) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valueType));
        if (valueType == napi_number) {
            NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        } else if (valueType == napi_function) {
            asyncContext->slotId = GetDefaultSlotId();
            NAPI_CALL(env, napi_create_reference(env, parameters[0], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
        }
    } else if (parameterCount == 2) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "GetNrOptionMode", NativeGetNrOptionMode, GetNrOptionModeCallback);
}

static napi_value IsNrSupported(napi_env env, napi_callback_info info)
{
    TELEPHONY_LOGI("IsNrSupported start!");
    size_t parameterCount = 1;
    napi_value parameters[1] = {0};
    void *data = nullptr;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    bool isNrSupported = false;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    NAPI_ASSERT(env, MatchIsNrSupportedParameter(env, parameters, parameterCount), "type mismatch");
    int32_t slotId = SIM_SLOT_0;
    if (parameterCount == 1) {
        NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &slotId));
    }
    if (slotId == SIM_SLOT_0) {
        isNrSupported = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsNrSupported(SIM_SLOT_0);
    } else if (slotId == SIM_SLOT_1) {
        isNrSupported = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsNrSupported(SIM_SLOT_1);
    }
    napi_get_boolean(env, isNrSupported, &result);
    return result;
}

static void NativeSetPrimarySlotId(napi_env env, void *data)
{
    auto context = static_cast<SetPrimarySlotIdContext *>(data);
    context->setResult = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetPrimarySlotId(context->slotId);
    TELEPHONY_LOGI("context->setResult = %{public}d", context->setResult);
    if (context->setResult == 1) {
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
        callbackValue = NapiUtil::CreateErrorMessage(env, "SetPrimarySlotId country code error");
    }
    NapiUtil::Handle1ValueCallback(env, context, callbackValue);
}

static napi_value SetPrimarySlotId(napi_env env, napi_callback_info info)
{
    size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar;
    void *data;
    napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data);
    NAPI_ASSERT(env, MatchGetISOCountryCodeForNetworkParameter(env, parameters, parameterCount), "type mismatch");
    auto asyncContext = std::make_unique<SetPrimarySlotIdContext>();
    NAPI_CALL(env, napi_get_value_int32(env, parameters[0], &asyncContext->slotId));
    if (parameterCount == 2) {
        NAPI_CALL(env, napi_create_reference(env, parameters[1], DEFAULT_REF_COUNT, &asyncContext->callbackRef));
    }
    return NapiUtil::HandleAsyncWork(
        env, asyncContext.release(), "SetPrimarySlotId", NativeSetPrimarySlotId, SetPrimarySlotIdCallback);
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
    napi_define_class(env, "RadioType", NAPI_AUTO_LENGTH, CreateEnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result);
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
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    InitEnumRadioType(env, exports);
    InitEnumNetworkType(env, exports);
    InitEnumRegStatus(env, exports);
    InitEnumNsaState(env, exports);
    InitEnumNetworkSelectionMode(env, exports);
    InitEnumNetworkInformationState(env, exports);
    InitEnumPreferredNetwork(env, exports);
    InitEnumNrOptionMode(env, exports);
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
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterRadioNetworkModule(void)
{
    napi_module_register(&_radioModule);
}
} // namespace Telephony
} // namespace OHOS
