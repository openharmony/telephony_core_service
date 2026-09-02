/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "manual_network_scan_callback.h"
#include "napi_util.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

static constexpr struct {
    int32_t type;
    const char *name;
} RADIO_TECH_NAMES[] = {
    { 0,  "GSM" },
    { 2,  "WCDMA" },
    { 7,  "LTE" },
    { 12, "NR" },
};

static constexpr int32_t RADIO_TECH_COUNT =
    sizeof(RADIO_TECH_NAMES) / sizeof(RADIO_TECH_NAMES[0]);

static inline const char *LookupRadioTech(int32_t radioType)
{
    for (int32_t i = 0; i < RADIO_TECH_COUNT; i++) {
        if (RADIO_TECH_NAMES[i].type == radioType) {
            return RADIO_TECH_NAMES[i].name;
        }
    }
    return "";
}

bool ManualNetworkScanCallback::CreateNapiCbRef(napi_env env, napi_value thisVar, napi_value argv[])
{
    cbEnv_ = env;
    if (napi_create_reference(cbEnv_, thisVar, 1, &cbThis_) != napi_ok) {
        return false;
    }
    if (napi_create_reference(cbEnv_, argv[ARRAY_INDEX_SECOND], 1, &cbFunc_) != napi_ok) {
        napi_delete_reference(cbEnv_, cbThis_);
        return false;
    }
    return true;
}

void ManualNetworkScanCallback::DestroyNapiCbRef(napi_env env, napi_ref thisRef, napi_ref funcRef)
{
    if (env == nullptr) {
        return;
    }
    if (thisRef != nullptr) {
        napi_delete_reference(env, thisRef);
    }
    if (funcRef != nullptr) {
        napi_delete_reference(env, funcRef);
    }
}

void ManualNetworkScanCallback::OnGetManualNetworkScanStateCallback(const bool isScanning, const int32_t errorCode)
{
    IsManualScanningContext *asyncContext = GetScanContext();
    if (asyncContext == nullptr) {
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
    asyncContext->resolved = (errorCode == HRIL_ERR_SUCCESS);
    if (asyncContext->resolved) {
        asyncContext->isManualScanning = isScanning;
    } else {
        asyncContext->errorCode = errorCode;
    }
    asyncContext->callbackEnd = true;
    asyncContext->cv.notify_one();
}

void ManualNetworkScanCallback::ReportManualScanInfo(napi_env env, napi_ref thisRef, napi_ref funcRef,
    const sptr<NetworkSearchResult> &networkSearchResult, bool isFinish)
{
    napi_handle_scope scope = nullptr;
    napi_status status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        return;
    }
    napi_value callbackValue = CreateCallbackObject(env);
    if (callbackValue == nullptr) {
        napi_close_handle_scope(env, scope);
        return;
    }
    napi_value searchResultArray = CreateSearchResultArray(env, networkSearchResult);
    if (searchResultArray == nullptr) {
        napi_close_handle_scope(env, scope);
        return;
    }
    status = SetCallbackProperties(env, callbackValue, searchResultArray, isFinish);
    if (status != napi_ok) {
        napi_close_handle_scope(env, scope);
        return;
    }
    status = CallJavaScriptCallback(env, thisRef, funcRef, callbackValue);
    if (status != napi_ok) {
        napi_close_handle_scope(env, scope);
        return;
    }
    napi_close_handle_scope(env, scope);
}

napi_value ManualNetworkScanCallback::CreateCallbackObject(napi_env env)
{
    napi_value callbackValue = nullptr;
    napi_status status = napi_create_object(env, &callbackValue);
    if (status != napi_ok || callbackValue == nullptr) {
        return nullptr;
    }
    return callbackValue;
}

napi_value ManualNetworkScanCallback::CreateSearchResultArray(napi_env env,
    const sptr<NetworkSearchResult> &networkSearchResult)
{
    napi_value searchResultArray = nullptr;
    napi_status status = napi_create_array(env, &searchResultArray);
    if (status != napi_ok || searchResultArray == nullptr) {
        return nullptr;
    }
    if (networkSearchResult == nullptr) {
        return nullptr;
    }
    std::vector<NetworkInformation> resultList = networkSearchResult->GetNetworkSearchInformation();
    int32_t resultListSize = static_cast<int32_t>(resultList.size());
    for (int32_t i = 0; i < resultListSize; i++) {
        napi_value info = nullptr;
        status = napi_create_object(env, &info);
        if (status != napi_ok || info == nullptr) {
            return nullptr;
        }
        NapiUtil::SetPropertyStringUtf8(env, info, "operatorName", resultList[i].GetOperatorLongName());
        NapiUtil::SetPropertyStringUtf8(env, info, "operatorNumeric", resultList[i].GetOperatorNumeric());
        NapiUtil::SetPropertyInt32(env, info, "state", resultList[i].GetNetworkState());
        int32_t radioType = resultList[i].GetRadioTech();
        const char *techName = LookupRadioTech(radioType);
        NapiUtil::SetPropertyStringUtf8(env, info, "radioTech", techName);
        status = napi_set_element(env, searchResultArray, i, info);
        if (status != napi_ok) {
            return nullptr;
        }
    }
    return searchResultArray;
}

napi_status ManualNetworkScanCallback::SetCallbackProperties(napi_env env, napi_value callbackValue,
    napi_value searchResultArray, bool isFinish)
{
    napi_status status = napi_set_named_property(env, callbackValue, "networkInfos", searchResultArray);
    if (status != napi_ok) {
        return status;
    }
    NapiUtil::SetPropertyBoolean(env, callbackValue, "isFinish", isFinish);
    return napi_ok;
}

napi_status ManualNetworkScanCallback::CallJavaScriptCallback(napi_env env, napi_ref thisRef, napi_ref funcRef,
    napi_value callbackValue)
{
    napi_value thisVar = nullptr;
    napi_status status = napi_get_reference_value(env, thisRef, &thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        return status;
    }
    napi_value callbackFunc = nullptr;
    status = napi_get_reference_value(env, funcRef, &callbackFunc);
    if (status != napi_ok || callbackFunc == nullptr) {
        return status;
    }
    napi_value callbackResult = nullptr;
    napi_value invokeArgs[] = { callbackValue };
    status = napi_call_function(env, thisVar, callbackFunc, 1, invokeArgs, &callbackResult);
    if (status != napi_ok) {
        return status;
    }
    return status;
}

void ManualNetworkScanCallback::OnStartManualNetworkScanCallback(
    const sptr<NetworkSearchResult> &networkSearchResult, const bool isFinish, int32_t slotId)
{
    if (networkSearchResult == nullptr) {
        return;
    }
    if (cbEnv_ == nullptr || cbThis_ == nullptr || cbFunc_ == nullptr) {
        return;
    }
    napi_env env = cbEnv_;
    napi_ref thisRef = cbThis_;
    napi_ref funcRef = cbFunc_;
    auto task = [env, thisRef, funcRef, networkSearchResult, isFinish]() {
        ReportManualScanInfo(env, thisRef, funcRef, networkSearchResult, isFinish);
        if (isFinish) {
            DestroyNapiCbRef(env, thisRef, funcRef);
        }
    };
    napi_send_event(env, task, napi_eprio_immediate);
    if (isFinish) {
        cbThis_ = nullptr;
        cbFunc_ = nullptr;
    }
}

} // namespace Telephony
} // namespace OHOS
