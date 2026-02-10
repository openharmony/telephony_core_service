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
#include "manual_network_scan_callback_manager.h"

#include "core_service_client.h"
#include "napi_util.h"
#include "singleton.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "start_manual_network_scan_callback.h"

namespace OHOS {
namespace Telephony {
int32_t ManualNetworkScanCallbackManager::StartManualNetworkScanCallback(StartManualScanCallback &stateCallback)
{
    int32_t slotId = stateCallback.slotId;
    stateCallback.callback = new NapiStartManualScanCallback();
    if (stateCallback.callback == nullptr) {
        TELEPHONY_LOGE("[slot%{public}d] Creat callback failed", slotId);
        return TELEPHONY_ERR_REGISTER_CALLBACK_FAIL;
    }
    InsertStartManualScanCallback(slotId, stateCallback);
    int32_t ret = DelayedRefSingleton<CoreServiceClient>::GetInstance().StartManualNetworkScanCallback(
        slotId, stateCallback.callback);
    if (ret == TELEPHONY_SUCCESS) {
        TELEPHONY_LOGI("[slot%{public}d] startManualNetworkScan successfully", slotId);
    } else {
        if (stateCallback.callback != nullptr) {
            stateCallback.callback = nullptr;
        }
        RemoveStartManualScanCallback(slotId);
        TELEPHONY_LOGE("[slot%{public}d] startManualNetworkScan failed, ret %{public}d", slotId, ret);
    }
    return ret;
}

int32_t ManualNetworkScanCallbackManager::StopManualNetworkScanCallback(napi_env env, int32_t slotId)
{
    int32_t ret = TELEPHONY_SUCCESS;
    RemoveStartManualScanCallback(slotId);
    ret = DelayedRefSingleton<CoreServiceClient>::GetInstance().StopManualNetworkScanCallback(slotId);
    return ret;
}

void ManualNetworkScanCallbackManager::InsertStartManualScanCallback(int32_t slotId,
    const StartManualScanCallback &stateCallback)
{
    std::unique_lock<ffrt::mutex> lock(mutex_);
    for (auto iter = listStartManualScanCallback_.begin(); iter != listStartManualScanCallback_.end();) {
        if (iter->slotId == slotId) {
            iter = listStartManualScanCallback_.erase(iter);
        } else {
            ++iter;
        }
    }
    listStartManualScanCallback_.push_back(stateCallback);
}

void ManualNetworkScanCallbackManager::RemoveStartManualScanCallback(int32_t slotId)
{
    std::unique_lock<ffrt::mutex> lock(mutex_);
    auto iter = listStartManualScanCallback_.begin();
    for (; iter != listStartManualScanCallback_.end(); ++iter) {
        if (iter->slotId == slotId) {
            if (iter->callback != nullptr) {
                iter->callback = nullptr;
            }
            listStartManualScanCallback_.erase(iter);
            break;
        }
    }
}

int32_t ManualNetworkScanCallbackManager::ReportManualScanInfo(int32_t slotId,
    const sptr<NetworkSearchResult> &networkSearchResult, const bool isFinish)
{
    int32_t ret = TELEPHONY_ERROR;
    std::unique_lock<ffrt::mutex> lock(mutex_);
    for (auto iter : listStartManualScanCallback_) {
        if (iter.slotId == slotId) {
            ret = ReportManualScanInfoInner(iter, networkSearchResult, isFinish);
            break;
        }
    }
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("[slot%{public}d] Report startManualNetworkScan callback failed, ret %{public}d", slotId, ret);
        return ret;
    }
    return ret;
}

int32_t ManualNetworkScanCallbackManager::ReportManualScanInfoInner(const StartManualScanCallback &stateCallback,
    const sptr<NetworkSearchResult> &networkSearchResult, const bool isFinish)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(stateCallback.env, &loop);
    if (loop == nullptr) {
        TELEPHONY_LOGE("stateCallback.env is null");
        return TELEPHONY_ERROR;
    }
    auto task = [stateCallback = stateCallback, networkSearchResult, isFinish]() {
        int32_t ret = ReportManualScanInfo(networkSearchResult, isFinish, stateCallback);
        if (ret != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("ReportManualScanInfo failed, result: %{public}d", ret);
            return;
        }
        TELEPHONY_LOGI("ReportManualScanInfo successfully");
    };
    int32_t resultCode = napi_send_event(stateCallback.env, task, napi_eprio_immediate);
    if (resultCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ReportManualScanInfo failed, result: %{public}d", resultCode);
        return TELEPHONY_ERROR;
    }
    return TELEPHONY_SUCCESS;
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
        case NetworkRat::NETWORK_NR: {
            return "NR";
        }
        default: {
            return "";
        }
    }
}

int32_t ManualNetworkScanCallbackManager::ReportManualScanInfo(const sptr<NetworkSearchResult> &networkSearchResult,
    const bool isFinish, const StartManualScanCallback &stateCallback)
{
    napi_env env = stateCallback.env;
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        TELEPHONY_LOGE("scope is nullptr");
        return TELEPHONY_ERROR;
    }
    napi_value callbackValues[CALLBACK_VALUES_SIZE] = { 0 };
    napi_create_object(env, &callbackValues[0]);
    napi_value searchResultArray = nullptr;
    napi_create_array(env, &searchResultArray);
    std::vector<NetworkInformation> resultList = networkSearchResult->GetNetworkSearchInformation();
    int32_t resultListSize = static_cast<int32_t>(resultList.size());
    for (int32_t i = 0; i < resultListSize; i++) {
        napi_value info = nullptr;
        napi_create_object(env, &info);
        NapiUtil::SetPropertyStringUtf8(env, info, "operatorName", resultList[i].GetOperatorLongName());
        NapiUtil::SetPropertyStringUtf8(env, info, "operatorNumeric", resultList[i].GetOperatorNumeric());
        NapiUtil::SetPropertyInt32(env, info, "state", WrapToJsPlmnState(resultList[i].GetNetworkState()));
        NapiUtil::SetPropertyStringUtf8(env, info, "radioTech", GetRadioTechName(resultList[i].GetRadioTech()));
        napi_set_element(env, searchResultArray, i, info);
    }
    napi_set_named_property(env, callbackValues[0], "networkInfos", searchResultArray);
    NapiUtil::SetPropertyBoolean(env, callbackValues[0], "isFinish", isFinish);
    napi_value thisVar = nullptr;
    napi_get_reference_value(env, stateCallback.thisVar, &thisVar);
    napi_value callbackFunc = nullptr;
    napi_get_reference_value(env, stateCallback.callbackRef, &callbackFunc);
    if (callbackFunc == nullptr) {
        TELEPHONY_LOGE("callbackFunc is nullptr!");
        napi_close_handle_scope(env, scope);
        return TELEPHONY_ERROR;
    }
    napi_value callbackResult = nullptr;
    napi_status ret =
        napi_call_function(env, thisVar, callbackFunc, std::size(callbackValues), callbackValues, &callbackResult);
    if (ret != napi_status::napi_ok) {
        TELEPHONY_LOGE("napi_call_function failed!");
        napi_close_handle_scope(env, scope);
        return TELEPHONY_ERROR;
    }
    napi_close_handle_scope(env, scope);
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS