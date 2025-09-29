/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "network_search_callback.h"
#include "refbase.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

AniNetworkSearchCallback::AniNetworkSearchCallback(std::shared_ptr<AniCallbackContext> context)
    : context_(context)
{}

int32_t WrapNativeNetworkMode(int32_t nativeMode)
{
    if ((nativeMode >= static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_AUTO)) && (nativeMode <=
        static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA))) {
        return nativeMode;
    }
    return static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_AUTO);
}

void AniNetworkSearchCallback::OnGetPreferredNetworkCallback(const int32_t networkMode, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetPreferredNetworkCallback context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnGetPreferredNetworkCallback networkMode = %{public}d,errorCode = %{public}d", networkMode,
        errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = WrapNativeNetworkMode(networkMode);
    } else {
        context_->result = static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_AUTO);
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}

void AniNetworkSearchCallback::OnSetPreferredNetworkCallback(const bool setResult, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnSetPreferredNetworkCallback context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnSetPreferredNetworkCallback setResult = %{public}d , errorCode = %{public}d", setResult,
        errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = setResult;
    } else {
        context_->result = false;
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}

void AniNetworkSearchCallback::OnSetRadioStateCallback(const bool setResult, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnSetRadioStateCallback context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnSetRadioStateCallback setResult = %{public}d , errorCode = %{public}d", setResult, errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = setResult;
    } else {
        context_->result = false;
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}

void AniNetworkSearchCallback::OnGetRadioStateCallback(const bool isOn, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetRadioStateCallback context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnGetRadioStateCallback isOn = %{public}d , errorCode = %{public}d", isOn, errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = isOn;
    } else {
        context_->result = false;
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}

void AniNetworkSearchCallback::OnGetNetworkSearchInformation(const sptr<NetworkSearchResult> &networkSearchResult,
    const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetNetworkSearchInformation context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnGetNetworkSearchInformation  errorCode = %{public}d", errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = networkSearchResult;
    } else {
        context_->result = OHOS::sptr<NetworkSearchResult>::MakeSptr();
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}

void AniNetworkSearchCallback::OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnSetNetworkModeCallback context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnSetNetworkModeCallback setResult = %{public}d , errorCode = %{public}d", setResult, errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = setResult;
    } else {
        context_->result = false;
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}

void AniNetworkSearchCallback::OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetNetworkModeCallback context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnGetNetworkModeCallback get search mode = %{public}d , errorCode = %{public}d", searchModel,
        errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = searchModel;
    } else {
        context_->result = static_cast<int32_t>(SelectionMode::MODE_TYPE_UNKNOWN);
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}

void AniNetworkSearchCallback::OnGetNrOptionModeCallback(const int32_t mode, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetNrOptionModeCallback context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnGetNrOptionModeCallback get search mode = %{public}d , errorCode = %{public}d", mode, errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = mode;
    } else {
        context_->result = 0;
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}

void AniNetworkSearchCallback::OnSetNrOptionModeCallback(const bool setResult, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnSetNrOptionModeCallback context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    TELEPHONY_LOGI("OnSetNrOptionModeCallback set result = %{public}d , errorCode = %{public}d", setResult, errorCode);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->result = setResult;
    } else {
        context_->result = false;
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackComplete = true;
    context_->cv.notify_all();
}
} // namespace Telephony
} // namespace OHOS