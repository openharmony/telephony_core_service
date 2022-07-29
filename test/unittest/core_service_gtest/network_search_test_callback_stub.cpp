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

#include "network_search_test_callback_stub.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
int32_t NetworkSearchTestCallbackStub::GetNetworkModeCallbackResult() const
{
    return getNetworkModeResult_;
}

bool NetworkSearchTestCallbackStub::SetNetworkModeCallbackResult() const
{
    return setNetworkModeResult_;
}

bool NetworkSearchTestCallbackStub::SetRadioStateCallbackResult() const
{
    return setRadioStateResult_;
}

bool NetworkSearchTestCallbackStub::GetRadioStateCallbackResult() const
{
    return getRadioStateResult_;
}

bool NetworkSearchTestCallbackStub::GetNetworkSearchInformationCallbackResult() const
{
    return getNetworkSearchInformationResult_;
}

bool NetworkSearchTestCallbackStub::SetPreferredNetworkCallbackResult() const
{
    return setPreferredNetworkResult_;
}

bool NetworkSearchTestCallbackStub::GetPreferredNetworkCallbackResult() const
{
    return getPreferredNetworkResult_;
}

void NetworkSearchTestCallbackStub::WaitForGetNetworkModeCallback(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> callbackLock(getNetworkModeMutex_);
    getNetworkModeCv_.wait_for(callbackLock, std::chrono::seconds(timeoutSecond));
}

void NetworkSearchTestCallbackStub::WaitForSetNetworkModeCallback(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> callbackLock(setNetworkModeMutex_);
    setNetworkModeCv_.wait_for(callbackLock, std::chrono::seconds(timeoutSecond));
}

void NetworkSearchTestCallbackStub::WaitForSetRadioStateCallback(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> callbackLock(setRadioStateMutex_);
    setRadioStateCv_.wait_for(callbackLock, std::chrono::seconds(timeoutSecond));
}

void NetworkSearchTestCallbackStub::WaitForGetRadioStateCallback(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> callbackLock(getRadioStateMutex_);
    getRadioStateCv_.wait_for(callbackLock, std::chrono::seconds(timeoutSecond));
}

void NetworkSearchTestCallbackStub::WaitForGetNetworkSearchInformationCallback(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> callbackLock(getNetworkSearchInformationMutex_);
    getNetworkSearchInformationCv_.wait_for(callbackLock, std::chrono::seconds(timeoutSecond));
}

void NetworkSearchTestCallbackStub::WaitForSetPreferredNetworkCallback(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> callbackLock(setPreferredNetworkMutex_);
    setPreferredNetworkCv_.wait_for(callbackLock, std::chrono::seconds(timeoutSecond));
}

void NetworkSearchTestCallbackStub::WaitForGetPreferredNetworkCallback(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> callbackLock(getPreferredNetworkMutex_);
    getPreferredNetworkCv_.wait_for(callbackLock, std::chrono::seconds(timeoutSecond));
}

void NetworkSearchTestCallbackStub::OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode)
{
    TELEPHONY_LOGI("NetworkSearchTestCallbackStub OnGetNetworkModeCallback success mode:%{public}d, error:%{public}d",
        searchModel, errorCode);
    getNetworkModeResult_ = searchModel;
    getNetworkModeCv_.notify_all();
}

void NetworkSearchTestCallbackStub::OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode)
{
    TELEPHONY_LOGI("NetworkSearchTestCallbackStub OnSetNetworkModeCallback success result:%{public}d, error:%{public}d",
        setResult, errorCode);
    setNetworkModeResult_ = (TELEPHONY_SUCCESS == errorCode);
    setNetworkModeCv_.notify_all();
}

void NetworkSearchTestCallbackStub::OnSetRadioStateCallback(const bool setResult, const int32_t errorCode)
{
    TELEPHONY_LOGI("NetworkSearchTestCallbackStub OnSetRadioStateCallback success result:%{public}d, error:%{public}d",
        setResult, errorCode);
    setRadioStateResult_ = (TELEPHONY_SUCCESS == errorCode);
    setRadioStateCv_.notify_all();
}

void NetworkSearchTestCallbackStub::OnGetRadioStateCallback(const bool isRadioOn, const int32_t errorCode)
{
    TELEPHONY_LOGI("NetworkSearchTestCallbackStub OnGetRadioStateCallback success "
        "isRadioOn:%{public}d, error:%{public}d", isRadioOn, errorCode);
    getRadioStateResult_ = isRadioOn;
    getRadioStateCv_.notify_all();
}

void NetworkSearchTestCallbackStub::OnGetNetworkSearchInformation(
    const sptr<NetworkSearchResult> &nsResult, const int32_t errorCode)
{
    TELEPHONY_LOGI("NetworkSearchTestCallbackStub OnGetNetworkSearchInformation success error:%{public}d", errorCode);
    getNetworkSearchInformationResult_ = (TELEPHONY_SUCCESS == errorCode);
    getNetworkSearchInformationCv_.notify_all();
}

void NetworkSearchTestCallbackStub::OnSetPreferredNetworkCallback(const bool result, const int32_t errorCode)
{
    TELEPHONY_LOGI("NetworkSearchTestCallbackStub OnSetPreferredNetworkCallback success "
        "result:%{public}d, errorCode:%{public}d", result, errorCode);
    setPreferredNetworkResult_ = (TELEPHONY_SUCCESS == errorCode);
    setPreferredNetworkCv_.notify_all();
}

void NetworkSearchTestCallbackStub::OnGetPreferredNetworkCallback(const int32_t networkMode, const int32_t errorCode)
{
    TELEPHONY_LOGI("NetworkSearchTestCallbackStub OnGetPreferredNetworkCallback success "
        "result:%{public}d, error:%{public}d", networkMode, errorCode);
    getPreferredNetworkResult_ = (TELEPHONY_SUCCESS == errorCode);
    getPreferredNetworkCv_.notify_all();
}
} // namespace Telephony
} // namespace OHOS