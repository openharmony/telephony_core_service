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

#include "set_preferred_network_callback.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SetPreferredNetworkCallback::SetPreferredNetworkCallback(PreferredNetworkModeContext *asyncContext)
    : asyncContext_(asyncContext)
{}

void SetPreferredNetworkCallback::OnSetPreferredNetworkCallback(const bool setResult, const int32_t errorCode)
{
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("OnSetPreferredNetworkCallback asyncContext null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    TELEPHONY_LOGI("OnSetPreferredNetworkModelCallback setResult = %{public}d , errorCode = %{public}d", setResult,
        errorCode);
    asyncContext_->resolved = (errorCode == HRIL_ERR_SUCCESS) && setResult;
    if (!asyncContext_->resolved) {
        if (errorCode == HRIL_ERR_SUCCESS) {
            asyncContext_->errorCode = HRIL_ERR_GENERIC_FAILURE;
        } else if (errorCode == SLOTID_INPUT_ERROR) {
            asyncContext_->errorCode = SLOTID_INPUT_ERROR;
        } else if (errorCode == ENUMERATION_INPUT_ERROR) {
            asyncContext_->errorCode = ENUMERATION_INPUT_ERROR;
        } else {
            asyncContext_->errorCode = errorCode;
        }
    }
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
    TELEPHONY_LOGI("OnSetPreferredNetworkModelCallback end");
}
} // namespace Telephony
} // namespace OHOS