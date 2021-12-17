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

#include "get_preferred_network_callback.h"

#include "napi_radio.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
GetPreferredNetworkCallback::GetPreferredNetworkCallback(PreferredNetworkModeContext *asyncContext)
    : asyncContext_(asyncContext)
{}

int32_t WrapNativeNetworkMode(int32_t nativeMode)
{
    if ((nativeMode >= PREFERRED_NETWORK_MODE_AUTO) && (nativeMode <= PREFERRED_NETWORK_MODE_WCDMA_GSM)) {
        return nativeMode;
    }
    return PREFERRED_NETWORK_MODE_AUTO;
}

void GetPreferredNetworkCallback::OnGetPreferredNetworkCallback(const int32_t networkMode, const int32_t errorCode)
{
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("OnGetPreferredNetworkCallback asyncContext null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    TELEPHONY_LOGI("OnGetPreferredNetworkModelCallback networkMode = %{public}d,errorCode = %{public}d",
        networkMode, errorCode);
    asyncContext_->resolved = (errorCode == HRIL_ERR_SUCCESS) && (asyncContext_->errorCode != SLOTID_INPUT_ERROR);
    if (asyncContext_->resolved) {
        asyncContext_->preferredNetworkMode = WrapNativeNetworkMode(networkMode);
    } else if (asyncContext_->errorCode == SLOTID_INPUT_ERROR) {
        asyncContext_->errorCode = SLOTID_INPUT_ERROR;
    } else {
        asyncContext_->errorCode = errorCode;
    }
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
    TELEPHONY_LOGI("OnGetPreferredNetworkModelCallback end");
}
} // namespace Telephony
} // namespace OHOS