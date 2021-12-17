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

#include "set_radio_state_callback.h"

#include "telephony_napi_hril_error_code.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SetRadioStateCallback::SetRadioStateCallback(SwitchRadioContext *context) : asyncContext_(context) {}

void SetRadioStateCallback::OnSetRadioStateCallback(const bool setResult, const int32_t errorCode)
{
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("OnSetRadioStateCallback asyncContext null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    TELEPHONY_LOGI("OnSetRadioStateCallback setResult = %{public}d", setResult);
    asyncContext_->resolved = (errorCode == HRIL_ERR_REPEAT_STATUS) ||
        ((errorCode == HRIL_ERR_SUCCESS) && setResult);
    if (!asyncContext_->resolved) {
        asyncContext_->errorCode = errorCode;
    }
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
    TELEPHONY_LOGI("OnSetRadioStateCallback end");
}
} // namespace Telephony
} // namespace OHOS