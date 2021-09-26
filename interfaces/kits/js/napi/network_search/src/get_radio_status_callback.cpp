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

#include "get_radio_status_callback.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
GetRadioStatusCallback::GetRadioStatusCallback(IsRadioOnContext *context) : asyncContext_(context) {}

void GetRadioStatusCallback::OnGetRadioStatusCallback(const bool isOn, const int32_t errorCode)
{
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("OnGetRadioStatusCallback context nullptr");
        return;
    }
    TELEPHONY_LOGD("OnGetRadioStatusCallback isOn = %{public}d", isOn);
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    asyncContext_->resolved = errorCode == HRIL_ERR_SUCCESS;
    if (asyncContext_->resolved) {
        asyncContext_->isRadioOn = isOn;
    } else {
        asyncContext_->errorCode = errorCode;
    }
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
    TELEPHONY_LOGD("OnGetRadioStatusCallback end");
}
} // namespace Telephony
} // namespace OHOS