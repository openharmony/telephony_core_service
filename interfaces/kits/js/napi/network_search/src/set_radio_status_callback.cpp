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

#include "set_radio_status_callback.h"

#include "telephony_napi_hril_error_code.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SetRadioStatusCallback::SetRadioStatusCallback(SwitchRadioContext *context) : asyncContext_(context) {}

void SetRadioStatusCallback::OnSetRadioStatusCallback(const bool setResult, const int32_t errorCode)
{
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    TELEPHONY_LOGD("OnSetRadioStatusCallback setResult = %{public}d", setResult);
    asyncContext_->resolved = setResult;
    asyncContext_->errorCode = errorCode;
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
    TELEPHONY_LOGD("OnSetRadioStatusCallback end");
}
} // namespace Telephony
} // namespace OHOS