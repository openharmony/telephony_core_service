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

#include "set_network_search_mode_callback.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SetNetworkSearchModeCallback::SetNetworkSearchModeCallback(SetSelectModeContext *asyncContext)
    : asyncContext_(asyncContext)
{}

void SetNetworkSearchModeCallback::OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode)
{
    TELEPHONY_LOGI("OnSetNetworkModeCallback setResult = %{public}d ,errorCode = %{public}d", setResult, errorCode);
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    asyncContext_->setResult = setResult;
    asyncContext_->errorCode = errorCode;
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
}
} // namespace Telephony
} // namespace OHOS