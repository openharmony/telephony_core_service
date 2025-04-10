/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "get_nr_option_mode_callback.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_napi_hril_error_code.h"

namespace OHOS {
namespace Telephony {
GetNrOptionModeCallback::GetNrOptionModeCallback(NrOptionModeContext *asyncContext) : asyncContext_(asyncContext) {}

void GetNrOptionModeCallback::OnGetNrOptionModeCallback(const int32_t mode, const int32_t errorCode)
{
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("asyncContext is null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    TELEPHONY_LOGI("mode = %{public}d", mode);
    asyncContext_->resolved = errorCode == HRIL_ERR_SUCCESS;
    if (asyncContext_->resolved) {
        asyncContext_->nrOptionMode = mode;
    } else {
        asyncContext_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
    TELEPHONY_LOGI("end");
}
} // namespace Telephony
} // namespace OHOS
