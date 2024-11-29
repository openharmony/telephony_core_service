/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "set_profile_nick_name_callback.h"
#include "esim_state_type.h"
#include "napi_esim.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SetProfileNickNameResultCallback::SetProfileNickNameResultCallback(AsyncProfileNickname *context)
    : asyncContext_(context)
{}

void SetProfileNickNameResultCallback::OnSetProfileNickName(const int32_t &result, const int32_t errorCode)
{
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("asyncContext null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->asyncContext.callbackMutex);
    asyncContext_->asyncContext.context.resolved = (errorCode == TELEPHONY_ERR_SUCCESS);
    if (asyncContext_->asyncContext.context.resolved) {
        asyncContext_->asyncContext.callbackVal = result;
    } else {
        asyncContext_->asyncContext.context.errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
        TELEPHONY_LOGE("errorCode = %{public}d", errorCode);
    }
    asyncContext_->asyncContext.isCallbackEnd = true;
    asyncContext_->asyncContext.cv.notify_all();
}
} // namespace Telephony
} // namespace OHOS