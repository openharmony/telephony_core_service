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

#include "get_default_smdp_address_callback.h"

#include "esim_state_type.h"
#include "napi_esim.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
GetDefaultSmdpAddressResultCallback::GetDefaultSmdpAddressResultCallback(AsyncContext<std::string>  *context) : asyncContext_(context)
{}

void GetDefaultSmdpAddressResultCallback::OnGetDefaultSmdpAddress(const std::string &result, const int32_t errorCode)
{
    TELEPHONY_LOGI("start errorCode = %{public}d", errorCode);
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("asyncContext null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    asyncContext_->context.resolved = (errorCode == TELEPHONY_ERR_SUCCESS);
    if (asyncContext_->context.resolved) {
        asyncContext_->callbackVal = result;
    } else {
        asyncContext_->context.errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
    TELEPHONY_LOGD("end");
}
} // namespace Telephony
} // namespace OHOS