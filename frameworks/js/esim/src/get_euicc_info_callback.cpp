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

#include "get_euicc_info_callback.h"

#include "napi_esim.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include <codecvt>
#include <locale>

namespace OHOS {
namespace Telephony {
GetEuiccInformationCallback::GetEuiccInformationCallback(AsyncEuiccInfo *context) : asyncContext_(context)
{}

void GetEuiccInformationCallback::OnGetEuiccInfo(const EuiccInfo &result, const int32_t errorCode)
{
    TELEPHONY_LOGI("start errorCode = %{public}d", errorCode);
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGI("asyncContext null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->asyncContext.callbackMutex);
    asyncContext_->asyncContext.context.resolved = (errorCode == TELEPHONY_ERR_SUCCESS);
    if (asyncContext_->asyncContext.context.resolved) {
        asyncContext_->result = result;
        std::string osVersion = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.to_bytes(result.osVersion_);
    } else {
        asyncContext_->asyncContext.context.errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    asyncContext_->asyncContext.callbackEnd = true;
    asyncContext_->asyncContext.cv.notify_all();
    TELEPHONY_LOGI("end");
}
} // namespace Telephony
} // namespace OHOS