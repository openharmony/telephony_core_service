/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ani_reset_memory_callback.h"
#include "telephony_errors.h"

namespace OHOS {
using namespace Telephony;
namespace EsimAni {

AniResetMemoryCallback::AniResetMemoryCallback(AniAsyncResetMemory *context) : asyncContext_(context)
{}

void AniResetMemoryCallback::OnResetMemory(const int32_t &result, const int32_t errorCode)
{
    if (asyncContext_ == nullptr) {
        return;
    }

    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        asyncContext_->callbackVal = result;
    } else {
        asyncContext_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    asyncContext_->isCallbackEnd = true;
    asyncContext_->cv.notify_all();
}

} // namespace EsimAni
} // namespace OHOS