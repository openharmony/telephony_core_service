/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "telephony_radio_callback.h"

namespace OHOS {
namespace Telephony {
GetNetworkSearchModeCallback::GetNetworkSearchModeCallback(GetSelectModeContext *asyncContext)
    : asyncContext_(asyncContext)
{}

int32_t WrapNetworkSelectionMode(int32_t mode)
{
    switch (mode) {
        case NATIVE_NETWORK_SELECTION_AUTOMATIC:
            return NETWORK_SELECTION_AUTOMATIC;
        case NATIVE_NETWORK_SELECTION_MANUAL:
            return NETWORK_SELECTION_MANUAL;
        default:
            return NETWORK_SELECTION_UNKNOWN;
    }
}

void GetNetworkSearchModeCallback::OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode)
{
    TELEPHONY_LOGD("OnGetNetworkModeCallback searchModel = %{public}d", searchModel);
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("OnGetNetworkModeCallback asyncContext null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    asyncContext_->resolved = errorCode == TELEPHONY_ERR_SUCCESS;
    if (asyncContext_->resolved) {
        asyncContext_->selectMode = WrapNetworkSelectionMode(searchModel);
    } else {
        asyncContext_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
}

GetRadioStateCallback::GetRadioStateCallback(IsRadioOnContext *context)
    : asyncContext_(context)
{}

void GetRadioStateCallback::OnGetRadioStateCallback(const bool isOn, const int32_t errorCode)
{
    TELEPHONY_LOGD("OnGetRadioStateCallback isOn = %{public}d", isOn);
    if (asyncContext_ == nullptr) {
        TELEPHONY_LOGE("OnGetRadioStateCallback asyncContext null");
        return;
    }
    std::unique_lock<std::mutex> callbackLock(asyncContext_->callbackMutex);
    asyncContext_->resolved = errorCode == TELEPHONY_ERR_SUCCESS;
    if (asyncContext_->resolved) {
        asyncContext_->isRadioOn = isOn;
    } else {
        asyncContext_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    asyncContext_->callbackEnd = true;
    asyncContext_->cv.notify_all();
    TELEPHONY_LOGD("OnGetRadioStateCallback end");
}
} // namespace Telephony
} // namespace OHOS