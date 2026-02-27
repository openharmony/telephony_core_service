/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "start_manual_network_scan_callback.h"

#include "manual_network_scan_callback_manager.h"
#include "singleton.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
void NapiStartManualScanCallback::OnStartManualNetworkScanCallback(
    const sptr<NetworkSearchResult> &networkSearchResult, const bool isFinish, int32_t slotId)
{
    if (networkSearchResult == nullptr) {
        TELEPHONY_LOGE("networkSearchResult is null!");
        return;
    }
    auto manager = DelayedSingleton<ManualNetworkScanCallbackManager>::GetInstance();
    if (manager == nullptr) {
        TELEPHONY_LOGE("ManualNetworkScanCallbackManager is null!");
        return;
    }
    int32_t ret = manager->ReportManualScanInfo(slotId, networkSearchResult, isFinish);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("failed! errCode:%{public}d", ret);
    } else {
        TELEPHONY_LOGI("success! slotId:%{public}d", slotId);
    }
}
} // namespace Telephony
} // namespace OHOS