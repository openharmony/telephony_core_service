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

#ifndef MANUAL_NETWORK_SCAN_CALLBACK_MANAGER_H
#define MANUAL_NETWORK_SCAN_CALLBACK_MANAGER_H

#include <cstdint>
#include <uv.h>

#include "napi_radio.h"

namespace OHOS {
namespace Telephony {
class ManualNetworkScanCallbackManager {
public:
    int32_t StartManualNetworkScanCallback(StartManualScanCallback &stateCallback);
    int32_t StopManualNetworkScanCallback(napi_env env, int32_t slotId);
    int32_t ReportManualScanInfo(int32_t slotId, const sptr<NetworkSearchResult> &networkSearchResult,
        const bool isFinish);

private:
    int32_t ReportManualScanInfoInner(const StartManualScanCallback &stateCallback,
        const sptr<NetworkSearchResult> &networkSearchResult, const bool isFinish);
    int32_t InsertStartManualScanCallback(int32_t slotId, StartManualScanCallback &stateCallback);
    void RemoveStartManualScanCallback(int32_t slotId);
    static int32_t ReportManualScanInfo(const sptr<NetworkSearchResult> &networkSearchResult, const bool isFinish,
        const StartManualScanCallback &stateCallback);

private:
    std::list<StartManualScanCallback> listStartManualScanCallback_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // MANUAL_NETWORK_SCAN_CALLBACK_MANAGER_H