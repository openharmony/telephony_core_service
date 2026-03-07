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

#ifndef MANUAL_NETWORK_SCAN_H
#define MANUAL_NETWORK_SCAN_H

#include "network_search_manager.h"

namespace OHOS {
namespace Telephony {
class ManualNetworkScan : public std::enable_shared_from_this<ManualNetworkScan> {
    DECLARE_DELAYED_SINGLETON(ManualNetworkScan);
public:
    void InitManagerPointer(const std::weak_ptr<NetworkSearchManager> &networkSearchManager);
    int32_t GetManualNetworkScanState(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t StartManualNetworkScanCallback(int32_t slotId, const sptr<INetworkSearchCallback> &callback);
    int32_t StopManualNetworkScanCallback(int32_t slotId);
    void NotifyManualScanStateChanged(
        int32_t slotId, bool isFinish, const sptr<NetworkSearchResult> &networkSearchResult);
    int32_t RemoveManualNetworkScanCallback(const sptr<INetworkSearchCallback> &callback);

private:
    struct ManualScanCallbackRecord {
        int32_t slotId;
        sptr<INetworkSearchCallback> callback;
        sptr<IRemoteObject::DeathRecipient> deathRecipient;
    };

    std::list<ManualScanCallbackRecord> listManualScanCallbackRecord_;
    std::mutex mutexScan_;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;

};
} // namespace Telephony
} // namespace OHOS

#endif // MANUAL_NETWORK_SCAN_H