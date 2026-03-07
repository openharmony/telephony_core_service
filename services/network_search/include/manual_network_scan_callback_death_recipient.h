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

#ifndef MANUAL_NETWORK_SCAN_CALLBACK_DEATH_RECIPIENT_H
#define MANUAL_NETWORK_SCAN_CALLBACK_DEATH_RECIPIENT_H

#include "iremote_broker.h"
#include "manual_network_scan.h"

namespace OHOS {
namespace Telephony {
class ManualNetworkScanCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit ManualNetworkScanCallbackDeathRecipient(const std::weak_ptr<ManualNetworkScan> &manualNetworkScan)
        : manualNetworkScan_(manualNetworkScan) {};
    ~ManualNetworkScanCallbackDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    std::weak_ptr<ManualNetworkScan> manualNetworkScan_;
};
} // namespace Telephony
} // namespace OHOS
#endif // MANUAL_NETWORK_SCAN_CALLBACK_DEATH_RECIPIENT_H