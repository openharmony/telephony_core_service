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

#include "manual_network_scan_callback_death_recipient.h"
#include "iremote_broker.h"
#include "manual_network_scan.h"

namespace OHOS {
namespace Telephony {

void ManualNetworkScanCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        TELEPHONY_LOGE("remote object is null");
        return;
    }
    auto manualNetworkScan = manualNetworkScan_.lock();
    if (manualNetworkScan == nullptr) {
        TELEPHONY_LOGE("manualNetworkScan is null");
        return;
    }
    sptr<IRemoteObject> remoteObj = remote.promote();
    sptr<INetworkSearchCallback> callback = iface_cast<INetworkSearchCallback>(remoteObj);
    if (callback == nullptr) {
        TELEPHONY_LOGE("OnRemoteDied iface_cast failed, remote is not INetworkSearchCallback");
        return;
    }
    manualNetworkScan->RemoveManualNetworkScanCallback(callback);
}
}
}