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

#include "manual_network_scan.h"
#include "manual_network_scan_callback_death_recipient.h"

namespace OHOS {
namespace Telephony {
ManualNetworkScan::ManualNetworkScan() {};

ManualNetworkScan::~ManualNetworkScan() {};

void ManualNetworkScan::InitManagerPointer(const std::weak_ptr<NetworkSearchManager> &networkSearchManager)
{
    networkSearchManager_ = networkSearchManager;
}

int32_t ManualNetworkScan::GetManualNetworkScanState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("ManualNetworkScan::GetManualNetworkScanState callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    auto nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("ManualNetworkScan::GetManualNetworkScanState nsm is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    bool isScanning = nsm->GetManualNetworkScanState();
    MessageParcel data;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (!data.WriteBool(isScanning) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
        TELEPHONY_LOGE("GetManualNetworkScanState fail slotId:%{public}d", slotId);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    callback->OnNetworkSearchCallback(
        INetworkSearchCallback::NetworkSearchCallback::GET_MANUAL_NETWORK_SCAN_STATUS_RESULT, data);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t ManualNetworkScan::StartManualNetworkScanCallback(int32_t slotId,
    const sptr<INetworkSearchCallback> &callback)
{
    auto nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("ManualNetworkScan::StartManualNetworkScanCallback nsm is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret = nsm->ManualNetworkScanState(slotId, true);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        return ret;
    }
    std::lock_guard<std::mutex> lock(mutexScan_);
    for (auto iter = listManualScanCallbackRecord_.begin(); iter != listManualScanCallbackRecord_.end();) {
        if (iter->slotId == slotId) {
            if (iter->callback != nullptr && iter->callback->AsObject() != nullptr && iter->deathRecipient != nullptr) {
                auto remoteObj = iter->callback->AsObject();
                remoteObj->RemoveDeathRecipient(iter->deathRecipient);
            }
            iter = listManualScanCallbackRecord_.erase(iter);
        } else {
            ++iter;
        }
    }
    ManualScanCallbackRecord scanRecord;
    scanRecord.slotId = slotId;
    scanRecord.callback = callback;
    scanRecord.deathRecipient = sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) ManualNetworkScanCallbackDeathRecipient(shared_from_this()));
    if (scanRecord.deathRecipient == nullptr || callback == nullptr || callback->AsObject() == nullptr) {
        TELEPHONY_LOGE("deathRecipient or callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (!callback->AsObject()->AddDeathRecipient(scanRecord.deathRecipient)) {
        TELEPHONY_LOGE("callback remote server add death recipient failed");
        return TELEPHONY_ERR_ADD_DEATH_RECIPIENT_FAIL;
    }
    listManualScanCallbackRecord_.push_back(scanRecord);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t ManualNetworkScan::StopManualNetworkScanCallback(int32_t slotId)
{
    auto nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("ManualNetworkScan::StopManualNetworkScanCallback nsm is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (nsm->GetManualNetworkScanState()) {
        nsm->ManualNetworkScanState(slotId, false);
    }

    return TELEPHONY_ERR_SUCCESS;
}

void ManualNetworkScan::NotifyManualScanStateChanged(int32_t slotId, bool isFinish,
    const sptr<NetworkSearchResult> &networkSearchResult)
{
    std::lock_guard<std::mutex> lock(mutexScan_);
    for (auto iter = listManualScanCallbackRecord_.begin(); iter != listManualScanCallbackRecord_.end();) {
        if (iter->slotId == slotId) {
            if (iter->callback == nullptr) {
                TELEPHONY_LOGE("callback is nullptr from listManualScanCallbackRecord_");
                iter = listManualScanCallbackRecord_.erase(iter);
                continue;
            }
            MessageParcel data;
            data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
            networkSearchResult->Marshalling(data);
            if (!data.WriteBool(isFinish) || !data.WriteInt32(slotId)) {
                TELEPHONY_LOGE("NotifyManualScanStateChanged fail slotId:%{public}d", slotId);
                return;
            }
            iter->callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::START_MANUAL_NETWORK_SCAN_STATUS_RESULT, data);

            if (isFinish) {
                iter = listManualScanCallbackRecord_.erase(iter);
                continue;
            }
        }
        ++iter;
    }
}

int32_t ManualNetworkScan::RemoveManualNetworkScanCallback(const sptr<INetworkSearchCallback> &callback)
{
    if (callback == nullptr || callback->AsObject() == nullptr) {
        TELEPHONY_LOGE("callback is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::lock_guard<std::mutex> lock(mutexScan_);
    for (auto iter = listManualScanCallbackRecord_.begin(); iter != listManualScanCallbackRecord_.end();) {
        if (iter->callback == nullptr || iter->callback->AsObject() == nullptr) {
            ++iter;
            continue;
        }
        auto remoteObj = iter->callback->AsObject();
        if (remoteObj.GetRefPtr() == callback->AsObject().GetRefPtr() && iter->deathRecipient != nullptr) {
            remoteObj->RemoveDeathRecipient(iter->deathRecipient);
            iter = listManualScanCallbackRecord_.erase(iter);
        } else {
            ++iter;
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}
}
}