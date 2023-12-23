/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "network_type.h"

#include "network_search_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkType::NetworkType(const std::weak_ptr<NetworkSearchManager> &networkSearchManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), slotId_(slotId)
{}

void NetworkType::ProcessGetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork event is nullptr");
        return;
    }
    std::shared_ptr<PreferredNetworkTypeInfo> preferredNetworkInfo =
        event->GetSharedObject<PreferredNetworkTypeInfo>();
    if (TELEPHONY_EXT_WRAPPER.getPreferredNetworkExt_ != nullptr && preferredNetworkInfo != nullptr) {
        TELEPHONY_EXT_WRAPPER.getPreferredNetworkExt_(preferredNetworkInfo->preferredNetworkType);
    }
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (preferredNetworkInfo == nullptr && responseInfo == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork object is nullptr\n");
        return;
    }
    MessageParcel data;
    int64_t index = -1;
    if (!WriteGetPreferredNetworkInfo(preferredNetworkInfo, responseInfo, data, index)) {
        return;
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr) {
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::GET_PREFERRED_NETWORK_MODE_RESULT, data);
            TELEPHONY_LOGI("NetworkType::ProcessGetPreferredNetwork callback success");
        }
        NetworkUtils::RemoveCallbackFromMap(index);
    } else {
        TELEPHONY_LOGI("NetworkType::ProcessGetPreferredNetwork has no callbackInfo");
    }
}

void NetworkType::ProcessSetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &event) const
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork event is nullptr");
        return;
    }
    std::shared_ptr<NetworkSearchManager> networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork networkSearchManager is nullptr");
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork responseInfo is nullptr");
        return;
    }

    bool success = responseInfo->error == HRilErrType::NONE;
    if (success) {
        int32_t networkMode = 0;
        networkSearchManager->GetCachePreferredNetworkValue(slotId_, networkMode);
        if (networkMode >= static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_AUTO) &&
            networkMode < static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_MAX_VALUE)) {
            networkSearchManager->SavePreferredNetworkValue(slotId_, networkMode);
        }
    }
    int64_t index = responseInfo->flag;
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork callbackInfo is nullptr slotId:%{public}d", slotId_);
        return;
    }
    sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
    if (callback == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork callback is nullptr slotId:%{public}d", slotId_);
        return;
    }
    MessageParcel data;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (!data.WriteBool(success) ||
        !data.WriteInt32(success ? TELEPHONY_SUCCESS : (int32_t)responseInfo->error)) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork write date fail slotId:%{public}d", slotId_);
        return;
    }
    callback->OnNetworkSearchCallback(
        INetworkSearchCallback::NetworkSearchCallback::SET_PREFERRED_NETWORK_MODE_RESULT, data);
    NetworkUtils::RemoveCallbackFromMap(index);
}

bool NetworkType::WriteGetPreferredNetworkInfo(std::shared_ptr<PreferredNetworkTypeInfo> &preferredNetworkInfo,
    std::shared_ptr<HRilRadioResponseInfo> &responseInfo, MessageParcel &data, int64_t &index) const
{
    std::shared_ptr<NetworkSearchManager> networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork networkSearchManager is nullptr\n");
        return false;
    }
    int32_t networkMode = -1;
    if (!data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor())) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork WriteInterfaceToken failed");
        return false;
    }
    if (preferredNetworkInfo != nullptr) {
        networkMode = preferredNetworkInfo->preferredNetworkType;
        index = preferredNetworkInfo->flag;
        networkSearchManager->SavePreferredNetworkValue(slotId_, networkMode);
        if (!data.WriteInt32(networkMode) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork WriteInt32 networkMode is false");
            return false;
        }
    } else if (responseInfo != nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork error code is %{public}d", responseInfo->error);
        index = responseInfo->flag;
        if (!data.WriteInt32(networkMode) && !data.WriteInt32(static_cast<int32_t>(responseInfo->error))) {
            TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork WriteInt32 networkMode is false");
            return false;
        }
    }
    return true;
}
} // namespace Telephony
} // namespace OHOS
