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

#include <cinttypes>

#include "network_search_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkType::NetworkType(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), slotId_(slotId)
{}

void NetworkType::ProcessGetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("NetworkType::ProcessGetPreferredNetwork");
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork event is nullptr");
        return;
    }
    std::shared_ptr<NetworkSearchManager> networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork networkSearchManager is nullptr\n");
        return;
    }
    std::shared_ptr<PreferredNetworkTypeInfo> preferredNetworkInfo =
        event->GetSharedObject<PreferredNetworkTypeInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (preferredNetworkInfo == nullptr && responseInfo == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork object is nullptr\n");
        return;
    }
    MessageParcel data;
    int64_t index = -1;
    int32_t networkMode = -1;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (preferredNetworkInfo != nullptr) {
        networkMode = preferredNetworkInfo->preferredNetworkType;
        index = preferredNetworkInfo->flag;
        networkSearchManager->SavePreferredNetworkValue(slotId_, networkMode);
        if (!data.WriteInt32(networkMode) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork WriteInt32 networkMode is false");
            return;
        }
    } else if (responseInfo != nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork error code is %{public}d", responseInfo->error);
        index = responseInfo->flag;
        if (!data.WriteInt32(networkMode) && !data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE("NetworkType::ProcessGetPreferredNetwork WriteInt32 networkMode is false");
            return;
        }
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr) {
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::GET_PREFERRED_NETWORK_MODE_RESULT, data);
            TELEPHONY_LOGI("NetworkType::ProcessGetPreferredNetwork callback success");
        }
        NetworkUtils::RemoveCallbackFromMap(index);
    }
}

void NetworkType::ProcessSetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("NetworkType::ProcessSetPreferredNetwork ok");
    if (event == nullptr) {
        TELEPHONY_LOGE("NitzUpdate::ProcessSetPreferredNetwork event is nullptr");
        return;
    }
    std::shared_ptr<NetworkSearchManager> networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork networkSearchManager is nullptr\n");
        return;
    }
    MessageParcel data;
    int64_t index = -1;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork HRilRadioResponseInfo error is %{public}d",
            responseInfo->error);
        index = responseInfo->flag;
        if (!data.WriteBool(false) || !data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork WriteBool slotId is false");
            return;
        }
    } else {
        index = event->GetParam();
        TELEPHONY_LOGI("NetworkType::ProcessSetPreferredNetwork index:(%{public}" PRId64 ")", index);
        if (!data.WriteBool(true) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE("NetworkType::ProcessSetPreferredNetwork WriteBool slotId is false");
            return;
        }
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        int32_t networkMode = callbackInfo->param_;
        networkSearchManager->SavePreferredNetworkValue(slotId_, networkMode);
        TELEPHONY_LOGI("NetworkSelection::ProcessSetNetworkSelectionMode NetworkMode is:%{public}d", networkMode);
        if (callback != nullptr) {
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::SET_PREFERRED_NETWORK_MODE_RESULT, data);
            TELEPHONY_LOGI("NetworkSelection::ProcessSetNetworkSelectionMode callback success");
        }
        NetworkUtils::RemoveCallbackFromMap(index);
    }
}
} // namespace Telephony
} // namespace OHOS
