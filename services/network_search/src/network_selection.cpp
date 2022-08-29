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

#include "network_selection.h"

#include "network_search_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkSelection::NetworkSelection(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), slotId_(slotId)
{}

void NetworkSelection::ProcessNetworkSearchResult(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("NetworkSelection::ProcessNetworkSearchResult slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<AvailableNetworkList> availNetworkResult = event->GetSharedObject<AvailableNetworkList>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (availNetworkResult == nullptr && responseInfo == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult object is nullptr slotId:%{public}d", slotId_);
        return;
    }

    MessageParcel data;
    int64_t index = -1;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (availNetworkResult != nullptr) {
        if (!AvailNetworkResult(availNetworkResult, data, index)) {
            return;
        }
    } else if (responseInfo != nullptr) {
        if (!ResponseInfoOfResult(responseInfo, data, index)) {
            return;
        }
    }
    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr) {
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::GET_AVAILABLE_RESULT, data);
            TELEPHONY_LOGI("NetworkSelection::ProcessNetworkSearchResult callback success slotId:%{public}d", slotId_);
        }
        NetworkUtils::RemoveCallbackFromMap(index);
    } else {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult callbackInfo is null slotId:%{public}d", slotId_);
    }
}

void NetworkSelection::ProcessGetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("NetworkSelection::ProcessGetNetworkSelectionMode slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessGetNetworkSelectionMode event is nullptr slotId:%{public}d", slotId_);
        return;
    }

    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<SetNetworkModeInfo> selectModeResult = event->GetSharedObject<SetNetworkModeInfo>();
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (selectModeResult == nullptr && responseInfo == nullptr) {
        TELEPHONY_LOGE(
            "NetworkSelection::ProcessGetNetworkSelectionMode SelectModeResultInfo, NetworkSearchManager"
            "or HRilRadioResponseInfo is nullptr slotId:%{public}d",
            slotId_);
        return;
    }

    MessageParcel data;
    int64_t index = -1;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    if (selectModeResult != nullptr) {
        if (!SelectModeResult(selectModeResult, data, index)) {
            return;
        }
    } else if (responseInfo != nullptr) {
        if (!ResponseInfoOfGet(responseInfo, data, index)) {
            return;
        }
    }

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo != nullptr) {
        sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
        if (callback != nullptr) {
            callback->OnNetworkSearchCallback(
                INetworkSearchCallback::NetworkSearchCallback::GET_NETWORK_MODE_RESULT, data);
            TELEPHONY_LOGI(
                "NetworkSelection::ProcessGetNetworkSelectionMode callback success slotId:%{public}d", slotId_);
        } else {
            TELEPHONY_LOGE(
                "NetworkSelection::ProcessGetNetworkSelectionMode callback is null slotId:%{public}d", slotId_);
        }
        NetworkUtils::RemoveCallbackFromMap(index);
    } else {
        TELEPHONY_LOGE(
            "NetworkSelection::ProcessGetNetworkSelectionMode callbackInfo is null slotId:%{public}d", slotId_);
    }
}

void NetworkSelection::ProcessSetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &event) const
{
    TELEPHONY_LOGI("NetworkSelection::ProcessSetNetworkSelectionMode ok slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessSetNetworkSelectionMode event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessSetNetworkSelectionMode nsm is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessSetNetworkSelectionMode responseInfo is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInterfaceToken(INetworkSearchCallback::GetDescriptor());
    int64_t index = responseInfo->flag;
    if (!ResponseInfoOfSet(responseInfo, data, index)) {
        return;
    }

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo = NetworkUtils::FindNetworkSearchCallback(index);
    if (callbackInfo == nullptr) {
        TELEPHONY_LOGE(
            "NetworkSelection::ProcessSetNetworkSelectionMode callbackInfo is nullptr slotId:%{public}d", slotId_);
        return;
    }
    sptr<INetworkSearchCallback> callback = callbackInfo->networkSearchItem_;
    nsm->SetNetworkSelectionValue(slotId_, static_cast<SelectionMode>(callbackInfo->param_));
    TELEPHONY_LOGI("NetworkSelection::ProcessSetNetworkSelectionMode selectionMode:%{public}d slotId:%{public}d",
        callbackInfo->param_, slotId_);
    if (callback != nullptr) {
        callback->OnNetworkSearchCallback(INetworkSearchCallback::NetworkSearchCallback::SET_NETWORK_MODE_RESULT, data);
        TELEPHONY_LOGI("NetworkSelection::ProcessSetNetworkSelectionMode callback success slotId:%{public}d", slotId_);
    } else {
        TELEPHONY_LOGE("NetworkSelection::ProcessSetNetworkSelectionMode callback fail slotId:%{public}d", slotId_);
    }
    NetworkUtils::RemoveCallbackFromMap(index);
}

bool NetworkSelection::AvailNetworkResult(
    std::shared_ptr<AvailableNetworkList> availNetworkResult, MessageParcel &data, int64_t &index) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::ProcessNetworkSearchResult nsm is nullptr slotId:%{public}d", slotId_);
        return false;
    }
    index = -1;
    if (availNetworkResult != nullptr) {
        int32_t availableSize = availNetworkResult->itemNum;
        index = availNetworkResult->flag;
        std::vector<AvailableNetworkInfo> &availableNetworkInfo = availNetworkResult->availableNetworkInfo;
        std::vector<NetworkInformation> networkInformation;
        if (availableSize > 0) {
            for (auto &availableNetworkInfoItem : availableNetworkInfo) {
                std::string longName = availableNetworkInfoItem.longName;
                std::string shortName = availableNetworkInfoItem.shortName;
                std::string numeric = availableNetworkInfoItem.numeric;
                int32_t status = availableNetworkInfoItem.status;
                int32_t rat = availableNetworkInfoItem.rat;
                NetworkInformation networkStateItem;
                networkStateItem.SetOperateInformation(longName, shortName, numeric, status, rat);
                networkInformation.push_back(networkStateItem);
            }
        }
        nsm->SetNetworkSearchResultValue(slotId_, availableSize, networkInformation);
        sptr<NetworkSearchResult> networkSearchResult = nsm->GetNetworkSearchInformationValue(slotId_);
        if (networkSearchResult != nullptr) {
            networkSearchResult->Marshalling(data);
        }
        if (!data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE(
                "NetworkSelection::ProcessNetworkSearchResult WriteInt32 errorCode is false slotId:%{public}d",
                slotId_);
            return false;
        }
    }
    return true;
}

bool NetworkSelection::ResponseInfoOfResult(
    std::shared_ptr<HRilRadioResponseInfo> responseInfo, MessageParcel &data, int64_t &index) const
{
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("NetworkSelection::RilRadioResponseInfoOfResult error code is %{public}d slotId:%{public}d",
            responseInfo->error, slotId_);
        index = responseInfo->flag;
        sptr<NetworkSearchResult> networkSearchResult = new (std::nothrow) NetworkSearchResult;
        networkSearchResult->Marshalling(data);
        if (!data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE(
                "NetworkSelection::RilRadioResponseInfoOfResult WriteInt32 errorCode is false slotId:%{public}d",
                slotId_);
            return false;
        }
    }
    return true;
}

bool NetworkSelection::ResponseInfoOfGet(
    std::shared_ptr<HRilRadioResponseInfo> responseInfo, MessageParcel &data, int64_t &index) const
{
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE(
            "NetworkSelection::RilRadioResponseInfoOfGet HRilRadioResponseInfo error is %{public}d "
            "slotId:%{public}d",
            responseInfo->error, slotId_);
        index = responseInfo->flag;
        if (!data.WriteInt32(static_cast<int32_t>(SelectionMode::MODE_TYPE_UNKNOWN))) {
            TELEPHONY_LOGE(
                "NetworkSelection::RilRadioResponseInfoOfGet WriteInt32 slotId is false slotId:%{public}d", slotId_);
            return false;
        }
        if (!data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE(
                "NetworkSelection::RilRadioResponseInfoOfGet WriteInt32 errorCode is false slotId:%{public}d", slotId_);
            return false;
        }
    }
    return true;
}

bool NetworkSelection::ResponseInfoOfSet(
    std::shared_ptr<HRilRadioResponseInfo> responseInfo, MessageParcel &data, int64_t &index) const
{
    if (responseInfo->error == HRilErrType::NONE) {
        if (!data.WriteBool(true) || !data.WriteInt32(TELEPHONY_SUCCESS)) {
            TELEPHONY_LOGE("NetworkSelection::ResponseInfoOfSet write data fail slotId:%{public}d", slotId_);
            return false;
        }
    } else {
        if (!data.WriteBool(false) || !data.WriteInt32((int32_t)responseInfo->error)) {
            TELEPHONY_LOGE("NetworkSelection::ResponseInfoOfSet write data fail slotId:%{public}d", slotId_);
            return false;
        }
    }
    return true;
}

bool NetworkSelection::SelectModeResult(
    std::shared_ptr<SetNetworkModeInfo> selectModeResult, MessageParcel &data, int64_t &index) const
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::SelectModeResult nsm is nullptr slotId:%{public}d", slotId_);
        return false;
    }

    if (selectModeResult == nullptr) {
        TELEPHONY_LOGE("NetworkSelection::SelectModeResult selectModeResult is nullptr slotId:%{public}d", slotId_);
        return false;
    }
    int32_t selectMode = selectModeResult->selectMode;
    TELEPHONY_LOGI("NetworkSelection::ProcessGetNetworkSelectionMode selectMode:%{public}d slotId:%{public}d",
        selectMode, slotId_);
    nsm->SetNetworkSelectionValue(slotId_, static_cast<SelectionMode>(selectMode));
    if (!data.WriteInt32(selectMode)) {
        TELEPHONY_LOGE(
            "NetworkSelection::ProcessGetNetworkSelectionMode WriteInt32 slotId is false slotId:%{public}d", slotId_);
        return false;
    }
    if (!data.WriteInt32(TELEPHONY_SUCCESS)) {
        TELEPHONY_LOGE(
            "NetworkSelection::ProcessGetNetworkSelectionMode WriteInt32 errorCode is false slotId:%{public}d",
            slotId_);
        return false;
    }
    index = selectModeResult->flag;
    return true;
}
} // namespace Telephony
} // namespace OHOS
