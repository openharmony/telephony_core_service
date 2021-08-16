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

#include "network_search_result.h"

#include <securec.h>

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkSearchResult::NetworkSearchResult() {}

void NetworkSearchResult::SetNetworkSearchResultValue(
    int32_t listSize, std::vector<NetworkInformation> &operatorInfo)
{
    listSize_ = listSize;
    operatorInfoList_ = operatorInfo;
    TELEPHONY_LOGI("NetworkSearchResult::SetNetworkSearchResultValue size:%{public}d, %{public}zu)", listSize_,
        operatorInfoList_.size());
}

std::vector<NetworkInformation> NetworkSearchResult::GetNetworkSearchResult() const
{
    return operatorInfoList_;
}

int32_t NetworkSearchResult::GetNetworkSearchResultSize() const
{
    return listSize_;
}

bool NetworkSearchResult::ReadFromParcel(Parcel &parcel)
{
    listSize_ = parcel.ReadInt32();
    TELEPHONY_LOGI("ReadParcelable<NetworkState> %{public}d", listSize_);
    for (int32_t i = 0; i < listSize_; i++) {
        std::unique_ptr<NetworkInformation> networkInfo(parcel.ReadParcelable<NetworkInformation>());
        if (networkInfo == nullptr) {
            TELEPHONY_LOGE("ReadParcelable<NetworkState> failed");
            return false;
        }
        operatorInfoList_.emplace_back(*networkInfo);
    }
    return true;
}

bool NetworkSearchResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(listSize_)) {
        TELEPHONY_LOGE("NetworkSearchResult::Marshalling WriteInt32 failed");
        return false;
    }
    TELEPHONY_LOGI("ReadParcelable<NetworkState> size:%{public}d", listSize_);
    for (auto &networkState : operatorInfoList_) {
        parcel.WriteParcelable(&networkState);
    }
    return true;
}

NetworkSearchResult *NetworkSearchResult::Unmarshalling(Parcel &parcel)
{
    NetworkSearchResult *param = new (std::nothrow) NetworkSearchResult();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}
} // namespace Telephony
} // namespace OHOS