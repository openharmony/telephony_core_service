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

#ifndef NETWORK_SEARCH_RESULT_H
#define NETWORK_SEARCH_RESULT_H

#include "network_information.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchResult : public Parcelable {
public:
    NetworkSearchResult();
    virtual ~NetworkSearchResult() = default;
    void SetNetworkSearchResultValue(int32_t listSize, std::vector<NetworkInformation> &operatorInfo);
    std::vector<NetworkInformation> GetNetworkSearchInformation() const;
    int32_t GetNetworkSearchInformationSize() const;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static NetworkSearchResult *Unmarshalling(Parcel &parcel);

private:
    int32_t listSize_ = 0;
    std::vector<NetworkInformation> operatorInfoList_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_RESULT_H
