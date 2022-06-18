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

#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_SELECTION_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_SELECTION_H

#include <memory>

#include "event_handler.h"
#include "hril_network_parcel.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class NetworkSelection {
public:
    NetworkSelection(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId);
    virtual ~NetworkSelection() = default;
    void ProcessNetworkSearchResult(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessGetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessSetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &event) const;

private:
    bool AvailNetworkResult(
        std::shared_ptr<AvailableNetworkList> availNetworkResult, MessageParcel &data, int64_t &index) const;
    bool SelectModeResult(
        std::shared_ptr<SetNetworkModeInfo> selectModeResult, MessageParcel &data, int64_t &index) const;
    bool ResponseInfoOfResult(
        std::shared_ptr<HRilRadioResponseInfo> responseInfo, MessageParcel &data, int64_t &index) const;
    bool ResponseInfoOfGet(
        std::shared_ptr<HRilRadioResponseInfo> responseInfo, MessageParcel &data, int64_t &index) const;
    bool ResponseInfoOfSet(
        std::shared_ptr<HRilRadioResponseInfo> responseInfo, MessageParcel &data, int64_t &index) const;

    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    int32_t slotId_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_SELECTION_H
