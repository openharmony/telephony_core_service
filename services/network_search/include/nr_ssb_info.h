/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef NETWORK_SEARCH_INCLUDE_NR_SSB_INFO_H
#define NETWORK_SEARCH_INCLUDE_NR_SSB_INFO_H

#include "event_handler.h"
#include "hril_network_parcel.h"
#include "nr_ssb_information.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class NrSsbInfo {
public:
    NrSsbInfo(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId);
    virtual ~NrSsbInfo() = default;
    bool FillNrSsbIdInformation(const std::shared_ptr<NrSsbInformation> &nrCellSsbIdsInfo);
    bool ProcessGetNrSsbId(const AppExecFwk::InnerEvent::Pointer &event);

private:
    bool UpdateNrSsbIdInfo(int32_t slotId, std::shared_ptr<NrCellSsbIds> nrCellSsbIds);
    std::mutex mutex_;
    std::shared_ptr<NrCellSsbInfo> nrCellSsbIdsInfo_ = nullptr;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;

    int32_t slotId_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NR_SSB_INFO_H