/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "nr_ssb_info.h"

#include "network_search_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NrSsbInfo::NrSsbInfo(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), slotId_(slotId)
{
    nrCellSsbIdsInfo_ = std::make_shared<NrCellSsbInfo>();
}

bool NrSsbInfo::FillNrSsbIdInformation(const std::shared_ptr<NrSsbInformation> &nrCellSsbIdsInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (nrCellSsbIdsInfo == nullptr) {
        TELEPHONY_LOGE("nrCellSsbIdsInfo is null");
        return false;
    }
    nrCellSsbIdsInfo->SetSsbBaseParam(nrCellSsbIdsInfo_->arfcn, nrCellSsbIdsInfo_->cid, nrCellSsbIdsInfo_->pci,
        nrCellSsbIdsInfo_->rsrp, nrCellSsbIdsInfo_->sinr, nrCellSsbIdsInfo_->timeAdvance);
    nrCellSsbIdsInfo->SetSCellSsbList(nrCellSsbIdsInfo_->sCellSsbList);
    nrCellSsbIdsInfo->SetNbCellSsbList(nrCellSsbIdsInfo_->nbCellCount, nrCellSsbIdsInfo_->nbCellSsbList);
    return true;
}

bool NrSsbInfo::ProcessGetNrSsbId(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (event == nullptr) {
        TELEPHONY_LOGE("Event is nullptr");
        return false;
    }
    std::shared_ptr<NrCellSsbIds> nrCellSsbIds = event->GetSharedObject<NrCellSsbIds>();
    if (nrCellSsbIds == nullptr) {
        TELEPHONY_LOGE("NrCellSsbIds is nullptr");
        return false;
    }

    if (!UpdateNrSsbIdInfo(slotId_, nrCellSsbIds)) {
        TELEPHONY_LOGE("Get ssb info is failed");
        return false;
    }
    return true;
}

bool NrSsbInfo::UpdateNrSsbIdInfo(int32_t slotId, std::shared_ptr<NrCellSsbIds> nrCellSsbIds)
{
    if (nrCellSsbIds == nullptr || nrCellSsbIdsInfo_ == nullptr) {
        TELEPHONY_LOGE("nrCellSsbIds or nrCellSsbIdsInfo_ is nullptr");
        return false;
    }
    if (nrCellSsbIds->nbCellCount > NrSsbInformation::MAX_NBCELL_COUNT) {
        TELEPHONY_LOGE("nbCellCount:%{public}d > MAX_NBCELL_COUNT", nrCellSsbIds->nbCellCount);
        return false;
    }
    nrCellSsbIdsInfo_->arfcn = nrCellSsbIds->arfcn;
    nrCellSsbIdsInfo_->cid = nrCellSsbIds->cid;
    nrCellSsbIdsInfo_->pci = nrCellSsbIds->pic;
    nrCellSsbIdsInfo_->rsrp = nrCellSsbIds->rsrp;
    nrCellSsbIdsInfo_->sinr = nrCellSsbIds->sinr;
    nrCellSsbIdsInfo_->timeAdvance = nrCellSsbIds->timeAdvance;
    nrCellSsbIdsInfo_->nbCellCount = nrCellSsbIds->nbCellCount;
    for (const auto &info : nrCellSsbIds->sCellSsbList) {
        SsbInfo ssbInfo;
        ssbInfo.ssbId = info.ssbId;
        ssbInfo.rsrp = info.rsrp;
        nrCellSsbIdsInfo_->sCellSsbList.push_back(ssbInfo);
    }
    for (int32_t i = 0; i < nrCellSsbIds->nbCellCount; i++) {
        NeighboringCellSsbInformation neighboringCellSsbInfo;
        neighboringCellSsbInfo.pci = nrCellSsbIds->nbCellSsbList[i].pci;
        neighboringCellSsbInfo.arfcn = nrCellSsbIds->nbCellSsbList[i].arfcn;
        neighboringCellSsbInfo.rsrp = nrCellSsbIds->nbCellSsbList[i].rsrp;
        neighboringCellSsbInfo.sinr = nrCellSsbIds->nbCellSsbList[i].sinr;
        for (const auto &info : nrCellSsbIds->nbCellSsbList[i].ssbIdList) {
            SsbInfo ssbInfo;
            ssbInfo.ssbId = info.ssbId;
            ssbInfo.rsrp = info.rsrp;
            neighboringCellSsbInfo.ssbList.push_back(ssbInfo);
        }
        nrCellSsbIdsInfo_->nbCellSsbList.push_back(neighboringCellSsbInfo);
    }
    return true;
}
} // namespace Telephony
} // namespace OHOS