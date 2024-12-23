/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "nr_ssb_information.h"

#include <cstdint>
#include <ctime>
#include <memory>

#include "iosfwd"
#include "new"
#include "parcel.h"
#include "string"

namespace OHOS {
namespace Telephony {
bool NrSsbInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(arfcn_)) {
        return false;
    }
    if (!parcel.WriteInt64(cid_)) {
        return false;
    }
    if (!parcel.WriteInt32(pci_)) {
        return false;
    }
    if (!parcel.WriteInt32(rsrp_)) {
        return false;
    }
    if (!parcel.WriteInt32(sinr_)) {
        return false;
    }
    if (!parcel.WriteInt32(timeAdvance_)) {
        return false;
    }
    for (int32_t i = 0; i < SCELL_SSB_LIST && i < static_cast<int32_t>(sCellSsbList_.size()); ++i) {
        if (!parcel.WriteInt32(sCellSsbList_[i].ssbId)) {
            return false;
        }
        if (!parcel.WriteInt32(sCellSsbList_[i].rsrp)) {
            return false;
        }
    }
    if (!MarshallingNbCellSsbId(parcel)) {
        return false;
    }
    return true;
}

bool NrSsbInformation::MarshallingNbCellSsbId(Parcel &parcel) const
{
    if (nbCellCount_ > MAX_NBCELL_COUNT) {
        return false;
    }
    if (!parcel.WriteInt32(nbCellCount_)) {
        return false;
    }
    for (int32_t i = 0; i < nbCellCount_; ++i) {
        if (!parcel.WriteInt32(nbCellSsbList_[i].pci)) {
            return false;
        }
        if (!parcel.WriteInt32(nbCellSsbList_[i].arfcn)) {
            return false;
        }
        if (!parcel.WriteInt32(nbCellSsbList_[i].rsrp)) {
            return false;
        }
        if (!parcel.WriteInt32(nbCellSsbList_[i].sinr)) {
            return false;
        }
        for (int32_t j = 0; j < NBCELL_SSB_LIST; ++j) {
            if (!parcel.WriteInt32(nbCellSsbList_[i].ssbList[j].ssbId)) {
                return false;
            }
            if (!parcel.WriteInt32(nbCellSsbList_[i].ssbList[j].rsrp)) {
                return false;
            }
        }
    }
    return true;
}

bool NrSsbInformation::ReadFromParcel(Parcel &parcel)
{
    int32_t item_32;
    int64_t item_64;
    if (!parcel.ReadInt32(item_32)) {
        return false;
    }
    arfcn_ = item_32;
    if (!parcel.ReadInt64(item_64)) {
        return false;
    }
    cid_ = item_64;
    if (!parcel.ReadInt32(item_32)) {
        return false;
    }
    pci_ = item_32;
    if (!parcel.ReadInt32(item_32)) {
        return false;
    }
    rsrp_ = item_32;
    if (!parcel.ReadInt32(item_32)) {
        return false;
    }
    sinr_ = item_32;
    if (!parcel.ReadInt32(item_32)) {
        return false;
    }
    timeAdvance_ = item_32;
    for (int32_t i = 0; i < SCELL_SSB_LIST; ++i) {
        SsbInfo ssbInfo;
        if (!parcel.ReadInt32(item_32)) {
            return false;
        }
        ssbInfo.ssbId = item_32;
        if (!parcel.ReadInt32(item_32)) {
            return false;
        }
        ssbInfo.rsrp = item_32;
        sCellSsbList_.push_back(ssbInfo);
    }
    if (!ReadFromParcelForNbCell(parcel)) {
        return false;
    }
    return true;
}

bool NrSsbInformation::ReadFromParcelForNbCell(Parcel &parcel)
{
    int32_t item_32;
    if (!parcel.ReadInt32(item_32)) {
        return false;
    }
    nbCellCount_ = (item_32 > MAX_NBCELL_COUNT) ? MAX_NBCELL_COUNT : item_32;
    for (int32_t i = 0; i < nbCellCount_; ++i) {
        NeighboringCellSsbInformation nbCellSsbInfo;
        if (!parcel.ReadInt32(item_32)) {
            return false;
        }
        nbCellSsbInfo.pci = item_32;
        if (!parcel.ReadInt32(item_32)) {
            return false;
        }
        nbCellSsbInfo.arfcn = item_32;
        if (!parcel.ReadInt32(item_32)) {
            return false;
        }
        nbCellSsbInfo.rsrp = item_32;
        if (!parcel.ReadInt32(item_32)) {
            return false;
        }
        nbCellSsbInfo.sinr = item_32;
        for (int32_t j = 0; j < NBCELL_SSB_LIST; ++j) {
            SsbInfo ssbInfo;
            if (!parcel.ReadInt32(item_32)) {
                return false;
            }
            ssbInfo.ssbId = item_32;
            if (!parcel.ReadInt32(item_32)) {
                return false;
            }
            ssbInfo.rsrp = item_32;
            nbCellSsbInfo.ssbList.push_back(ssbInfo);
        }
        nbCellSsbList_.push_back(nbCellSsbInfo);
    }
    return true;
}

void NrSsbInformation::SetSsbBaseParam(
    int32_t arfcn, int64_t cid, int32_t pci, int32_t rsrp, int32_t sinr, int32_t timeAdvance)
{
    arfcn_ = arfcn;
    cid_ = cid;
    pci_ = pci;
    rsrp_ = rsrp;
    sinr_ = sinr;
    timeAdvance_ = timeAdvance;
}

void NrSsbInformation::SetSCellSsbList(std::vector<SsbInfo> sCellSsbList)
{
    sCellSsbList_.clear();
    for (const auto &info : sCellSsbList) {
        SsbInfo ssbInfo;
        ssbInfo.ssbId = info.ssbId;
        ssbInfo.rsrp = info.rsrp;
        sCellSsbList_.push_back(ssbInfo);
    }
}

void NrSsbInformation::SetNbCellSsbList(int32_t nbCellCount, std::vector<NeighboringCellSsbInformation> nbCellSsbList)
{
    nbCellSsbList_.clear();
    nbCellCount_ = (nbCellCount > MAX_NBCELL_COUNT) ? MAX_NBCELL_COUNT : nbCellCount;
    for (int32_t i = 0; i < nbCellCount_; ++i) {
        NeighboringCellSsbInformation nbCellSsbInfo;
        nbCellSsbInfo.pci = nbCellSsbList[i].pci;
        nbCellSsbInfo.arfcn = nbCellSsbList[i].arfcn;
        nbCellSsbInfo.rsrp = nbCellSsbList[i].rsrp;
        nbCellSsbInfo.sinr = nbCellSsbList[i].sinr;
        for (const auto &info : nbCellSsbList[i].ssbList) {
            SsbInfo ssbInfo;
            ssbInfo.ssbId = info.ssbId;
            ssbInfo.rsrp = info.rsrp;
            nbCellSsbInfo.ssbList.push_back(ssbInfo);
        }
        nbCellSsbList_.push_back(nbCellSsbInfo);
    }
}

int32_t NrSsbInformation::GetArfcn() const
{
    return arfcn_;
}

int64_t NrSsbInformation::GetCid() const
{
    return cid_;
}

int32_t NrSsbInformation::GetPci() const
{
    return pci_;
}

int32_t NrSsbInformation::GetRsrp() const
{
    return rsrp_;
}

int32_t NrSsbInformation::GetSinr() const
{
    return sinr_;
}

int32_t NrSsbInformation::GetTimeAdvance() const
{
    return timeAdvance_;
}

int32_t NrSsbInformation::GetNbCellCount() const
{
    return nbCellCount_;
}

void NrSsbInformation::GetSCellSsbIdList(std::vector<SsbInfo> &sCellSsbList) const
{
    for (const auto &info : sCellSsbList_) {
        SsbInfo ssbInfo;
        ssbInfo.ssbId = info.ssbId;
        ssbInfo.rsrp = info.rsrp;
        sCellSsbList.push_back(ssbInfo);
    }
}

void NrSsbInformation::GetNbCellSsbIdList(std::vector<NeighboringCellSsbInformation> &nbCellSsbList) const
{
    for (int32_t i = 0; i < nbCellCount_; i++) {
        NeighboringCellSsbInformation neighboringCellSsbInfo;
        neighboringCellSsbInfo.pci = nbCellSsbList_[i].pci;
        neighboringCellSsbInfo.arfcn = nbCellSsbList_[i].arfcn;
        neighboringCellSsbInfo.rsrp = nbCellSsbList_[i].rsrp;
        neighboringCellSsbInfo.sinr = nbCellSsbList_[i].sinr;
        for (const auto &info : nbCellSsbList_[i].ssbList) {
            SsbInfo ssbInfo;
            ssbInfo.ssbId = info.ssbId;
            ssbInfo.rsrp = info.rsrp;
            neighboringCellSsbInfo.ssbList.push_back(ssbInfo);
        }
        nbCellSsbList.push_back(neighboringCellSsbInfo);
    }
}
} // namespace Telephony
} // namespace OHOS
