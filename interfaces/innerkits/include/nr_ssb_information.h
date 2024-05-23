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

#ifndef OHOS_NR_SSB_INFORMATION_H
#define OHOS_NR_SSB_INFORMATION_H

#include <vector>

#include "parcel.h"

namespace OHOS {
namespace Telephony {

struct SsbInfo {
    /** SSB index. */
    int32_t ssbId;
    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rsrp;
};

struct NeighboringCellSsbInformation {
    /** Physical cell ID. */
    int32_t pci;
    /** Absolute Radio Frequency Channel Number of the BCCH carrier 0~1023 */
    int32_t arfcn;
    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rsrp;
    /** Signal To Interference Plus Noise Ratio. */
    int32_t sinr;
    /** Neighboring cell ssbId list, always size is 4 */
    std::vector<SsbInfo> ssbList;
};

struct NrCellSsbInfo {
    /** Absolute Radio Frequency Channel Number of the BCCH carrier 0~1023 */
    int32_t arfcn;
    /** Context Identifier. */
    int64_t cid;
    /** Physical cell ID. */
    int32_t pci;
    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rsrp;
    /** Signal To Interference Plus Noise Ratio. */
    int32_t sinr;
    /** Time advance. */
    int32_t timeAdvance;
    /** Service cell ssbId list, always size is 8 */
    std::vector<SsbInfo> sCellSsbList;
    /** Neighboring cell ssb list count, max size is 4 */
    int32_t nbCellCount;
    /** Neighboring cell ssb info list, max size is 4 */
    std::vector<NeighboringCellSsbInformation> nbCellSsbList;
};

class NrSsbInformation : public Parcelable {
public:
    NrSsbInformation() = default;
    ~NrSsbInformation() = default;
    bool Marshalling(Parcel &parcel) const override;
    bool MarshallingNbCellSsbId(Parcel &parcel) const;
    bool ReadFromParcel(Parcel &parcel);
    bool ReadFromParcelForNbCell(Parcel &parcel);
    void SetSsbBaseParam(int32_t arfcn, int64_t cid, int32_t pci, int32_t rsrp, int32_t sinr, int32_t timeAdvance);
    void SetSCellSsbList(std::vector<SsbInfo> sCellSsbList);
    void SetNbCellSsbList(int32_t nbCellCount, std::vector<NeighboringCellSsbInformation> nbCellSsbList);
    int32_t GetArfcn() const;
    int64_t GetCid() const;
    int32_t GetPci() const;
    int32_t GetRsrp() const;
    int32_t GetSinr() const;
    int32_t GetTimeAdvance() const;
    int32_t GetNbCellCount() const;
    void GetSCellSsbIdList(std::vector<SsbInfo> &sCellSsbList) const;
    void GetNbCellSsbIdList(std::vector<NeighboringCellSsbInformation> &nbCellSsbList) const;

public:
    static const int32_t SCELL_SSB_LIST = 8;
    static const int32_t NBCELL_SSB_LIST = 4;
    static const int32_t MAX_NBCELL_COUNT = 4;

private:
    int32_t arfcn_ = 0; /** Absolute Radio Frequency Channel Number */
    int64_t cid_ = 0; /** Context Identifier. */
    int32_t pci_ = 0; /** Physical cell ID. */
    int32_t rsrp_ = 0; /** Reference Signal Received Power */
    int32_t sinr_ = 0; /** Signal To Interference Plus Noise Ratio. */
    int32_t timeAdvance_ = 0; /** Time advance. */
    std::vector<SsbInfo> sCellSsbList_; /** Service cell ssbId list */
    int32_t nbCellCount_ = 0; /** Neighboring cell ssb list count */
    std::vector<NeighboringCellSsbInformation> nbCellSsbList_; /** Neighboring cell ssb info list */
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_NR_SSB_INFORMATION_H