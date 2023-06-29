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

#ifndef NETWORK_SEARCH_INCLUDE_CELL_INFO_H
#define NETWORK_SEARCH_INCLUDE_CELL_INFO_H

#include "event_handler.h"
#include "hril_network_parcel.h"
#include "cell_information.h"
#include "signal_information.h"
#include "network_state.h"
#include "cell_location.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class CellInfo {
public:
    CellInfo(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId);
    virtual ~CellInfo() = default;
    static void InitCellSignalBar(const int32_t bar = 5);
    void GetCellInfoList(std::vector<sptr<CellInformation>> &cellInfo);
    void ProcessNeighboringCellInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void ClearCellInfoList();
    void UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac);
    sptr<CellLocation> GetCellLocation();

private:
    bool ProcessCellLocation(
        sptr<CellInformation> &cell, CellInformation::CellType type, int32_t cellId, int32_t lac);
    bool ProcessNeighboringCellGsm(CellNearbyInfo *cellInfo);
    bool ProcessNeighboringCellLte(CellNearbyInfo *cellInfo);
    bool ProcessNeighboringCellWcdma(CellNearbyInfo *cellInfo);
    bool ProcessNeighboringCellCdma(CellNearbyInfo *cellInfo);
    bool ProcessNeighboringCellTdscdma(CellNearbyInfo *cellInfo);
    bool ProcessNeighboringCellNr(CellNearbyInfo *cellInfo);
    bool ProcessCurrentCell(CurrentCellInformation *cellInfo);
    bool ProcessCurrentCellWcdma(CurrentCellInformation *cellInfo);
    bool ProcessCurrentCellLte(CurrentCellInformation *cellInfo);
    bool ProcessCurrentCellGsm(CurrentCellInformation *cellInfo);
    bool ProcessCurrentCellCdma(CurrentCellInformation *cellInfo);
    bool ProcessCurrentCellTdscdma(CurrentCellInformation *cellInfo);
    bool ProcessCurrentCellNr(CurrentCellInformation *cellInfo);
    int32_t GetCurrentSignalLevelGsm(int32_t rxlev);
    int32_t GetCurrentSignalLevelLte(int32_t rsrp);
    int32_t GetCurrentSignalLevelWcdma(int32_t rscp);
    int32_t GetCurrentSignalLevelCdma(int32_t pilotStrength);
    int32_t GetCurrentSignalLevelTdscdma(int32_t rscp);
    int32_t GetCurrentSignalLevelNr(int32_t rsrp);
    void AddCellInformation(sptr<CellInformation> &cellInfo, std::vector<sptr<CellInformation>> &cellInfos);
    void NotifyCellInfoUpdated() const;
    void UpdateSignalLevel(sptr<CellInformation> &cell, CellInformation::CellType cellType);
    CellInformation::CellType ConvertToCellType(SignalInformation::NetworkType signalType) const;
    CellInformation::CellType ConvertTechToCellType(RadioTech techType) const;
    CellInformation::CellType ConvertRatToCellType(int ratType) const;
    sptr<CellLocation> GetCellLocationExt(CellInformation::CellType type);
    std::mutex mutex_;
    std::vector<sptr<CellInformation>> cellInfos_;
    sptr<CellInformation> currentCellInfo_ = nullptr;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;

    using CallInfoFunc = bool (CellInfo::*)(CellNearbyInfo *);
    static const std::map<RatType, CallInfoFunc> memberFuncMap_;
    int32_t slotId_ = 0;
    static int32_t signalBar_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_CELL_INFO_H