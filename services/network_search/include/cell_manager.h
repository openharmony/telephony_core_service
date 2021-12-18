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

#ifndef OHOS_CELL_MANAGER_H
#define OHOS_CELL_MANAGER_H

#include "event_handler.h"
#include "hril_network_parcel.h"
#include "cell_information.h"
#include "signal_information.h"
#include "network_state.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class CellManager {
public:
    CellManager(std::weak_ptr<NetworkSearchManager> networkSearchManager);
    virtual ~CellManager() = default;
    void GetCellInfoList(std::vector<sptr<CellInformation>> &cellInfo);
    void ProcessNeighboringCellInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void ClearCellInfoList();
    void UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac);
private:
    void ProcessCellLocation(CellInformation::CellType type, int32_t cellId, int32_t lac);
    bool ProcessNeighboringGsm(CellNearbyInfo *cellInfo);
    bool ProcessNeighboringLte(CellNearbyInfo *cellInfo);
    bool ProcessNeighboringWcdma(CellNearbyInfo *cellInfo);
    bool ProcessCurrentCell(CurrentCellInfo *cellInfo);
    bool ProcessCurrentCellWcdma(CurrentCellInfo *cellInfo);
    bool ProcessCurrentCellLte(CurrentCellInfo *cellInfo);
    bool ProcessCurrentCellGsm(CurrentCellInfo *cellInfo);
    void AddCellInformation(sptr<CellInformation>& cellInfo, std::vector<sptr<CellInformation>> &cellInfos);
    void NotifyCellInfoUpdated() const;
    void UpdateSignalLevel(CellInformation::CellType cellType);
    CellInformation::CellType ConvertToCellType(SignalInformation::NetworkType signalType) const;
    CellInformation::CellType ConvertTechToCellType(RadioTech techType) const;
    CellInformation::CellType ConvertRatToCellType(int ratType) const;
    std::mutex mutex_;
    std::vector<sptr<CellInformation>> cellInfos_;
    sptr<CellInformation> currentCellInfo_ = nullptr;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    bool cellInfoChangedFlag_ = false;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_CELL_MANAGER_H