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

#include "cell_manager.h"
#include "telephony_log_wrapper.h"
#include "network_search_manager.h"
#include "network_search_notify.h"

namespace OHOS {
namespace Telephony {
CellManager::CellManager(std::weak_ptr<NetworkSearchManager> networkSearchManager)
    : networkSearchManager_(networkSearchManager)
{}

void CellManager::ProcessNeighboringCellInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("CellManager::ProcessNeighboringCellInfo cell info start......");
    std::lock_guard<std::mutex> lock(mutex_);
    if (event == nullptr) {
        TELEPHONY_LOGE("CellManager::ProcessNeighboringCellInfo event is nullptr");
        return;
    }

    CellListNearbyInfo *cellInfo = event->GetSharedObject<CellListNearbyInfo>().get();
    if (cellInfo == nullptr) {
        TELEPHONY_LOGE("CellManager::ProcessNeighboringCellInfo rssi is nullptr");
        return;
    }

    int32_t cellSize = cellInfo->itemNum >= CellInformation::MAX_CELL_NUM ? CellInformation::MAX_CELL_NUM :
                                                                            cellInfo->itemNum;
    if (cellSize > 0) {
        cellInfos_.clear();
    } else {
        return;
    }

    TELEPHONY_LOGI("CellManager::ProcessNeighboringCellInfo cell size:%{public}d, cur size:%{public}zu",
        cellInfo->itemNum, cellInfos_.size());
    std::vector<CellNearbyInfo> cell = cellInfo->cellNearbyInfo;
    for (int32_t i = 0; i < cellSize; ++i) {
        int32_t type = cell[i].ratType;
        switch (type) {
            case RatType::NETWORK_TYPE_GSM: {
                ProcessNeighboringGsm(&cell[i]);
                break;
            }
            case RatType::NETWORK_TYPE_LTE: {
                ProcessNeighboringLte(&cell[i]);
                break;
            }
            case RatType::NETWORK_TYPE_WCDMA: {
                ProcessNeighboringWcdma(&cell[i]);
                break;
            }
            default:
                break;
        }
    }
}

void CellManager::ProcessCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("CellManager::ProcessCurrentCellInfo cell info start...");
    std::lock_guard<std::mutex> lock(mutex_);
    if (event == nullptr) {
        TELEPHONY_LOGE("CellManager::ProcessCurrentCellInfo event is nullptr");
        return;
    }
    CurrentCellInfo *cellInfo = event->GetSharedObject<CurrentCellInfo>().get();
    if (cellInfo == nullptr) {
        TELEPHONY_LOGE("CellManager::ProcessCurrentCellInfo rssi is nullptr");
        return;
    }
    cellInfoChangedFlag_ = true;
    ProcessCurrentCell(cellInfo);
    TELEPHONY_LOGI("CellManager::ProcessCurrentCellInfo size %{public}zu", cellInfos_.size());
    NotifyCellInfoUpdated();
}

void CellManager::NotifyCellInfoUpdated() const
{
    if (cellInfoChangedFlag_ && currentCellInfo_ != nullptr) {
        std::vector<sptr<CellInformation>> allCellInfos;
        allCellInfos.emplace_back(currentCellInfo_);

        DelayedSingleton<NetworkSearchNotify>::GetInstance()->NotifyCellInfoUpdated(allCellInfos);
    } else {
        TELEPHONY_LOGI("CellManager::NotifyCellInfoUpdated no notify");
    }
}

void CellManager::UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac)
{
    CellInformation::CellType type = ConvertTechToCellType(static_cast<RadioTech>(techType));
    if (currentCellInfo_ == nullptr || type == CellInformation::CellType::CELL_TYPE_NONE ||
        currentCellInfo_->GetNetworkType() != type) {
        TELEPHONY_LOGE("CellManager::UpdateCellLocation type error");
        return;
    }

    cellInfoChangedFlag_ = false;
    ProcessCellLocation(type, cellId, lac);
    UpdateSignalLevel(type);
    NotifyCellInfoUpdated();
}

void CellManager::ProcessCellLocation(CellInformation::CellType type, int32_t cellId, int32_t lac)
{
    switch (type) {
        case CellInformation::CellType::CELL_TYPE_GSM: {
            GsmCellInformation *gsm = reinterpret_cast<GsmCellInformation *>(currentCellInfo_.GetRefPtr());
            if (gsm->GetLac() != lac) {
                cellInfoChangedFlag_ = true;
                gsm->UpdateLocation(cellId, lac);
            }
            break;
        }
        case CellInformation::CellType::CELL_TYPE_LTE: {
            LteCellInformation *lte = reinterpret_cast<LteCellInformation *>(currentCellInfo_.GetRefPtr());
            if (lte->GetTac() != lac) {
                cellInfoChangedFlag_ = true;
            }
            lte->UpdateLocation(cellId, lac);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_WCDMA: {
            WcdmaCellInformation *wcdma = reinterpret_cast<WcdmaCellInformation *>(currentCellInfo_.GetRefPtr());
            if (wcdma->GetLac() != lac) {
                cellInfoChangedFlag_ = true;
            }
            wcdma->UpdateLocation(cellId, lac);
            break;
        }
        default:
            TELEPHONY_LOGE("CellManager::ProcessCellLocation type error");
            break;
    }
}

void CellManager::UpdateSignalLevel(CellInformation::CellType cellType)
{
    if (currentCellInfo_ == nullptr) {
        TELEPHONY_LOGE("CellManager::UpdateSignalLevel currentCellInfo_ is null");
        return;
    }

    if (cellType == CellInformation::CellType::CELL_TYPE_NONE || currentCellInfo_->GetNetworkType() != cellType) {
        TELEPHONY_LOGE("CellManager::UpdateSignalLevel type error");
        return;
    }

    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("CellManager::UpdateSignalLevel nsm is nullptr");
        return;
    }

    std::vector<sptr<SignalInformation>> signals = nsm->GetSignalInfoList(1);
    int32_t signalLevel = 0;
    for (const auto &v : signals) {
        if (ConvertToCellType(v->GetNetworkType()) == cellType) {
            TELEPHONY_LOGI("CellManager::UpdateSignalLevel signal level %{public}d", v->GetSignalLevel());
            signalLevel = v->GetSignalLevel();
            break;
        }
    }
    currentCellInfo_->SetSignalLevel(signalLevel);
}

CellInformation::CellType CellManager::ConvertToCellType(SignalInformation::NetworkType signalType) const
{
    switch (signalType) {
        case SignalInformation::NetworkType::GSM:
            return CellInformation::CellType::CELL_TYPE_GSM;
        case SignalInformation::NetworkType::WCDMA:
            return CellInformation::CellType::CELL_TYPE_WCDMA;
        case SignalInformation::NetworkType::LTE:
            return CellInformation::CellType::CELL_TYPE_LTE;
        default:
            return CellInformation::CellType::CELL_TYPE_NONE;
    }
}

CellInformation::CellType CellManager::ConvertRatToCellType(int ratType) const
{
    switch (ratType) {
        case RatType::NETWORK_TYPE_GSM: {
            return CellInformation::CellType::CELL_TYPE_GSM;
        }
        case RatType::NETWORK_TYPE_WCDMA: {
            return CellInformation::CellType::CELL_TYPE_WCDMA;
        }
        case RatType::NETWORK_TYPE_LTE: {
            return CellInformation::CellType::CELL_TYPE_LTE;
        }
        default:
            return CellInformation::CellType::CELL_TYPE_NONE;
    }
}

CellInformation::CellType CellManager::ConvertTechToCellType(RadioTech techType) const
{
    switch (techType) {
        case RadioTech::RADIO_TECHNOLOGY_GSM:
            return CellInformation::CellType::CELL_TYPE_GSM;
        case RadioTech::RADIO_TECHNOLOGY_WCDMA:
            return CellInformation::CellType::CELL_TYPE_WCDMA;
        case RadioTech::RADIO_TECHNOLOGY_LTE:
            return CellInformation::CellType::CELL_TYPE_LTE;
        default:
            return CellInformation::CellType::CELL_TYPE_NONE;
    }
}

bool CellManager::ProcessCurrentCell(CurrentCellInfo *cellInfo)
{
    bool ret = false;
    if (cellInfo->ratType == RatType::NETWORK_TYPE_GSM) {
        ret = ProcessCurrentCellGsm(cellInfo);
    } else if (cellInfo->ratType == RatType::NETWORK_TYPE_LTE) {
        ret = ProcessCurrentCellLte(cellInfo);
    } else if (cellInfo->ratType == RatType::NETWORK_TYPE_WCDMA) {
        ret = ProcessCurrentCellWcdma(cellInfo);
    } else {
        TELEPHONY_LOGI("CellManager::ProcessCurrentCell error rat type:%{public}d", cellInfo->ratType);
        return false;
    }

    if (!ret) {
        TELEPHONY_LOGE("CellManager::ProcessCurrentCell error");
        return ret;
    }
    currentCellInfo_->SetIsCamped(true);
    UpdateSignalLevel(ConvertRatToCellType(cellInfo->ratType));

    return true;
}

bool CellManager::ProcessNeighboringGsm(CellNearbyInfo *cellInfo)
{
    sptr<GsmCellInformation> cell = new GsmCellInformation;
    if (cell != nullptr) {
        int32_t &arfcn = cellInfo->ServiceCellParas.gsm.arfcn;
        int32_t &cellId = cellInfo->ServiceCellParas.gsm.cellId;
        int32_t &bsic = cellInfo->ServiceCellParas.gsm.bsic;
        int32_t &lac = cellInfo->ServiceCellParas.gsm.lac;
        cell->Init(0, 0, cellId);
        cell->SetGsmParam(bsic, lac, arfcn);
        cellInfos_.emplace_back(cell);
        TELEPHONY_LOGI(
            "CellManager::ProcessNeighboringGsm arfcn:%{public}d cellId:%{private}d"
            "bsic:%{private}d lac:%{private}d",
            arfcn, cellId, bsic, lac);
        return true;
    }
    return false;
}

bool CellManager::ProcessNeighboringLte(CellNearbyInfo *cellInfo)
{
    sptr<LteCellInformation> cell = new LteCellInformation;
    if (cell != nullptr) {
        int32_t &arfcn = cellInfo->ServiceCellParas.lte.arfcn;
        int32_t pci = cellInfo->ServiceCellParas.lte.pci;
        cell->Init(0, 0, 0);
        cell->SetLteParam(pci, 0, arfcn);
        cellInfos_.emplace_back(cell);
        TELEPHONY_LOGI("CellManager::ProcessLte arfcn:%{public}d pci:%{private}d", arfcn, pci);
        return true;
    }
    return false;
}

bool CellManager::ProcessNeighboringWcdma(CellNearbyInfo *cellInfo)
{
    sptr<WcdmaCellInformation> cell = new WcdmaCellInformation;
    if (cell != nullptr) {
        int32_t &arfcn = cellInfo->ServiceCellParas.wcdma.arfcn;
        int32_t psc = cellInfo->ServiceCellParas.wcdma.psc;
        cell->Init(0, 0, 0);
        cell->SetWcdmaParam(psc, 0, arfcn);
        cellInfos_.emplace_back(cell);
        TELEPHONY_LOGI("CellManager::ProcessWcdma arfcn:%{public}d psc:%{public}d", arfcn, psc);
        return true;
    }
    return false;
}

bool CellManager::ProcessCurrentCellGsm(CurrentCellInfo *cellInfo)
{
    sptr<GsmCellInformation> cell = new GsmCellInformation;
    if (cell != nullptr) {
        int32_t &arfcn = cellInfo->ServiceCellParas.gsm.arfcn;
        int32_t &cellId = cellInfo->ServiceCellParas.gsm.cellId;
        int32_t &bsic = cellInfo->ServiceCellParas.gsm.bsic;
        int32_t &lac = cellInfo->ServiceCellParas.gsm.lac;
        cell->Init(cellInfo->mcc, cellInfo->mnc, cellId);
        cell->SetGsmParam(bsic, lac, arfcn);
        if (currentCellInfo_ && *(static_cast<GsmCellInformation *>(currentCellInfo_.GetRefPtr())) == *cell) {
            TELEPHONY_LOGI("CellManager::ProcessCurrentCellLte no changed");
            return false;
        }

        cellInfoChangedFlag_ = true;
        currentCellInfo_ = cell;
        TELEPHONY_LOGI(
            "CellManager::ProcessCurrentCellGsm arfcn:%{public}d cellId:%{private}d"
            "bsic:%{private}d lac:%{private}d",
            arfcn, cellId, bsic, lac);
        return true;
    }
    return false;
}

bool CellManager::ProcessCurrentCellLte(CurrentCellInfo *cellInfo)
{
    sptr<LteCellInformation> cell = new LteCellInformation;
    if (cell != nullptr) {
        int32_t &arfcn = cellInfo->ServiceCellParas.lte.arfcn;
        int32_t &pci = cellInfo->ServiceCellParas.lte.pci;
        int32_t &cellId = cellInfo->ServiceCellParas.lte.cellId;
        int32_t &tac = cellInfo->ServiceCellParas.lte.tac;
        cell->Init(cellInfo->mcc, cellInfo->mnc, cellId);
        cell->SetLteParam(pci, tac, arfcn);
        if (currentCellInfo_ && *(static_cast<LteCellInformation *>(currentCellInfo_.GetRefPtr())) == *cell) {
            TELEPHONY_LOGI("CellManager::ProcessCurrentCellLte no changed");
            return false;
        }

        cellInfoChangedFlag_ = true;
        currentCellInfo_ = cell;
        TELEPHONY_LOGI("CellManager::ProcessCurrentCellLte arfcn:%{public}d pci:%{private}d", arfcn, pci);
        return true;
    }
    return false;
}

bool CellManager::ProcessCurrentCellWcdma(CurrentCellInfo *cellInfo)
{
    sptr<WcdmaCellInformation> cell = new WcdmaCellInformation;
    if (cell != nullptr) {
        int32_t &arfcn = cellInfo->ServiceCellParas.wcdma.arfcn;
        int32_t &psc = cellInfo->ServiceCellParas.wcdma.psc;
        int32_t &cellId = cellInfo->ServiceCellParas.wcdma.cellId;
        int32_t &lac = cellInfo->ServiceCellParas.wcdma.lac;
        cell->Init(cellInfo->mcc, cellInfo->mnc, cellId);
        cell->SetWcdmaParam(psc, lac, arfcn);
        if (currentCellInfo_ && *(static_cast<WcdmaCellInformation *>(currentCellInfo_.GetRefPtr())) == *cell) {
            TELEPHONY_LOGI("CellManager::ProcessCurrentCellWcdma no changed");
            return false;
        }

        cellInfoChangedFlag_ = true;
        currentCellInfo_ = cell;
        TELEPHONY_LOGI("CellManager::ProcessCurrentCellWcdma arfcn:%{public}d psc:%{private}d", arfcn, psc);
        return true;
    }
    return false;
}

void CellManager::GetCellInfoList(std::vector<sptr<CellInformation>> &cellInfo)
{
    cellInfo.clear();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (currentCellInfo_ != nullptr) {
            AddCellInformation(currentCellInfo_, cellInfo);
        }
        for (auto &cell : cellInfos_) {
            AddCellInformation(cell, cellInfo);
        }
    }
    TELEPHONY_LOGI("CellManager::GetCellInfoList size:%{public}zu", cellInfo.size());
}

void CellManager::ClearCellInfoList()
{
    std::lock_guard<std::mutex> lock(mutex_);
    currentCellInfo_ = nullptr;
    cellInfos_.clear();
}

void CellManager::AddCellInformation(sptr<CellInformation> &cellInfo, std::vector<sptr<CellInformation>> &cellInfos)
{
    CellInformation::CellType type = cellInfo->GetNetworkType();
    switch (type) {
        case CellInformation::CellType::CELL_TYPE_GSM: {
            sptr<GsmCellInformation> cell = new GsmCellInformation;
            GsmCellInformation &gsmCell = *cell;
            gsmCell = *(static_cast<GsmCellInformation *>(cellInfo.GetRefPtr()));
            cellInfos.emplace_back(cell);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_LTE: {
            sptr<LteCellInformation> cell = new LteCellInformation;
            LteCellInformation &lteCell = *cell;
            lteCell = *(static_cast<LteCellInformation *>(cellInfo.GetRefPtr()));
            cellInfos.emplace_back(cell);

            TELEPHONY_LOGI("CellManager::GetCellInfoList type :%{public}d ....", lteCell.GetNetworkType());
            break;
        }
        case CellInformation::CellType::CELL_TYPE_WCDMA: {
            sptr<WcdmaCellInformation> cell = new WcdmaCellInformation;
            WcdmaCellInformation &wcdmaCell = *cell;
            wcdmaCell = *(static_cast<WcdmaCellInformation *>(cellInfo.GetRefPtr()));
            cellInfos.emplace_back(cell);

            TELEPHONY_LOGI("CellManager::GetCellInfoList type :%{public}d ....", wcdmaCell.GetNetworkType());
            break;
        }
        default:
            break;
    }
}
} // namespace Telephony
} // namespace OHOS