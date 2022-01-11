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
{
    memberFuncMap_[RatType::NETWORK_TYPE_GSM] = &CellManager::ProcessNeighboringCellGsm;
    memberFuncMap_[RatType::NETWORK_TYPE_CDMA] = &CellManager::ProcessNeighboringCellCdma;
    memberFuncMap_[RatType::NETWORK_TYPE_WCDMA] = &CellManager::ProcessNeighboringCellWcdma;
    memberFuncMap_[RatType::NETWORK_TYPE_TDSCDMA] = &CellManager::ProcessNeighboringCellTdscdma;
    memberFuncMap_[RatType::NETWORK_TYPE_LTE] = &CellManager::ProcessNeighboringCellLte;
    memberFuncMap_[RatType::NETWORK_TYPE_NR] = &CellManager::ProcessNeighboringCellNr;
}

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
        auto itFunc = memberFuncMap_.find(type);
        if (itFunc != memberFuncMap_.end()) {
            auto memberFunc = itFunc->second;
            if (memberFunc != nullptr) {
                (this->*memberFunc)(&cell[i]);
            }
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

    ProcessCurrentCell(cellInfo);
    TELEPHONY_LOGI("CellManager::ProcessCurrentCellInfo type:%{public}d, size %{public}zu", cellInfo->ratType,
        cellInfos_.size());
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
            if (gsm->GetCellId() != cellId && gsm->GetLac() != lac) {
                cellInfoChangedFlag_ = true;
                gsm->UpdateLocation(cellId, lac);
            }
            break;
        }
        case CellInformation::CellType::CELL_TYPE_LTE: {
            LteCellInformation *lte = reinterpret_cast<LteCellInformation *>(currentCellInfo_.GetRefPtr());
            if (lte->GetCellId() != cellId && lte->GetTac() != lac) {
                cellInfoChangedFlag_ = true;
                lte->UpdateLocation(cellId, lac);
            }
            break;
        }
        case CellInformation::CellType::CELL_TYPE_WCDMA: {
            WcdmaCellInformation *wcdma = reinterpret_cast<WcdmaCellInformation *>(currentCellInfo_.GetRefPtr());
            if (wcdma->GetCellId() != cellId && wcdma->GetLac() != lac) {
                cellInfoChangedFlag_ = true;
                wcdma->UpdateLocation(cellId, lac);
            }
            break;
        }
        case CellInformation::CellType::CELL_TYPE_CDMA:
            break;
        case CellInformation::CellType::CELL_TYPE_TDSCDMA: {
            TdscdmaCellInformation *tdscdma =
                reinterpret_cast<TdscdmaCellInformation *>(currentCellInfo_.GetRefPtr());
            if (tdscdma->GetCellId() != cellId && tdscdma->GetLac() != lac) {
                cellInfoChangedFlag_ = true;
                tdscdma->UpdateLocation(cellId, lac);
            }
            break;
        }
        case CellInformation::CellType::CELL_TYPE_NR: {
            NrCellInformation *nr = reinterpret_cast<NrCellInformation *>(currentCellInfo_.GetRefPtr());
            if (nr->GetCellId() != cellId && nr->GetTac() != lac) {
                cellInfoChangedFlag_ = true;
                nr->UpdateLocation(cellId, lac);
            }
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
        case SignalInformation::NetworkType::CDMA:
            return CellInformation::CellType::CELL_TYPE_CDMA;
        case SignalInformation::NetworkType::TDSCDMA:
            return CellInformation::CellType::CELL_TYPE_TDSCDMA;
        case SignalInformation::NetworkType::NR:
            return CellInformation::CellType::CELL_TYPE_NR;
        default:
            return CellInformation::CellType::CELL_TYPE_NONE;
    }
}

CellInformation::CellType CellManager::ConvertRatToCellType(int ratType) const
{
    switch (ratType) {
        case RatType::NETWORK_TYPE_GSM:
            return CellInformation::CellType::CELL_TYPE_GSM;
        case RatType::NETWORK_TYPE_WCDMA:
            return CellInformation::CellType::CELL_TYPE_WCDMA;
        case RatType::NETWORK_TYPE_LTE:
            return CellInformation::CellType::CELL_TYPE_LTE;
        case RatType::NETWORK_TYPE_CDMA:
            return CellInformation::CellType::CELL_TYPE_CDMA;
        case RatType::NETWORK_TYPE_TDSCDMA:
            return CellInformation::CellType::CELL_TYPE_TDSCDMA;
        case RatType::NETWORK_TYPE_NR:
            return CellInformation::CellType::CELL_TYPE_NR;
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
        case RadioTech::RADIO_TECHNOLOGY_HSPAP:
        case RadioTech::RADIO_TECHNOLOGY_HSPA:
            return CellInformation::CellType::CELL_TYPE_WCDMA;
        case RadioTech::RADIO_TECHNOLOGY_LTE:
            return CellInformation::CellType::CELL_TYPE_LTE;
        case RadioTech::RADIO_TECHNOLOGY_TD_SCDMA:
            return CellInformation::CellType::CELL_TYPE_TDSCDMA;
        case RadioTech::RADIO_TECHNOLOGY_1XRTT:
        case RadioTech::RADIO_TECHNOLOGY_EVDO:
        case RadioTech::RADIO_TECHNOLOGY_EHRPD:
            return CellInformation::CellType::CELL_TYPE_CDMA;
        default:
            return CellInformation::CellType::CELL_TYPE_NONE;
    }
}

bool CellManager::ProcessCurrentCell(CurrentCellInfo *cellInfo)
{
    bool ret = false;
    UpdateSignalLevel(ConvertRatToCellType(cellInfo->ratType));
    switch (cellInfo->ratType) {
        case RatType::NETWORK_TYPE_GSM: {
            ret = ProcessCurrentCellGsm(cellInfo);
            break;
        }
        case RatType::NETWORK_TYPE_LTE: {
            ret = ProcessCurrentCellLte(cellInfo);
            break;
        }
        case RatType::NETWORK_TYPE_WCDMA: {
            ret = ProcessCurrentCellWcdma(cellInfo);
            break;
        }
        case RatType::NETWORK_TYPE_TDSCDMA: {
            ret = ProcessCurrentCellTdscdma(cellInfo);
            break;
        }
        case RatType::NETWORK_TYPE_CDMA: {
            ret = ProcessCurrentCellCdma(cellInfo);
            break;
        }
        case RatType::NETWORK_TYPE_NR: {
            ret = ProcessCurrentCellNr(cellInfo);
            break;
        }
        default: {
            TELEPHONY_LOGI("CellManager::ProcessCurrentCell error rat type:%{public}d", cellInfo->ratType);
            return false;
        }
    }
    if (!ret) {
        TELEPHONY_LOGI("CellManager::ProcessCurrentCell currentCellInfo is null or cell info no change");
        return false;
    }
    currentCellInfo_->SetIsCamped(true);
    return true;
}

bool CellManager::ProcessNeighboringCellGsm(CellNearbyInfo *cellInfo)
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
            "CellManager::ProcessNeighboringCellGsm arfcn:%{public}d cellId:%{private}d"
            "bsic:%{private}d lac:%{private}d",
            arfcn, cellId, bsic, lac);
        return true;
    }
    return false;
}

bool CellManager::ProcessNeighboringCellLte(CellNearbyInfo *cellInfo)
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

bool CellManager::ProcessNeighboringCellWcdma(CellNearbyInfo *cellInfo)
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

bool CellManager::ProcessNeighboringCellCdma(CellNearbyInfo *cellInfo)
{
    sptr<CdmaCellInformation> cell = new CdmaCellInformation;
    if (cell != nullptr) {
        int32_t &baseId = cellInfo->ServiceCellParas.cdma.baseId;
        int32_t &longitude = cellInfo->ServiceCellParas.cdma.longitude;
        int32_t &latitude = cellInfo->ServiceCellParas.cdma.latitude;
        int32_t &networkId = cellInfo->ServiceCellParas.cdma.networkId;
        int32_t &systemId = cellInfo->ServiceCellParas.cdma.systemId;
        cell->Init(0, 0, 0);
        cell->SetCdmaParam(baseId, latitude, longitude, networkId, systemId);
        cellInfos_.emplace_back(cell);
        TELEPHONY_LOGI("CellManager::ProcessCdma baseId:%{public}d psc:%{public}d", baseId, systemId);
        return true;
    }
    return false;
}

bool CellManager::ProcessNeighboringCellTdscdma(CellNearbyInfo *cellInfo)
{
    sptr<TdscdmaCellInformation> cell = new TdscdmaCellInformation;
    if (cell != nullptr) {
        int32_t &arfcn = cellInfo->ServiceCellParas.tdscdma.arfcn;
        int32_t &cpid = cellInfo->ServiceCellParas.tdscdma.cpid;
        int32_t &lac = cellInfo->ServiceCellParas.tdscdma.lac;
        cell->Init(0, 0, 0);
        cell->SetTdscdmaParam(cpid, lac, arfcn);
        cellInfos_.emplace_back(cell);
        TELEPHONY_LOGI("CellManager::ProcessTdscdma arfcn:%{public}d psc:%{public}d", arfcn, cpid);
        return true;
    }
    return false;
}

bool CellManager::ProcessNeighboringCellNr(CellNearbyInfo *cellInfo)
{
    sptr<NrCellInformation> cell = new NrCellInformation;
    if (cell != nullptr) {
        int32_t &nrArfcn = cellInfo->ServiceCellParas.nr.nrArfcn;
        int32_t &pci = cellInfo->ServiceCellParas.nr.pci;
        int32_t &tac = cellInfo->ServiceCellParas.nr.tac;
        int32_t &nci = cellInfo->ServiceCellParas.nr.nci;
        cell->Init(0, 0, 0);
        cell->SetNrParam(nrArfcn, pci, tac, nci);
        cellInfos_.emplace_back(cell);
        TELEPHONY_LOGI("CellManager::ProcessNeighboringCellNr arfcn:%{public}d pci:%{public}d", nrArfcn, pci);
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
            cellInfoChangedFlag_ = false;
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
            cellInfoChangedFlag_ = false;
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
            cellInfoChangedFlag_ = false;
            return false;
        }

        cellInfoChangedFlag_ = true;
        currentCellInfo_ = cell;
        TELEPHONY_LOGI("CellManager::ProcessCurrentCellWcdma arfcn:%{public}d psc:%{private}d", arfcn, psc);
        return true;
    }
    return false;
}

bool CellManager::ProcessCurrentCellCdma(CurrentCellInfo *cellInfo)
{
    sptr<CdmaCellInformation> cell = new CdmaCellInformation;
    if (cell != nullptr) {
        int32_t &baseId = cellInfo->ServiceCellParas.cdma.baseId;
        int32_t &longitude = cellInfo->ServiceCellParas.cdma.longitude;
        int32_t &latitude = cellInfo->ServiceCellParas.cdma.latitude;
        int32_t &networkId = cellInfo->ServiceCellParas.cdma.networkId;
        int32_t &systemId = cellInfo->ServiceCellParas.cdma.systemId;
        cell->Init(cellInfo->mcc, cellInfo->mnc, baseId);
        cell->SetCdmaParam(baseId, latitude, longitude, networkId, systemId);
        if (currentCellInfo_ && *(static_cast<CdmaCellInformation *>(currentCellInfo_.GetRefPtr())) == *cell) {
            TELEPHONY_LOGI("CellManager::ProcessCurrentCellCdma no changed");
            cellInfoChangedFlag_ = false;
            return false;
        }

        cellInfoChangedFlag_ = true;
        currentCellInfo_ = cell;
        TELEPHONY_LOGI(
            "CellManager::ProcessCurrentCellCdma baseId:%{public}d networkId:%{private}d", baseId, networkId);
        return true;
    }
    return false;
}

bool CellManager::ProcessCurrentCellTdscdma(CurrentCellInfo *cellInfo)
{
    sptr<TdscdmaCellInformation> cell = new TdscdmaCellInformation;
    if (cell != nullptr) {
        int32_t &arfcn = cellInfo->ServiceCellParas.tdscdma.arfcn;
        int32_t &cpid = cellInfo->ServiceCellParas.tdscdma.cpid;
        int32_t &cellId = cellInfo->ServiceCellParas.tdscdma.cellId;
        int32_t &lac = cellInfo->ServiceCellParas.tdscdma.lac;
        cell->Init(cellInfo->mcc, cellInfo->mnc, cellId);
        cell->SetTdscdmaParam(cpid, lac, arfcn);
        if (currentCellInfo_ && *(static_cast<TdscdmaCellInformation *>(currentCellInfo_.GetRefPtr())) == *cell) {
            TELEPHONY_LOGI("CellManager::ProcessCurrentCellTdscdma no changed");
            cellInfoChangedFlag_ = false;
            return false;
        }

        cellInfoChangedFlag_ = true;
        currentCellInfo_ = cell;
        TELEPHONY_LOGI("CellManager::ProcessCurrentCellTdscdma arfcn:%{public}d pci:%{private}d", arfcn, cpid);
        return true;
    }
    return false;
}

bool CellManager::ProcessCurrentCellNr(CurrentCellInfo *cellInfo)
{
    sptr<NrCellInformation> cell = new NrCellInformation;
    if (cell != nullptr) {
        int32_t &nrArfcn = cellInfo->ServiceCellParas.nr.nrArfcn;
        int32_t &pci = cellInfo->ServiceCellParas.nr.pci;
        int32_t &tac = cellInfo->ServiceCellParas.nr.tac;
        int32_t &nci = cellInfo->ServiceCellParas.nr.nci;
        cell->Init(cellInfo->mcc, cellInfo->mnc, 0);
        cell->SetNrParam(nrArfcn, pci, tac, nci);
        if (currentCellInfo_ && *(static_cast<NrCellInformation *>(currentCellInfo_.GetRefPtr())) == *cell) {
            TELEPHONY_LOGI("CellManager::ProcessCurrentCellNr no changed");
            cellInfoChangedFlag_ = false;
            return false;
        }

        cellInfoChangedFlag_ = true;
        currentCellInfo_ = cell;
        TELEPHONY_LOGI("CellManager::ProcessCurrentCellNr arfcn:%{public}d pci:%{private}d", nrArfcn, pci);
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
            break;
        }
        case CellInformation::CellType::CELL_TYPE_WCDMA: {
            sptr<WcdmaCellInformation> cell = new WcdmaCellInformation;
            WcdmaCellInformation &wcdmaCell = *cell;
            wcdmaCell = *(static_cast<WcdmaCellInformation *>(cellInfo.GetRefPtr()));
            cellInfos.emplace_back(cell);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_CDMA: {
            sptr<CdmaCellInformation> cell = new CdmaCellInformation;
            CdmaCellInformation &cdmaCell = *cell;
            cdmaCell = *(static_cast<CdmaCellInformation *>(cellInfo.GetRefPtr()));
            cellInfos.emplace_back(cell);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_TDSCDMA: {
            sptr<TdscdmaCellInformation> cell = new TdscdmaCellInformation;
            TdscdmaCellInformation &tdscdmaCell = *cell;
            tdscdmaCell = *(static_cast<TdscdmaCellInformation *>(cellInfo.GetRefPtr()));
            cellInfos.emplace_back(cell);
            break;
        }
        case CellInformation::CellType::CELL_TYPE_NR: {
            sptr<NrCellInformation> cell = new NrCellInformation;
            NrCellInformation &nrCell = *cell;
            nrCell = *(static_cast<NrCellInformation *>(cellInfo.GetRefPtr()));
            cellInfos.emplace_back(cell);
            break;
        }
        default:
            break;
    }
}

sptr<CellLocation> CellManager::GetCellLocation()
{
    if (currentCellInfo_ == nullptr) {
        TELEPHONY_LOGE("CellManager::GetCellLocation is null");
        return nullptr;
    }
    CellInformation::CellType type = currentCellInfo_->GetNetworkType();
    switch (type) {
        case CellInformation::CellType::CELL_TYPE_GSM: {
            sptr<TdscdmaCellInformation> cellinfo =
                static_cast<TdscdmaCellInformation *>(currentCellInfo_.GetRefPtr());
            sptr<GsmCellLocation> cellLocation = new GsmCellLocation;
            cellLocation->SetGsmParam(cellinfo->GetCellId(), cellinfo->GetLac());
            return cellLocation;
        }
        case CellInformation::CellType::CELL_TYPE_TDSCDMA: {
            sptr<GsmCellInformation> cellinfo = static_cast<GsmCellInformation *>(currentCellInfo_.GetRefPtr());
            sptr<GsmCellLocation> cellLocation = new GsmCellLocation;
            cellLocation->SetGsmParam(cellinfo->GetCellId(), cellinfo->GetLac());
            return cellLocation;
        }
        case CellInformation::CellType::CELL_TYPE_LTE: {
            sptr<LteCellInformation> cellinfo = static_cast<LteCellInformation *>(currentCellInfo_.GetRefPtr());
            sptr<GsmCellLocation> cellLocation = new GsmCellLocation;
            cellLocation->SetGsmParam(cellinfo->GetCellId(), cellinfo->GetTac());
            return cellLocation;
        }
        case CellInformation::CellType::CELL_TYPE_WCDMA: {
            sptr<WcdmaCellInformation> cellinfo = static_cast<WcdmaCellInformation *>(currentCellInfo_.GetRefPtr());
            sptr<GsmCellLocation> cellLocation = new GsmCellLocation;
            cellLocation->SetGsmParam(cellinfo->GetCellId(), cellinfo->GetLac(), cellinfo->GetPsc());
            return cellLocation;
        }
        case CellInformation::CellType::CELL_TYPE_CDMA: {
            sptr<CdmaCellInformation> cellinfo = static_cast<CdmaCellInformation *>(currentCellInfo_.GetRefPtr());
            sptr<CdmaCellLocation> cellLocation = new CdmaCellLocation;
            cellLocation->SetCdmaParam(cellinfo->GetBaseId(), cellinfo->GetLatitude(), cellinfo->GetLongitude(),
                cellinfo->GetNid(), cellinfo->GetSid());
            return cellLocation;
        }
        default:
            TELEPHONY_LOGE("CellManager::GetCellLocation cell type error");
            break;
    }
    return nullptr;
}
} // namespace Telephony
} // namespace OHOS