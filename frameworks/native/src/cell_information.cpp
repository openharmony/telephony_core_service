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

#include "cell_information.h"
#include <ctime>

namespace OHOS {
namespace Telephony {
void CellInformation::Init(int32_t mcc, int32_t mnc, int32_t cellId)
{
    mcc_ = mcc;
    mnc_ = mnc;
    cellId_ = cellId;
    timeStamp_ = time(0);
}

int32_t CellInformation::GetCellId() const
{
    return cellId_;
}

int32_t CellInformation::GetMcc() const
{
    return mcc_;
}

int32_t CellInformation::GetMnc() const
{
    return mnc_;
}

uint64_t CellInformation::GetTimeStamp() const
{
    return timeStamp_;
}

int32_t CellInformation::GetSignalLevel() const
{
    return signalLevel_;
}

void CellInformation::SetSignalLevel(int32_t signalLevel)
{
    signalLevel_ = signalLevel;
    timeStamp_ = time(0);
}

bool CellInformation::GetIsCamped() const
{
    return isCamped_;
}

void CellInformation::SetIsCamped(bool isCamped)
{
    isCamped_ = isCamped;
    timeStamp_ = time(0);
}

void GsmCellInformation::SetGsmParam(int32_t bsic, int32_t lac, int32_t arfcn)
{
    bsic_ = bsic;
    lac_ = lac;
    arfcn_= arfcn;
}

GsmCellInformation::GsmCellInformation(const GsmCellInformation &gsmCell)
{
    mcc_ = gsmCell.mcc_;
    mnc_ = gsmCell.mnc_;
    arfcn_ = gsmCell.arfcn_;
    cellId_ = gsmCell.cellId_;
    bsic_ = gsmCell.bsic_;
    lac_ = gsmCell.lac_;
    timeStamp_ = gsmCell.timeStamp_;
    signalLevel_ = gsmCell.signalLevel_;
    isCamped_ = gsmCell.isCamped_;
}

GsmCellInformation &GsmCellInformation::operator=(const GsmCellInformation &gsmCell)
{
    mcc_ = gsmCell.mcc_;
    mnc_ = gsmCell.mnc_;
    arfcn_ = gsmCell.arfcn_;
    cellId_ = gsmCell.cellId_;
    bsic_ = gsmCell.bsic_;
    lac_ = gsmCell.lac_;
    timeStamp_ = gsmCell.timeStamp_;
    signalLevel_ = gsmCell.signalLevel_;
    isCamped_ = gsmCell.isCamped_;
    return *this;
}

bool GsmCellInformation::operator==(const GsmCellInformation &other) const
{
    return mcc_ == other.mcc_ && mnc_ == other.mnc_ &&
           arfcn_ == other.arfcn_ && cellId_ == other.cellId_ &&
           bsic_ == other.bsic_ && lac_ == other.lac_ &&
           timeStamp_ == other.timeStamp_ && signalLevel_ == other.signalLevel_ &&
           isCamped_ == other.isCamped_;
}

CellInformation::CellType GsmCellInformation::GetNetworkType() const
{
    return CellType::CELL_TYPE_GSM;
}

int32_t GsmCellInformation::GetArfcn() const
{
    return arfcn_;
}

std::string GsmCellInformation::ToString() const
{
    int32_t netWorkType = static_cast<int32_t>(GsmCellInformation::GetNetworkType());
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",mcc:" + std::to_string(mcc_) +
        ",mnc:" + std::to_string(mnc_) + ",arfcn:" + std::to_string(arfcn_) + ",cellId:" + std::to_string(cellId_) +
        ",timeStamp:" + std::to_string(timeStamp_) + ",signalLevel:" + std::to_string(signalLevel_) +
        ",bsic:" + std::to_string(bsic_) + ",lac:" + std::to_string(lac_));
    return content;
}

bool GsmCellInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellInformation::CellType::CELL_TYPE_GSM))) {
        return false;
    }
    if (!parcel.WriteInt32(mcc_)) {
        return false;
    }
    if (!parcel.WriteInt32(mnc_)) {
        return false;
    }
    if (!parcel.WriteInt32(arfcn_)) {
        return false;
    }
    if (!parcel.WriteInt32(cellId_)) {
        return false;
    }
    if (!parcel.WriteInt32(bsic_)) {
        return false;
    }
    if (!parcel.WriteInt32(lac_)) {
        return false;
    }
    if (!parcel.WriteInt64(timeStamp_)) {
        return false;
    }
    if (!parcel.WriteInt32(signalLevel_)) {
        return false;
    }
    if (!parcel.WriteBool(isCamped_)) {
        return false;
    }
    return true;
}

GsmCellInformation *GsmCellInformation::Unmarshalling(Parcel &parcel)
{
    GsmCellInformation *param = new (std::nothrow) GsmCellInformation();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool GsmCellInformation::ReadFromParcel(Parcel &parcel)
{
    mcc_ = parcel.ReadInt32();
    mnc_ = parcel.ReadInt32();
    arfcn_ = parcel.ReadInt32();
    cellId_ = parcel.ReadInt32();
    bsic_ = parcel.ReadInt32();
    lac_ = parcel.ReadInt32();
    timeStamp_ = parcel.ReadInt64();
    signalLevel_ = parcel.ReadInt32();
    isCamped_ = parcel.ReadBool();

    return true;
}

int32_t GsmCellInformation::GetLac() const
{
    return lac_;
}

int32_t GsmCellInformation::GetBsic() const
{
    return bsic_;
}

void GsmCellInformation::UpdateLocation(int32_t cellId, int32_t lac)
{
    cellId_ = cellId;
    lac_ = lac;
    timeStamp_ = time(0);
}

void LteCellInformation::SetLteParam(int32_t pci, int32_t tac, int32_t arfcn)
{
    pci_ = pci;
    tac_ = tac;
    earfcn_= arfcn;
}

LteCellInformation::LteCellInformation(const LteCellInformation &lteCell)
{
    mcc_ = lteCell.mcc_;
    mnc_ = lteCell.mnc_;
    earfcn_ = lteCell.earfcn_;
    cellId_ = lteCell.cellId_;
    pci_ = lteCell.pci_;
    tac_ = lteCell.tac_;
    timeStamp_ = lteCell.timeStamp_;
    signalLevel_ = lteCell.signalLevel_;
    isCamped_ = lteCell.isCamped_;
}

LteCellInformation &LteCellInformation::operator=(const LteCellInformation &lteCell)
{
    mcc_ = lteCell.mcc_;
    mnc_ = lteCell.mnc_;
    earfcn_ = lteCell.earfcn_;
    cellId_ = lteCell.cellId_;
    pci_ = lteCell.pci_;
    tac_ = lteCell.tac_;
    timeStamp_ = lteCell.timeStamp_;
    signalLevel_ = lteCell.signalLevel_;
    isCamped_ = lteCell.isCamped_;
    return *this;
}

bool LteCellInformation::operator==(const LteCellInformation &other) const
{
    return mcc_ == other.mcc_ && mnc_ == other.mnc_ &&
           earfcn_ == other.earfcn_ && cellId_ == other.cellId_ &&
           pci_ == other.pci_ && tac_ == other.tac_ &&
           timeStamp_ == other.timeStamp_ && signalLevel_ == other.signalLevel_ &&
           isCamped_ == other.isCamped_;
}

CellInformation::CellType LteCellInformation::GetNetworkType() const
{
    return CellType::CELL_TYPE_LTE;
}

int32_t LteCellInformation::GetArfcn() const
{
    return earfcn_;
}

bool LteCellInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellInformation::CellType::CELL_TYPE_LTE))) {
        return false;
    }
    if (!parcel.WriteInt32(mcc_)) {
        return false;
    }
    if (!parcel.WriteInt32(mnc_)) {
        return false;
    }
    if (!parcel.WriteInt32(earfcn_)) {
        return false;
    }
    if (!parcel.WriteInt32(cellId_)) {
        return false;
    }
    if (!parcel.WriteInt32(pci_)) {
        return false;
    }
    if (!parcel.WriteInt32(tac_)) {
        return false;
    }
    if (!parcel.WriteInt64(timeStamp_)) {
        return false;
    }
    if (!parcel.WriteInt32(signalLevel_)) {
        return false;
    }
    if (!parcel.WriteBool(isCamped_)) {
        return false;
    }
    return true;
}

LteCellInformation *LteCellInformation::Unmarshalling(Parcel &parcel)
{
    LteCellInformation *param = new (std::nothrow) LteCellInformation();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool LteCellInformation::ReadFromParcel(Parcel &parcel)
{
    mcc_ = parcel.ReadInt32();
    mnc_ = parcel.ReadInt32();
    earfcn_ = parcel.ReadInt32();
    cellId_ = parcel.ReadInt32();
    pci_ = parcel.ReadInt32();
    tac_ = parcel.ReadInt32();
    timeStamp_ = parcel.ReadInt64();
    signalLevel_ = parcel.ReadInt32();
    isCamped_ = parcel.ReadBool();
    return true;
}

int32_t LteCellInformation::GetPci() const
{
    return pci_;
}

int32_t LteCellInformation::GetTac() const
{
    return tac_;
}

void LteCellInformation::UpdateLocation(int32_t cellId, int32_t tac)
{
    cellId_ = cellId;
    tac_ = tac;
    timeStamp_ = time(0);
}

std::string LteCellInformation::ToString() const
{
    int32_t netWorkType = static_cast<int32_t>(LteCellInformation::GetNetworkType());
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",mcc:" + std::to_string(mcc_) +
        ",mnc:" + std::to_string(mnc_) + ",earfcn:" + std::to_string(earfcn_) + ",cellId:" + std::to_string(cellId_) +
        ",timeStamp:" + std::to_string(timeStamp_) + ",signalLevel:" + std::to_string(signalLevel_) +
        ",pci:" + std::to_string(pci_) + ",tac:" + std::to_string(tac_));
    return content;
}

void WcdmaCellInformation::SetWcdmaParam(int32_t psc, int32_t lac, int32_t arfcn)
{
    psc_ = psc;
    lac_ = lac;
    uarfcn_= arfcn;
}

WcdmaCellInformation::WcdmaCellInformation(const WcdmaCellInformation &wcdmaCell)
{
    mcc_ = wcdmaCell.mcc_;
    mnc_ = wcdmaCell.mnc_;
    uarfcn_ = wcdmaCell.uarfcn_;
    cellId_ = wcdmaCell.cellId_;
    psc_ = wcdmaCell.psc_;
    lac_ = wcdmaCell.lac_;
    timeStamp_ = wcdmaCell.timeStamp_;
    signalLevel_ = wcdmaCell.signalLevel_;
    isCamped_ = wcdmaCell.isCamped_;
}

WcdmaCellInformation &WcdmaCellInformation::operator=(const WcdmaCellInformation &wcdmaCell)
{
    mcc_ = wcdmaCell.mcc_;
    mnc_ = wcdmaCell.mnc_;
    uarfcn_ = wcdmaCell.uarfcn_;
    cellId_ = wcdmaCell.cellId_;
    psc_ = wcdmaCell.psc_;
    lac_ = wcdmaCell.lac_;
    timeStamp_ = wcdmaCell.timeStamp_;
    signalLevel_ = wcdmaCell.signalLevel_;
    isCamped_ = wcdmaCell.isCamped_;
    return *this;
}

bool WcdmaCellInformation::operator==(const WcdmaCellInformation &other) const
{
    return mcc_ == other.mcc_ && mnc_ == other.mnc_ &&
           uarfcn_ == other.uarfcn_ && cellId_ == other.cellId_ &&
           psc_ == other.psc_ && lac_ == other.lac_ &&
           timeStamp_ == other.timeStamp_ && signalLevel_ == other.signalLevel_ &&
           isCamped_ == other.isCamped_;
}

CellInformation::CellType WcdmaCellInformation::GetNetworkType() const
{
    return CellType::CELL_TYPE_WCDMA;
}

int32_t WcdmaCellInformation::GetArfcn() const
{
    return uarfcn_;
}

bool WcdmaCellInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellInformation::CellType::CELL_TYPE_WCDMA))) {
        return false;
    }
    if (!parcel.WriteInt32(mcc_)) {
        return false;
    }
    if (!parcel.WriteInt32(mnc_)) {
        return false;
    }
    if (!parcel.WriteInt32(uarfcn_)) {
        return false;
    }
    if (!parcel.WriteInt32(cellId_)) {
        return false;
    }
    if (!parcel.WriteInt32(psc_)) {
        return false;
    }
    if (!parcel.WriteInt32(lac_)) {
        return false;
    }
    if (!parcel.WriteInt64(timeStamp_)) {
        return false;
    }
    if (!parcel.WriteInt32(signalLevel_)) {
        return false;
    }
    if (!parcel.WriteBool(isCamped_)) {
        return false;
    }
    return true;
}

WcdmaCellInformation *WcdmaCellInformation::Unmarshalling(Parcel &parcel)
{
    WcdmaCellInformation *param = new (std::nothrow) WcdmaCellInformation();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool WcdmaCellInformation::ReadFromParcel(Parcel &parcel)
{
    mcc_ = parcel.ReadInt32();
    mnc_ = parcel.ReadInt32();
    uarfcn_ = parcel.ReadInt32();
    cellId_ = parcel.ReadInt32();
    psc_ = parcel.ReadInt32();
    lac_ = parcel.ReadInt32();
    timeStamp_ = parcel.ReadInt64();
    signalLevel_ = parcel.ReadInt32();
    isCamped_ = parcel.ReadBool();
    return true;
}

int32_t WcdmaCellInformation::GetPsc() const
{
    return psc_;
}

int32_t WcdmaCellInformation::GetLac() const
{
    return lac_;
}

void WcdmaCellInformation::UpdateLocation(int32_t cellId, int32_t lac)
{
    cellId_ = cellId;
    lac_ = lac;
    timeStamp_ = time(0);
}

std::string WcdmaCellInformation::ToString() const
{
    int32_t netWorkType = static_cast<int32_t>(WcdmaCellInformation::GetNetworkType());
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",mcc:" + std::to_string(mcc_) +
        ",mnc:" + std::to_string(mnc_) + ",uarfcn:" + std::to_string(uarfcn_) + ",cellId:" + std::to_string(cellId_) +
        ",timeStamp:" + std::to_string(timeStamp_) + ",signalLevel:" + std::to_string(signalLevel_) +
        ",psc:" + std::to_string(psc_) + ",lac:" + std::to_string(lac_));
    return content;
}
} // namespace Telephony
} // namespace OHOS