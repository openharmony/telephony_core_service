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
#include <securec.h>

namespace OHOS {
namespace Telephony {
const int32_t MNC_INT_MAX = 999;
const int32_t MNC_DIGIT_OFFSET = 28;
const uint32_t MNC_VALID_BIT = 0X0FFFFFFF;
void CellInformation::Init(int32_t mcc, int32_t mnc, int32_t cellId)
{
    if (mnc > MNC_INT_MAX) {
        int mnc_digit = mnc >> MNC_DIGIT_OFFSET;
        mnc = static_cast<int32_t>(static_cast<uint32_t>(mnc) & MNC_VALID_BIT);
        char mnc_str[MNC_DIGIT_OFFSET] = {0};
        char strFormat[MNC_DIGIT_OFFSET] = {0};
        int size = snprintf_s(strFormat, MNC_DIGIT_OFFSET, MNC_DIGIT_OFFSET - 1, "%s%dd", "%0", mnc_digit);
        if (size > 0) {
            size = snprintf_s(mnc_str, mnc_digit + 1, mnc_digit, strFormat, mnc);
        }
        if (size > 0) {
            mnc_ = mnc_str;
        }
    } else {
        mnc_ = std::to_string(mnc);
    }
    mcc_ = std::to_string(mcc);
    cellId_ = cellId;
    timeStamp_ = static_cast<uint64_t>(time(0));
}

int32_t CellInformation::GetCellId() const
{
    return cellId_;
}

std::string CellInformation::GetMcc() const
{
    return mcc_;
}

std::string CellInformation::GetMnc() const
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
    timeStamp_ = static_cast<uint64_t>(time(0));
}

bool CellInformation::GetIsCamped() const
{
    return isCamped_;
}

void CellInformation::SetIsCamped(bool isCamped)
{
    isCamped_ = isCamped;
    timeStamp_ = static_cast<uint64_t>(time(0));
}

CellInformation *CellInformation::Unmarshalling(Parcel &parcel)
{
    return nullptr;
}

void GsmCellInformation::SetGsmParam(int32_t bsic, int32_t lac, int32_t arfcn)
{
    bsic_ = bsic;
    lac_ = lac;
    arfcn_ = arfcn;
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
        signalLevel_ == other.signalLevel_ &&
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
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",mcc:" + mcc_ +
        ",mnc:" + mnc_ + ",arfcn:" + std::to_string(arfcn_) + ",cellId:" + std::to_string(cellId_) +
        ",timeStamp:" + std::to_string(timeStamp_) + ",signalLevel:" + std::to_string(signalLevel_) +
        ",bsic:" + std::to_string(bsic_) + ",lac:" + std::to_string(lac_));
    return content;
}

bool GsmCellInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellInformation::CellType::CELL_TYPE_GSM))) {
        return false;
    }
    if (!parcel.WriteString(mcc_)) {
        return false;
    }
    if (!parcel.WriteString(mnc_)) {
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
    if (!parcel.WriteUint64(timeStamp_)) {
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
    mcc_ = parcel.ReadString();
    mnc_ = parcel.ReadString();
    arfcn_ = parcel.ReadInt32();
    cellId_ = parcel.ReadInt32();
    bsic_ = parcel.ReadInt32();
    lac_ = parcel.ReadInt32();
    timeStamp_ = parcel.ReadUint64();
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
    earfcn_ = arfcn;
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
        signalLevel_ == other.signalLevel_ &&
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
    if (!parcel.WriteString(mcc_)) {
        return false;
    }
    if (!parcel.WriteString(mnc_)) {
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
    mcc_ = parcel.ReadString();
    mnc_ = parcel.ReadString();
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
    timeStamp_ = static_cast<uint64_t>(time(0));
}

std::string LteCellInformation::ToString() const
{
    int32_t netWorkType = static_cast<int32_t>(LteCellInformation::GetNetworkType());
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",mcc:" + mcc_ +
        ",mnc:" + mnc_ + ",earfcn:" + std::to_string(earfcn_) + ",cellId:" + std::to_string(cellId_) +
        ",timeStamp:" + std::to_string(timeStamp_) + ",signalLevel:" + std::to_string(signalLevel_) +
        ",pci:" + std::to_string(pci_) + ",tac:" + std::to_string(tac_));
    return content;
}

void WcdmaCellInformation::SetWcdmaParam(int32_t psc, int32_t lac, int32_t arfcn)
{
    psc_ = psc;
    lac_ = lac;
    uarfcn_ = arfcn;
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
        signalLevel_ == other.signalLevel_ &&
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
    if (!parcel.WriteString(mcc_)) {
        return false;
    }
    if (!parcel.WriteString(mnc_)) {
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
    mcc_ = parcel.ReadString();
    mnc_ = parcel.ReadString();
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
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",mcc:" + mcc_ +
        ",mnc:" + mnc_ + ",uarfcn:" + std::to_string(uarfcn_) + ",cellId:" + std::to_string(cellId_) +
        ",timeStamp:" + std::to_string(timeStamp_) + ",signalLevel:" + std::to_string(signalLevel_) +
        ",psc:" + std::to_string(psc_) + ",lac:" + std::to_string(lac_));
    return content;
}

void TdscdmaCellInformation::SetTdscdmaParam(int32_t cpid, int32_t lac, int32_t arfcn)
{
    cpid_ = cpid;
    lac_ = lac;
    uarfcn_ = arfcn;
}

TdscdmaCellInformation::TdscdmaCellInformation(const TdscdmaCellInformation &tdscdmaCell)
{
    mcc_ = tdscdmaCell.mcc_;
    mnc_ = tdscdmaCell.mnc_;
    uarfcn_ = tdscdmaCell.uarfcn_;
    cellId_ = tdscdmaCell.cellId_;
    cpid_ = tdscdmaCell.cpid_;
    lac_ = tdscdmaCell.lac_;
    timeStamp_ = tdscdmaCell.timeStamp_;
    signalLevel_ = tdscdmaCell.signalLevel_;
    isCamped_ = tdscdmaCell.isCamped_;
}

TdscdmaCellInformation &TdscdmaCellInformation::operator=(const TdscdmaCellInformation &tdscdmaCell)
{
    mcc_ = tdscdmaCell.mcc_;
    mnc_ = tdscdmaCell.mnc_;
    uarfcn_ = tdscdmaCell.uarfcn_;
    cellId_ = tdscdmaCell.cellId_;
    cpid_ = tdscdmaCell.cpid_;
    lac_ = tdscdmaCell.lac_;
    timeStamp_ = tdscdmaCell.timeStamp_;
    signalLevel_ = tdscdmaCell.signalLevel_;
    isCamped_ = tdscdmaCell.isCamped_;
    return *this;
}

bool TdscdmaCellInformation::operator==(const TdscdmaCellInformation &other) const
{
    return mcc_ == other.mcc_ && mnc_ == other.mnc_ &&
        uarfcn_ == other.uarfcn_ && cellId_ == other.cellId_ &&
        cpid_ == other.cpid_ && lac_ == other.lac_ &&
        signalLevel_ == other.signalLevel_ &&
        isCamped_ == other.isCamped_;
}

CellInformation::CellType TdscdmaCellInformation::GetNetworkType() const
{
    return CellType::CELL_TYPE_TDSCDMA;
}

int32_t TdscdmaCellInformation::GetArfcn() const
{
    return uarfcn_;
}

bool TdscdmaCellInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellInformation::CellType::CELL_TYPE_TDSCDMA))) {
        return false;
    }
    if (!parcel.WriteString(mcc_)) {
        return false;
    }
    if (!parcel.WriteString(mnc_)) {
        return false;
    }
    if (!parcel.WriteInt32(uarfcn_)) {
        return false;
    }
    if (!parcel.WriteInt32(cellId_)) {
        return false;
    }
    if (!parcel.WriteInt32(cpid_)) {
        return false;
    }
    if (!parcel.WriteInt32(lac_)) {
        return false;
    }
    if (!parcel.WriteUint64(timeStamp_)) {
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

TdscdmaCellInformation *TdscdmaCellInformation::Unmarshalling(Parcel &parcel)
{
    TdscdmaCellInformation *param = new (std::nothrow) TdscdmaCellInformation();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool TdscdmaCellInformation::ReadFromParcel(Parcel &parcel)
{
    mcc_ = parcel.ReadString();
    mnc_ = parcel.ReadString();
    uarfcn_ = parcel.ReadInt32();
    cellId_ = parcel.ReadInt32();
    cpid_ = parcel.ReadInt32();
    lac_ = parcel.ReadInt32();
    timeStamp_ = parcel.ReadUint64();
    signalLevel_ = parcel.ReadInt32();
    isCamped_ = parcel.ReadBool();
    return true;
}

int32_t TdscdmaCellInformation::GetCpid() const
{
    return cpid_;
}

int32_t TdscdmaCellInformation::GetLac() const
{
    return lac_;
}

void TdscdmaCellInformation::UpdateLocation(int32_t cellId, int32_t lac)
{
    cellId_ = cellId;
    lac_ = lac;
    timeStamp_ = time(0);
}

std::string TdscdmaCellInformation::ToString() const
{
    int32_t netWorkType = static_cast<int32_t>(TdscdmaCellInformation::GetNetworkType());
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",mcc:" + mcc_ +
        ",mnc:" + mnc_ + ",uarfcn:" + std::to_string(uarfcn_) + ",cellId:" + std::to_string(cellId_) +
        ",timeStamp:" + std::to_string(timeStamp_) + ",signalLevel:" + std::to_string(signalLevel_) +
        ",cpid:" + std::to_string(cpid_) + ",lac:" + std::to_string(lac_));
    return content;
}

void CdmaCellInformation::SetCdmaParam(int32_t baseId, int32_t latitude, int32_t longitude, int32_t nid, int32_t sid)
{
    baseId_ = baseId;
    latitude_ = latitude;
    longitude_ = longitude;
    nid_ = nid;
    sid_ = sid;
}

CdmaCellInformation::CdmaCellInformation(const CdmaCellInformation &cdmaCell)
{
    baseId_ = cdmaCell.baseId_;
    latitude_ = cdmaCell.latitude_;
    longitude_ = cdmaCell.longitude_;
    nid_ = cdmaCell.nid_;
    sid_ = cdmaCell.sid_;
    timeStamp_ = cdmaCell.timeStamp_;
    signalLevel_ = cdmaCell.signalLevel_;
    isCamped_ = cdmaCell.isCamped_;
}

CdmaCellInformation &CdmaCellInformation::operator=(const CdmaCellInformation &cdmaCell)
{
    baseId_ = cdmaCell.baseId_;
    latitude_ = cdmaCell.latitude_;
    longitude_ = cdmaCell.longitude_;
    nid_ = cdmaCell.nid_;
    sid_ = cdmaCell.sid_;
    timeStamp_ = cdmaCell.timeStamp_;
    signalLevel_ = cdmaCell.signalLevel_;
    isCamped_ = cdmaCell.isCamped_;
    return *this;
}

bool CdmaCellInformation::operator==(const CdmaCellInformation &other) const
{
    return baseId_ == other.baseId_ && latitude_ == other.latitude_ &&
        longitude_ == other.longitude_ && nid_ == other.nid_ &&
        sid_ == other.sid_ &&
        signalLevel_ == other.signalLevel_ && isCamped_ == other.isCamped_;
}

CellInformation::CellType CdmaCellInformation::GetNetworkType() const
{
    return CellType::CELL_TYPE_CDMA;
}

bool CdmaCellInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellInformation::CellType::CELL_TYPE_CDMA))) {
        return false;
    }
    if (!parcel.WriteInt32(baseId_)) {
        return false;
    }
    if (!parcel.WriteInt32(latitude_)) {
        return false;
    }
    if (!parcel.WriteInt32(longitude_)) {
        return false;
    }
    if (!parcel.WriteInt32(nid_)) {
        return false;
    }
    if (!parcel.WriteInt32(sid_)) {
        return false;
    }
    if (!parcel.WriteUint64(timeStamp_)) {
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

CdmaCellInformation *CdmaCellInformation::Unmarshalling(Parcel &parcel)
{
    CdmaCellInformation *param = new (std::nothrow) CdmaCellInformation();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool CdmaCellInformation::ReadFromParcel(Parcel &parcel)
{
    baseId_ = parcel.ReadInt32();
    latitude_ = parcel.ReadInt32();
    longitude_ = parcel.ReadInt32();
    nid_ = parcel.ReadInt32();
    sid_ = parcel.ReadInt32();
    timeStamp_ = parcel.ReadUint64();
    signalLevel_ = parcel.ReadInt32();
    isCamped_ = parcel.ReadBool();
    return true;
}

int32_t CdmaCellInformation::GetBaseId() const
{
    return baseId_;
}

int32_t CdmaCellInformation::GetLatitude() const
{
    return latitude_;
}

int32_t CdmaCellInformation::GetLongitude() const
{
    return longitude_;
}

int32_t CdmaCellInformation::GetNid() const
{
    return nid_;
}

int32_t CdmaCellInformation::GetSid() const
{
    return sid_;
}

void CdmaCellInformation::UpdateLocation(int32_t baseId, int32_t latitude, int32_t longitude)
{
    baseId_ = baseId;
    latitude_ = latitude;
    longitude_ = longitude;
    timeStamp_ = time(0);
}

std::string CdmaCellInformation::ToString() const
{
    int32_t netWorkType = static_cast<int32_t>(CdmaCellInformation::GetNetworkType());
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",baseId:" + std::to_string(baseId_) +
        ",latitude:" + std::to_string(latitude_) + ",longitude:" + std::to_string(longitude_) +
        ",nid:" + std::to_string(nid_) + ",timeStamp:" + std::to_string(timeStamp_) +
        ",signalLevel:" + std::to_string(signalLevel_) + ",sid:" + std::to_string(sid_));
    return content;
}

void NrCellInformation::SetNrParam(int32_t nrArfcn, int32_t pci, int32_t tac, int64_t nci)
{
    nrArfcn_ = nrArfcn;
    pci_ = pci;
    tac_ = tac;
    nci_ = nci;
}

NrCellInformation::NrCellInformation(const NrCellInformation &nrCell)
{
    mcc_ = nrCell.mcc_;
    mnc_ = nrCell.mnc_;
    cellId_ = nrCell.cellId_;
    nrArfcn_ = nrCell.nrArfcn_;
    pci_ = nrCell.pci_;
    tac_ = nrCell.tac_;
    nci_ = nrCell.nci_;
    timeStamp_ = nrCell.timeStamp_;
    signalLevel_ = nrCell.signalLevel_;
    isCamped_ = nrCell.isCamped_;
}

NrCellInformation &NrCellInformation::operator=(const NrCellInformation &nrCell)
{
    mcc_ = nrCell.mcc_;
    mnc_ = nrCell.mnc_;
    cellId_ = nrCell.cellId_;
    nrArfcn_ = nrCell.nrArfcn_;
    pci_ = nrCell.pci_;
    tac_ = nrCell.tac_;
    nci_ = nrCell.nci_;
    timeStamp_ = nrCell.timeStamp_;
    signalLevel_ = nrCell.signalLevel_;
    isCamped_ = nrCell.isCamped_;
    return *this;
}

bool NrCellInformation::operator==(const NrCellInformation &other) const
{
    return mcc_ == other.mcc_ && mnc_ == other.mnc_ &&
        cellId_ == other.cellId_ && nrArfcn_ == other.nrArfcn_ &&
        pci_ == other.pci_ && tac_ == other.tac_ && nci_ == other.nci_ &&
        signalLevel_ == other.signalLevel_ &&
        isCamped_ == other.isCamped_;
}

CellInformation::CellType NrCellInformation::GetNetworkType() const
{
    return CellType::CELL_TYPE_NR;
}

bool NrCellInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellInformation::CellType::CELL_TYPE_NR))) {
        return false;
    }
    if (!parcel.WriteString(mcc_)) {
        return false;
    }
    if (!parcel.WriteString(mnc_)) {
        return false;
    }
    if (!parcel.WriteInt32(cellId_)) {
        return false;
    }
    if (!parcel.WriteInt32(nrArfcn_)) {
        return false;
    }
    if (!parcel.WriteInt32(pci_)) {
        return false;
    }
    if (!parcel.WriteInt32(tac_)) {
        return false;
    }
    if (!parcel.WriteInt64(nci_)) {
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

NrCellInformation *NrCellInformation::Unmarshalling(Parcel &parcel)
{
    NrCellInformation *param = new (std::nothrow) NrCellInformation();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool NrCellInformation::ReadFromParcel(Parcel &parcel)
{
    mcc_ = parcel.ReadString();
    mnc_ = parcel.ReadString();
    cellId_ = parcel.ReadInt32();
    nrArfcn_ = parcel.ReadInt32();
    pci_ = parcel.ReadInt32();
    tac_ = parcel.ReadInt32();
    nci_ = parcel.ReadInt64();
    timeStamp_ = parcel.ReadInt64();
    signalLevel_ = parcel.ReadInt32();
    isCamped_ = parcel.ReadBool();
    return true;
}

int32_t NrCellInformation::GetArfcn() const
{
    return nrArfcn_;
}

int32_t NrCellInformation::GetPci() const
{
    return pci_;
}

int32_t NrCellInformation::GetTac() const
{
    return tac_;
}

int64_t NrCellInformation::GetNci() const
{
    return nci_;
}

void NrCellInformation::UpdateLocation(int32_t pci, int32_t tac)
{
    pci_ = pci;
    tac_ = tac;
    timeStamp_ = time(0);
}

std::string NrCellInformation::ToString() const
{
    int32_t netWorkType = static_cast<int32_t>(NrCellInformation::GetNetworkType());
    std::string content("netWorkType:" + std::to_string(netWorkType) + ",mcc:" + mcc_ +
        ",mnc:" + mnc_ + ",earfcn:" + std::to_string(nrArfcn_) + ",cellId:" + std::to_string(cellId_) +
        ",timeStamp:" + std::to_string(timeStamp_) + ",signalLevel:" + std::to_string(signalLevel_) +
        ",pci:" + std::to_string(pci_) + ",tac:" + std::to_string(tac_) + ",nci:" + std::to_string(nci_));
    return content;
}
} // namespace Telephony
} // namespace OHOS
