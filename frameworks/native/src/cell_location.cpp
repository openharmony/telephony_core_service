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

#include "cell_location.h"

#include <stdint.h>

#include "new"
#include "parcel.h"
#include "time.h"

namespace OHOS {
namespace Telephony {
CellLocation *CellLocation::Unmarshalling(Parcel &parcel)
{
    return nullptr;
}

bool GsmCellLocation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellLocation::CellType::CELL_TYPE_GSM))) {
        return false;
    }
    if (!parcel.WriteInt32(cellId_)) {
        return false;
    }
    if (!parcel.WriteInt32(lac_)) {
        return false;
    }
    if (!parcel.WriteInt32(psc_)) {
        return false;
    }
    if (!parcel.WriteInt64(timeStamp_)) {
        return false;
    }
    return true;
}

GsmCellLocation *GsmCellLocation::Unmarshalling(Parcel &parcel)
{
    GsmCellLocation *param = new (std::nothrow) GsmCellLocation();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool GsmCellLocation::ReadFromParcel(Parcel &parcel)
{
    cellId_ = parcel.ReadInt32();
    lac_ = parcel.ReadInt32();
    psc_ = parcel.ReadInt32();
    timeStamp_ = parcel.ReadInt64();
    return true;
}

uint64_t CellLocation::GetTimeStamp() const
{
    return timeStamp_;
}

CellLocation::CellType GsmCellLocation::GetCellLocationType() const
{
    return CellLocation::CellType::CELL_TYPE_GSM;
}

void GsmCellLocation::SetGsmParam(int32_t cellId, int32_t lac, int32_t psc)
{
    cellId_ = cellId;
    lac_ = lac;
    psc_ = psc;
    timeStamp_ = static_cast<uint64_t>(time(0));
}

int32_t GsmCellLocation::GetCellId() const
{
    return cellId_;
}

int32_t GsmCellLocation::GetLac() const
{
    return lac_;
}

int32_t GsmCellLocation::GetPsc() const
{
    return psc_;
}

bool CdmaCellLocation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(CellLocation::CellType::CELL_TYPE_CDMA))) {
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
    return true;
}

CdmaCellLocation *CdmaCellLocation::Unmarshalling(Parcel &parcel)
{
    CdmaCellLocation *param = new (std::nothrow) CdmaCellLocation();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
}

bool CdmaCellLocation::ReadFromParcel(Parcel &parcel)
{
    baseId_ = parcel.ReadInt32();
    latitude_ = parcel.ReadInt32();
    longitude_ = parcel.ReadInt32();
    nid_ = parcel.ReadInt32();
    sid_ = parcel.ReadInt32();
    timeStamp_ = parcel.ReadUint64();
    return true;
}

CellLocation::CellType CdmaCellLocation::GetCellLocationType() const
{
    return CellLocation::CellType::CELL_TYPE_CDMA;
}

void CdmaCellLocation::SetCdmaParam(int32_t baseId, int32_t latitude, int32_t longitude, int32_t nid, int32_t sid)
{
    baseId_ = baseId;
    latitude_ = latitude;
    longitude_ = longitude;
    nid_ = nid;
    sid_ = sid;
    timeStamp_ = static_cast<uint64_t>(time(0));
}

int32_t CdmaCellLocation::GetBaseId() const
{
    return baseId_;
}

int32_t CdmaCellLocation::GetLatitude() const
{
    return latitude_;
}

int32_t CdmaCellLocation::GetLongitude() const
{
    return longitude_;
}

int32_t CdmaCellLocation::GetNid() const
{
    return nid_;
}

int32_t CdmaCellLocation::GetSid() const
{
    return sid_;
}
} // namespace Telephony
} // namespace OHOS