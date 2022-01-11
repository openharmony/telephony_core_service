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

#ifndef OHOS_CELL_LOCATION_H
#define OHOS_CELL_LOCATION_H

#include "parcel.h"
#include "cell_information.h"

namespace OHOS {
namespace Telephony {
class CellLocation : public Parcelable {
public:
    enum class CellType {
        CELL_TYPE_NONE = 0,
        CELL_TYPE_GSM,
        CELL_TYPE_CDMA,
    };
    CellLocation() = default;
    virtual ~CellLocation() = default;
    virtual CellLocation::CellType GetCellLocationType() const = 0;
    virtual bool Marshalling(Parcel &parcel) const = 0;
    static CellLocation *Unmarshalling(Parcel &parcel);
    virtual bool ReadFromParcel(Parcel &parcel) = 0;

    virtual uint64_t GetTimeStamp() const;
protected:
    uint64_t timeStamp_ = 0;
};

class GsmCellLocation : public CellLocation {
public:
    GsmCellLocation() = default;
    virtual ~GsmCellLocation() = default;
    bool Marshalling(Parcel &parcel) const override;
    static GsmCellLocation *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    CellLocation::CellType GetCellLocationType() const override;
    void SetGsmParam(int32_t cellId, int32_t lac, int32_t psc = 0);
    /**
     * @return gsm cell id, 0 if unknown, 0xffff max legal value
     */
    int32_t GetCellId() const;
    /**
     * @return gsm location area code, 0 if unknown, 0xffff max legal value
     */
    int32_t GetLac() const;
    /**
     * On a UMTS network, return the primary scrambling code
     * cell.
     * @return primary scrambling code for WCDMA, 0 if unknown or GSM
     */
    int32_t GetPsc() const;
private:
    int32_t cellId_ = 0;
    int32_t lac_ = 0;
    int32_t psc_ = 0;
};

class CdmaCellLocation : public CellLocation {
public:
    CdmaCellLocation() = default;
    virtual ~CdmaCellLocation() = default;
    bool Marshalling(Parcel &parcel) const override;
    static CdmaCellLocation *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    CellLocation::CellType GetCellLocationType() const override;
    void SetCdmaParam(int32_t baseId, int32_t latitude, int32_t longitude, int32_t nid, int32_t sid);

    int32_t GetBaseId() const;
    int32_t GetLatitude() const;
    int32_t GetLongitude() const;
    int32_t GetNid() const;
    int32_t GetSid() const;
private:
    int32_t baseId_ = 0;
    int32_t latitude_ = 0;
    int32_t longitude_ = 0;
    int32_t nid_ = 0;
    int32_t sid_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_CELL_LOCATION_H