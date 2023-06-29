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

#ifndef OHOS_CELL_INFORMATION_H
#define OHOS_CELL_INFORMATION_H

#include "parcel.h"

namespace OHOS {
namespace Telephony {
class CellInformation : public Parcelable {
public:
    static const int32_t MAX_CELL_NUM = 10;
    /**
     * @brief Cell type
     */
    enum class CellType {
        CELL_TYPE_NONE = 0,
        /**
         * Global System for Mobile Communications (GSM) cell type
         */
        CELL_TYPE_GSM,
        /**
         * Code Division Multiple Access (CDMA) cell type
         */
        CELL_TYPE_CDMA,
        /**
         * Wideband Code Division Multiple Access (WCDMA) cell type
         */
        CELL_TYPE_WCDMA,
        /**
         * Time Division-Synchronous Code Division Multiple Access (TD-SCDMA) cell type
         */
        CELL_TYPE_TDSCDMA,
        /**
         * Long Term Evolution (LTE) cell type
         */
        CELL_TYPE_LTE,
        /**
         * 5G New Radio (NR) cell type
         */
        CELL_TYPE_NR
    };
    CellInformation() = default;
    virtual ~CellInformation() = default;
    virtual bool Marshalling(Parcel &parcel) const = 0;
    static CellInformation *Unmarshalling(Parcel &parcel);
    virtual bool ReadFromParcel(Parcel &parcel) = 0;
    virtual CellInformation::CellType GetNetworkType() const = 0;
    virtual std::string ToString() const = 0;
    void Init(int32_t mcc, int32_t mnc, int32_t cellId);

    /**
     * @brief Obtain the cell Id
     *
     * @return Cell Id
     */
    virtual int32_t GetCellId() const;
    /**
     * @brief Obtain the Mobile Country Code
     *
     * @return Mobile Country Code
     */
    virtual std::string GetMcc() const;
    /**
     * @brief Obtain the Mobile Network Code
     *
     * @return Mobile Network Code
     */
    virtual std::string GetMnc() const;
    virtual uint64_t GetTimeStamp() const;
    virtual int32_t GetSignalLevel() const;
    virtual int32_t GetSignalIntensity() const;
    virtual bool GetIsCamped() const;
    virtual void SetIsCamped(bool isCamped);
    virtual void SetSignalIntensity(int32_t signalIntensity);
    virtual void SetSignalLevel(int32_t signalLevel);

protected:
    std::string mcc_ = "";
    std::string mnc_ = "";
    int32_t cellId_ = 0;
    uint64_t timeStamp_ = 0;
    int32_t signalIntensity_ = 0;
    int32_t signalLevel_ = 0;
    bool isCamped_ = false;
};

class GsmCellInformation : public CellInformation {
public:
    GsmCellInformation() = default;
    virtual ~GsmCellInformation() = default;
    bool Marshalling(Parcel &parcel) const override;
    static GsmCellInformation *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    CellInformation::CellType GetNetworkType() const override;
    std::string ToString() const override;
    void SetGsmParam(int32_t bsic, int32_t lac, int32_t arfcn);
    void UpdateLocation(int32_t cellId, int32_t lac);
    GsmCellInformation(const GsmCellInformation &gsmCell);
    GsmCellInformation &operator=(const GsmCellInformation &gsmCell);
    bool operator==(const GsmCellInformation &other) const;
    /**
     * @brief Obtain the Location Area Code
     *
     * @return Location Area Code
     */
    int32_t GetLac() const;
    /**
     * @brief Obtain the Base Station Identity Code
     *
     * @return Base Station Identity Code
     */
    int32_t GetBsic() const;
    /**
     * @brief Obtain the Absolute RF Channel Number
     *
     * @return Absolute RF Channel Number
     */
    int32_t GetArfcn() const;

private:
    int32_t lac_ = 0;
    int32_t bsic_ = 0;
    int32_t arfcn_ = 0;
};

class LteCellInformation : public CellInformation {
public:
    LteCellInformation() = default;
    virtual ~LteCellInformation() = default;
    bool Marshalling(Parcel &parcel) const override;
    static LteCellInformation *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    CellInformation::CellType GetNetworkType() const override;
    std::string ToString() const override;
    void SetLteParam(int32_t pci, int32_t tac, int32_t arfcn);
    LteCellInformation(const LteCellInformation &lteCell);
    LteCellInformation &operator=(const LteCellInformation &lteCell);
    bool operator==(const LteCellInformation &other) const;
    void UpdateLocation(int32_t cellId, int32_t tac);
    /**
     * @brief Obtain the Physical Cell Id
     *
     * @return Physical Cell Id
     */
    int32_t GetPci() const;
    /**
     * @brief Obtain the Tracking Area Code
     *
     * @return Tracking Area Code
     */
    int32_t GetTac() const;
    /**
     * @brief Obtain the Absolute RF Channel Number
     *
     * @return Absolute RF Channel Number
     */
    int32_t GetArfcn() const;

private:
    int32_t pci_ = 0;
    int32_t tac_ = 0;
    int32_t earfcn_ = 0;
};

class WcdmaCellInformation : public CellInformation {
public:
    WcdmaCellInformation() = default;
    virtual ~WcdmaCellInformation() = default;
    bool Marshalling(Parcel &parcel) const override;
    static WcdmaCellInformation *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    CellInformation::CellType GetNetworkType() const override;
    std::string ToString() const override;
    void SetWcdmaParam(int32_t psc, int32_t lac, int32_t arfcn);
    WcdmaCellInformation(const WcdmaCellInformation &wcdmaCell);
    WcdmaCellInformation &operator=(const WcdmaCellInformation &wcdmaCell);
    bool operator==(const WcdmaCellInformation &other) const;
    void UpdateLocation(int32_t cellId, int32_t lac);
    /**
     * @brief Obtain the Primary Scrambling Code
     *
     * @return Primary Scrambling Code
     */
    int32_t GetPsc() const;
    /**
     * @brief Obtain the Location Area Code
     *
     * @return Location Area Code
     */
    int32_t GetLac() const;
    /**
     * @brief Obtain the Absolute RF Channel Number
     *
     * @return Absolute RF Channel Number
     */
    int32_t GetArfcn() const;

private:
    int32_t lac_ = 0;
    int32_t psc_ = 0;
    int32_t uarfcn_ = 0;
};

class TdscdmaCellInformation : public CellInformation {
public:
    TdscdmaCellInformation() = default;
    virtual ~TdscdmaCellInformation() = default;
    bool Marshalling(Parcel &parcel) const override;
    static TdscdmaCellInformation *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    CellInformation::CellType GetNetworkType() const override;
    std::string ToString() const override;
    void SetTdscdmaParam(int32_t psc, int32_t lac, int32_t arfcn);
    TdscdmaCellInformation(const TdscdmaCellInformation &wcdmaCell);
    TdscdmaCellInformation &operator=(const TdscdmaCellInformation &wcdmaCell);
    bool operator==(const TdscdmaCellInformation &other) const;
    void UpdateLocation(int32_t cellId, int32_t lac);
    /**
     * @brief Obtain the Cell Parameters ID
     *
     * @return Cell Parameters ID
     */
    int32_t GetCpid() const;
    /**
     * @brief Obtain the Location Area Code
     *
     * @return Location Area Code
     */
    int32_t GetLac() const;
    /**
     * @brief Obtain the Absolute RF Channel Number
     *
     * @return Absolute RF Channel Number
     */
    int32_t GetArfcn() const;

private:
    int32_t lac_ = 0;
    int32_t cpid_ = 0;
    int32_t uarfcn_ = 0;
};

class CdmaCellInformation : public CellInformation {
public:
    CdmaCellInformation() = default;
    virtual ~CdmaCellInformation() = default;
    bool Marshalling(Parcel &parcel) const override;
    static CdmaCellInformation *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    CellInformation::CellType GetNetworkType() const override;
    std::string ToString() const override;
    void SetCdmaParam(int32_t baseId, int32_t latitude, int32_t longitude, int32_t nid, int32_t sid);
    CdmaCellInformation(const CdmaCellInformation &cdmaCell);
    CdmaCellInformation &operator=(const CdmaCellInformation &cdmaCell);
    bool operator==(const CdmaCellInformation &other) const;
    void UpdateLocation(int32_t baseId, int32_t latitude, int32_t longitude);
    /**
     * @brief Obtain cdma base station identification number
     *
     * @return CDMA base station identification number
     */
    int32_t GetBaseId() const;
    /**
     * @brief Obtain cdma base station latitude
     *
     * @return CDMA base station latitude
     */
    int32_t GetLatitude() const;
    /**
     * @brief Obtain cdma base station longitude
     *
     * @return CDMA base station longitude
     */
    int32_t GetLongitude() const;
    /**
     * @brief Obtain cdma network identification number
     *
     * @return CDMA network identification number
     */
    int32_t GetNid() const;
    /**
     * @brief Obtain cdma system identification number
     *
     * @return CDMA system identification number
     */
    int32_t GetSid() const;

private:
    int32_t baseId_ = 0;
    int32_t latitude_ = 0;
    int32_t longitude_ = 0;
    int32_t nid_ = 0;
    int32_t sid_ = 0;
};

class NrCellInformation : public CellInformation {
public:
    NrCellInformation() = default;
    virtual ~NrCellInformation() = default;
    bool Marshalling(Parcel &parcel) const override;
    static NrCellInformation *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    CellInformation::CellType GetNetworkType() const override;
    std::string ToString() const override;
    void SetNrParam(int32_t nrArfcn, int32_t pci, int32_t tac, int64_t nci);
    void SetNrSignalParam(int32_t rsrp, int32_t rsrq);
    NrCellInformation(const NrCellInformation &nrCell);
    NrCellInformation &operator=(const NrCellInformation &nrCell);
    bool operator==(const NrCellInformation &other) const;
    void UpdateLocation(int32_t pci, int32_t tac);
    /**
     * @return Absolute RF Channel Number
     */
    int32_t GetArfcn() const;
    /**
     * @brief Obtain the Physical Cell Id
     *
     * @return Physical Cell Id
     */
    int32_t GetPci() const;
    /**
     * @brief Obtain the Tracking Area Code
     *
     * @return Tracking Area Code
     */
    int32_t GetTac() const;
    /**
     * @brief Obtain the NR(New Radio 5G) Cell Identity
     *
     * @return NR(New Radio 5G) Cell Identity
     */
    int64_t GetNci() const;

private:
    int32_t nrArfcn_ = 0;
    int32_t pci_ = 0;
    int32_t tac_ = 0;
    int64_t nci_ = 0;
    int32_t rsrp_ = 0;
    int32_t rsrq_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_CELL_INFORMATION_H