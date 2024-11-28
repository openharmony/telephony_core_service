/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_TEL_RIL_NETWORK_PARCEL_H
#define OHOS_TEL_RIL_NETWORK_PARCEL_H

#include "tel_ril_base_parcel.h"
#include "tel_ril_enum.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Defines the carrier information.
 */
struct OperatorInfoResult {
    /** Long carrier name of the registered network. */
    std::string longName = "";

    /** Short carrier name of the registered network. */
    std::string shortName = "";

    /** MCC+MNC of the registered network. */
    std::string numeric = "";

    /** flag, Used by search network manager in response. */
    int64_t flag = 0;
};

/**
 * @brief Defines the available network information.
 */
struct AvailableNetworkInfo {
    /** Long name of the registered network in alphanumeric format. */
    std::string longName = "";

    /** Short name of the registered network in alphanumeric format. */
    std::string shortName = "";

    /** Available network ID(MCC+MNC). */
    std::string numeric = "";

    /** Network status. For details, see {@link RilRegStatus}. */
    int32_t status = 0;

    /** Radio access technology type. For details, see {@link RilRadioTech}. */
    int32_t rat = 0;
};

/**
 * @brief Defines the available network list.
 */
struct AvailableNetworkList {
    /** The size of available network list. */
    int32_t itemNum = 0;

    /** Available network list. */
    std::vector<AvailableNetworkInfo> availableNetworkInfo {};

    /** Network list flag */
    int64_t flag = 0;
};

/**
 * @brief Defines the network mode information.
 */
struct SetNetworkModeInfo {
    /** Network mode. For details, see {@link PreferredNetworkTypeInfo}. */
    int32_t selectMode = 0;

    /** Operator information */
    std::string oper = "";

    /** flag, Used by search network manager in response. */
    int64_t flag = 0;
};

/**
 * @brief Voice registration status results
 */
struct CsRegStatusInfo {
    /** The notifyType,Indicate the content of the notification. */
    int32_t notifyType = 0;

    /**
     * The corresponding valid registration states are
     * NOT_REG_MT_NOT_SEARCHING_OP, "REG_MT_HOME, NOT_REG_MT_SEARCHING_OP,
     * REG_DENIED,  UNKNOWN, REG_ROAMING".
     */
    TelRilRegStatus regStatus =
        TelRilRegStatus::NO_REG_MT_NO_SEARCH;

    /** Location area code. */
    int32_t lacCode = 0;

    /** Cell ID. */
    int32_t cellId = 0;

    /** Available voice radio technology, RMS defined by radio technology. */
    TelRilRadioTech radioTechnology =
        TelRilRadioTech::RADIO_TECHNOLOGY_UNKNOWN;

    /** flag, Used by search network manager in response. */
    int64_t flag = 0;
};

/**
 * @brief Defines the registration status information of the PS domain.
 */
struct PsRegStatusResultInfo {
    /** The notifyType,Indicate the content of the notification. */
    int32_t notifyType = 0;

    /**
     * Valid when are is ITE UNKNOWN REG = REG, otherwise it defined in
     * RegStatus.
     */
    TelRilRegStatus regStatus = TelRilRegStatus::NO_REG_MT_NO_SEARCH;

    /** Location area code. */
    int32_t lacCode = 0;

    /** Cell ID. */
    int32_t cellId = 0;

    /** Radio access technology type. For details, see {@link RilRadioTech}. */
    TelRilRadioTech radioTechnology = TelRilRadioTech::RADIO_TECHNOLOGY_UNKNOWN;

    /** Whether the NR mode is available.*/
    bool isNrAvailable = false;

    /** Whether ENDC is available. */
    bool isEnDcAvailable = false;

    /** Whether DCNR is restricted. */
    bool isDcNrRestricted = false;

    /** flag, Used by search network manager in response. */
    int64_t flag = 0;
};

/**
 * @brief Defines the physical channel configuration.
 */
struct PhysicalChannelConfig {
    /** Connection status. */
    CellConnectionStatus cellConnStatus = CellConnectionStatus::SERVING_CELL_UNKNOWN;

    /** Radio access technology type. For details, see {@link RilRadioTech}. */
    TelRilRadioTech ratType = TelRilRadioTech::RADIO_TECHNOLOGY_UNKNOWN;

    /** Downlink bandwidth in kHz. */
    int32_t cellBandwidthDownlinkKhz = 0;

    /** Uplink bandwidth in kHz. */
    int32_t cellBandwidthUplinkKhz = 0;

    /** Frequency range. */
    int32_t freqRange = 0;

    /** Downlink channel ID. */
    int32_t downlinkChannelNum = 0;

    /** Uplink channel ID. */
    int32_t uplinkChannelNum = 0;

    /** Physical cell ID. */
    int32_t physicalCellId = 0;

    /** Logical device ID. */
    int32_t contextIdNum = 0;

    /**
     * A list of data calls mapped to this physical channel. An empty list
     * means the physical channel has no data call mapped to it.
     */
    std::vector<int32_t> contextIds {};
};

/**
 * @brief Defines the channel configuration information list.
 */
struct ChannelConfigInfoList {
    /** The size of ChannelConfigInfoList. */
    int32_t itemNum = 0;

    /** Physical channel configuration list. */
    std::vector<PhysicalChannelConfig> channelConfigInfos {};

    /** flag, Used by search network manager in response */
    int64_t flag = 0;
};

/**
 * @brief Defines the GSM cellular information.
 */
typedef struct {
    /** value:0~3 0:GSM850 1:GSM900 0:GSM1800 0:GSM1900 */
    int32_t band;

    /** Absolute Radio Frequency Channel Number of the BCCH carrier 0~1023 */
    int32_t arfcn;

    /** cell sit code 0~63 */
    int32_t bsic;

    /** Cell ID. */
    int32_t cellId;

    /** Location area code, which ranges from 0 to 0xFFFF. */
    int32_t lac;

    /** Signal received strength, which ranges from -120 to 37. */
    int32_t rxlev;

    /** Signal received quality, which ranges from 0 to 7. */
    int32_t rxQuality;

    /** Timing advance, which ranges from 0 to 63. */
    int32_t ta;
} CellRatGsm;

/**
 * @brief Defines the LTE cellular information.
 */
typedef struct {
    /** Absolute Radio Frequency Channel Number of the BCCH carrier 0~1023 */
    int32_t arfcn;

    /** Cell ID. */
    int32_t cellId;

    /** Physical cell ID. */
    int32_t pci;

    /** Tracking Area Code 0~FFFF */
    int32_t tac;

    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rsrp;

    /** Reference Signal Received Quality -19.5~-3 */
    int32_t rsrq;

    /** Receiving signal strength in dbm 90~-25 */
    int32_t rssi;
} CellRatLte;

/**
 * @brief Defines the WCDMA cellular information.
 */
typedef struct {
    /** Absolute Radio Frequency Channel Number of the BCCH carrier 0~1023 */
    int32_t arfcn;

    /** Primary Scrambling Code. 0~511 */
    int32_t psc;

    /** Cell ID. */
    int32_t cellId;

    /** Tracking Area Code 0~FFFF. */
    int32_t lac;

    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rscp;

    /** Reference Signal Received Quality -19.5~-3 */
    int32_t rxlev;

    /** Receiving signal strength in dbm 90~-25 */
    int32_t ecno;

    /** Discontinuous reception cycle length. 6~9 */
    int32_t drx;

    /** UTRAN Registration Area Identity. 0~65535 */
    int32_t ura;
} CellRatWcdma;

/**
 * @brief Defines the CDMA cellular information.
 */
typedef struct {
    /** integer type and range is 0-65535 */
    int32_t systemId;

    /** integer type and range is 0-65535 */
    int32_t networkId;

    /** integer type and range is 0-65535 */
    int32_t baseId;

    /** integer type and range is 0-65535 */
    int32_t zoneId;

    /** integer type and range is 0-65535 */
    int32_t pilotPn;

    /** integer type and range is 0-65535 */
    int32_t pilotStrength;

    /** integer type and range is 0-65535 */
    int32_t channel;

    /** integer type and range is -648000 -- 648000, unit: second */
    int32_t longitude;

    /** integer type and range is -648000 -- 648000, unit: second */
    int32_t latitude;
} CellRatCdma;

/**
 * @brief Defines the TD-SCDMA cellular information.
 */
typedef struct {
    /** Absolute RF channel number of the BCCH carrier. */
    int32_t arfcn;

    /** Synchronization flag. */
    int32_t syncId;

    /** Super cell. */
    int32_t sc;

    /** Cell ID. */
    int32_t cellId;

    /** Location area code. */
    int32_t lac;

    /** Received signal code power. */
    int32_t rscp;

    /** Discontinuous reception cycle. */
    int32_t drx;

    /** Routing area code. */
    int32_t rac;

    /** Super cell ID. */
    int32_t cpid;
} CellRatTdscdma;

/**
 * @brief Defines the NR cellular information.
 */
typedef struct {
    /** Absolute RF channel number of the BCCH carrier. */
    int32_t nrArfcn;

    /** Physical cell ID. */
    int32_t pci;

    /** Tracking Area Code, which ranges from 0 to FFFF. */
    int32_t tac;

    /** NR cell ID. */
    int64_t nci;
} CellRatNr;

/**
 * @brief Defines the current cell information.
 */
struct CurrentCellInfo {
    /** Radio access technology type. */
    int32_t ratType = 0;

    /** Mobile country code (MCC). */
    int32_t mcc = 0;

    /** Mobile network code (MNC). */
    int32_t mnc = 0;

    /** Cell information parameters. */
    union {
        CellRatGsm gsm;
        CellRatLte lte;
        CellRatWcdma wcdma;
        CellRatCdma cdma;
        CellRatTdscdma tdscdma;
        CellRatNr nr;
    } ServiceCellParas;
};

/**
 * @brief Defines the current cell information list.
 */
struct CellListCurrentInfo {
    /** The size of current cell information list. */
    int32_t itemNum = 0;

    /** Current cell information. */
    std::vector<CurrentCellInfo> cellCurrentInfo {};
};

/**
 * @brief Defines the NR cellular information.
 */
typedef struct {
    /** Absolute RF channel number of the BCCH carrier. */
    int32_t nrArfcn;

    /** Physical cell ID. */
    int32_t pci;

    /** Tracking Area Code, which ranges from 0 to FFFF. */
    int32_t tac;

    /** NR cell ID. */
    int64_t nci;

    /** Reference Signal Received Power. */
    int32_t rsrp;

    /** Reference Signal Received Quality. */
    int32_t rsrq;
} CellRatNrExt;

/**
 * @brief Defines the current cell information.
 */
struct CurrentCellInformation {
    /** Radio access technology type. */
    int32_t ratType = 0;

    /** Mobile country code (MCC). */
    int32_t mcc = 0;

    /** Mobile network code (MNC). */
    int32_t mnc = 0;

    /** Cell information parameters. */
    union {
        CellRatGsm gsm;
        CellRatLte lte;
        CellRatWcdma wcdma;
        CellRatCdma cdma;
        CellRatTdscdma tdscdma;
        CellRatNrExt nr;
    } ServiceCellParas;
};

/**
 * @brief Defines the current cell information list.
 */
struct CellListCurrentInformation {
    /** The size of current cell information list. */
    int32_t itemNum = 0;

    /** Current cell information. */
    std::vector<CurrentCellInformation> cellCurrentInfo {};
};

/**
 * @brief Defines the GSM cell information.
 */
typedef struct {
    /** value:0~3 0:GSM850 1:GSM900 0:GSM1800 0:GSM1900 */
    int32_t band;

    /** Absolute Radio Frequency Channel Number of the BCCHcarrier 0~1023 */
    int32_t arfcn;

    /** cell sit code 0~63 */
    int32_t bsic;

    /** Cell information ID */
    int32_t cellId;

    /** Location area code 0~FFFF */
    int32_t lac;

    /** <RXLEV> dbm -120~37 */
    int32_t rxlev;
} CellListRatGsm;

/**
 * @brief Defines the LTE cell information.
 */
typedef struct {
    /** Absolute Radio FreListquency Channel Number of the BCCHcarrier 0~1023
     */
    int32_t arfcn;

    /** Physical cell ID. */
    int32_t pci;

    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rsrp;

    /** Reference Signal Received Quality -19.5~-3 */
    int32_t rsrq;

    /** <RXLEV> dbm -120~37 */
    int32_t rxlev;
} CellListRatLte;

/**
 * @brief Defines the WCDMA cell information.
 */
typedef struct {
    /** Absolute Radio Frequency Channel Number of the BCCHcarrier 0~16383 */
    int32_t arfcn;

    /** Primary Scrambling Code. 0~511 */
    int32_t psc;

    /** Received Signal Code Power in dBm -120~25, dBm */
    int32_t rscp;

    /** The ratio of power per modulation bit to noise spectral density. -25~0
     */
    int32_t ecno;
} CellListRatWcdma;

/**
 * @brief Defines the CDMA cell information.
 */
typedef struct {
    /** integer type and range is 0-65535 */
    int32_t systemId;

    /** integer type and range is 0-65535 */
    int32_t networkId;

    /** integer type and range is 0-65535 */
    int32_t baseId;

    /** integer type and range is 0-65535 */
    int32_t zoneId;

    /** integer type and range is 0-65535 */
    int32_t pilotPn;

    /** integer type and range is 0-65535 */
    int32_t pilotStrength;

    /** integer type and range is 0-65535 */
    int32_t channel;

    /** integer type and range is -648000 -- 648000, unit: second */
    int32_t longitude;

    /** integer type and range is -648000 -- 648000, unit: second */
    int32_t latitude;
} CellListRatCdma;

/**
 * @brief Defines the TD-SCDMA cell information.
 */
typedef struct {
    /** Absolute RF channel number of the BCCH carrier. */
    int32_t arfcn;

    /** Synchronization flag. */
    int32_t syncId;

    /** Super cell. */
    int32_t sc;

    /** Cell ID. */
    int32_t cellId;

    /** Location area code, which ranges from 0 to 0xFFFF. */
    int32_t lac;

    /** Received signal code power. */
    int32_t rscp;

    /** Discontinuous reception cycle. */
    int32_t drx;

    /** Routing area code. */
    int32_t rac;

    /** 8-bit Cell Parameters ID described in TS 25.331, 0..127, INT_MAX if
     * unknown */
    int32_t cpid;
} CellListRatTdscdma;

/**
 * @brief Defines the NR cell information.
 */
typedef struct {
    /** Absolute RF channel number of the BCCH carrier. */
    int32_t nrArfcn;

    /** Physical cell ID. */
    int32_t pci;

    /** Tracking Area Code, which ranges from 0 to FFFF. */
    int32_t tac;

    /** NR cell ID. */
    int64_t nci;

    /** Reference Signal Received Power. */
    int32_t rsrp;

    /** Reference Signal Received Quality. */
    int32_t rsrq;
} CellListRatNr;

/**
 * @brief Defines the neighboring cell information.
 */
struct CellNearbyInfo {
    /**
     * Access technology type:
     * 0: unknown
     * 1: GSM
     * 2: CDMA
     * 3: WCDMA
     * 4: TD-SCDMA
     * 5: LTE
     * 6: NR
     */
    int32_t ratType = 0;

    /** Cell information for different network modes. */
    union {
        CellListRatGsm gsm;
        CellListRatLte lte;
        CellListRatWcdma wcdma;
        CellListRatCdma cdma;
        CellListRatTdscdma tdscdma;
        CellListRatNr nr;
    } ServiceCellParas;
};

/**
 * @brief Defines the neighboring cell list.
 */
struct CellListNearbyInfo {
    /** The size of nearby info of cell list. */
    int32_t itemNum = 0;

    /** Neighboring cell list. */
    std::vector<CellNearbyInfo> cellNearbyInfo {};
};

/**
 * @brief Defines the preferred network type.
 */
struct PreferredNetworkTypeInfo {
    /**
     * Network type
     * 0: automatic
     * 1: GSM
     * 2: WCDMA.
     * 3: LTE.
     * 4: LTE and WCDMA
     * 5: LTE, WCDMA, and GSM
     * 6: WCDMA and GSM
     * 7: CDMA
     * 8: EV-DO
     * 9: EV-DO and CDMA
     * 10: WCDMA, GSM, EV-DO, and CDMA
     * 11: LTE, EV-DO, and CDMA
     * 12: LTE, WCDMA, GSM, EV-DO, and CDMA
     * 13: TD-SCDMA
     * 14: TD-SCDMA and GSM
     * 15: TD-SCDMA and WCDMA
     * 16: TD-SCDMA, WCDMA, and GSM
     * 17: LTE and TD-SCDMA
     * 18: LTE, TDSCDMA, and GSM
     * 19: LTE, TD-SCDMA, and WCDMA
     * 20: LTE, TDSCDMA, WCDMA, and GSM
     * 21: TD-SCDMA, WCDMA, GSM, EV-DO, and CDMA
     * 22: LTE, TD-SCDMA, WCDMA, GSM, EV-DO, and CDMA
     * 31: NR
     * 32: NR and LTE
     * 33: NR, LTE, and WCDMA
     * 34: NR, LTE, WCDMA, and GSM
     * 35: NR, LTE, EV-DO, and CDMA
     * 36: NR, LTE, WCDMA, GSM, EV-DO, and CDMA
     * 37: NR, LTE, and TD-SCDMA.
     * 38: NR, LTE, TDSCDMA, and GSM
     * 39: NR, LTE, TD-SCDMA, and WCDMA
     * 40: NR, LTE, TD-SCDMA, WCDMA, and GSM
     * 41: NR, LTE, TD-SCDMA, WCDMA, GSM, EV-DO, and CDMA
     */
    int32_t preferredNetworkType = 0;

    /** Network ID */
    int64_t flag = 0;
};

struct NrModeInfo {
    int32_t nrMode = 0;
    int64_t flag = 0;
};

struct SsbIdInfo {
    /** SSB index. */
    int32_t ssbId;

    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rsrp;
};

struct NeighboringCellSsbInfo {
    /** Physical cell ID. */
    int32_t pci;

    /** Absolute Radio Frequency Channel Number of the BCCH carrier 0~1023 */
    int32_t arfcn;

    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rsrp;

    /** Signal To Interference Plus Noise Ratio. */
    int32_t sinr;

    /** Neighboring cell ssbId list, always size is 4 */
    std::vector<SsbIdInfo> ssbIdList;
};

struct NrCellSsbIds {
    /** Absolute Radio Frequency Channel Number of the BCCH carrier 0~1023 */
    int32_t arfcn;

    /** cid */
    int64_t cid;

    /** pic */
    int32_t pic;

    /** Reference Signal Received Power -140~-44, dBm */
    int32_t rsrp;

    /** Signal To Interference Plus Noise Ratio. */
    int32_t sinr;

    /** Time advance. */
    int32_t timeAdvance;

    /** Service cell ssbId list, always size is 8 */
    std::vector<SsbIdInfo> sCellSsbList;

    /** Neighboring cell ssb list count, mas size is 4 */
    int32_t nbCellCount;

    /** Neighboring cell ssb info list, mas size is 4 */
    std::vector<NeighboringCellSsbInfo> nbCellSsbList;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_NETWORK_PARCEL_H
