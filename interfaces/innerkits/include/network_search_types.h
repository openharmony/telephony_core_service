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

#ifndef NETWORK_SEARCH_TYPES_H
#define NETWORK_SEARCH_TYPES_H

#include "parcel.h"

namespace OHOS {
namespace Telephony {
constexpr const char *CUR_SLOT_ID = "CUR_SLOT_ID";
constexpr const char *CUR_PLMN_SHOW = "CUR_PLMN_SHOW";
constexpr const char *CUR_PLMN = "CUR_PLMN";
constexpr const char *CUR_SPN_SHOW = "CUR_SPN_SHOW";
constexpr const char *CUR_SPN = "CUR_SPN";

enum class DomainType {
    DOMAIN_TYPE_PS,
    DOMAIN_TYPE_CS,
};

enum class RegServiceState {
    REG_STATE_UNKNOWN,
    REG_STATE_IN_SERVICE,
    REG_STATE_NO_SERVICE,
    REG_STATE_EMERGENCY_ONLY,
    REG_STATE_SEARCH,
    REG_STATE_POWER_OFF
};

enum class RoamingType {
    ROAMING_STATE_UNKNOWN,
    ROAMING_STATE_UNSPEC,
    ROAMING_STATE_DOMESTIC,
    ROAMING_STATE_INTERNATIONAL
};

/**
 * Describes the radio access technology.
 */
enum class RadioTech {
    /**
     * Indicates the invalid value.
     */
    RADIO_TECHNOLOGY_INVALID = -1,

    /**
     * Indicates unknown radio access technology (RAT).
     */
    RADIO_TECHNOLOGY_UNKNOWN = 0,

    /**
     * Indicates that RAT is global system for mobile communications (GSM), including GSM, general packet
     * radio system (GPRS), and enhanced data rates for GSM evolution (EDGE).
     */
    RADIO_TECHNOLOGY_GSM = 1,

    /**
     * Indicates that RAT is code division multiple access (CDMA), including Interim Standard 95 (IS95) and
     * Single-Carrier Radio Transmission Technology (1xRTT).
     */
    RADIO_TECHNOLOGY_1XRTT = 2,

    /**
     * Indicates that RAT is wideband code division multiple address (WCDMA).
     */
    RADIO_TECHNOLOGY_WCDMA = 3,

    /**
     * Indicates that RAT is high-speed packet access (HSPA), including HSPA, high-speed downlink packet
     * access (HSDPA), and high-speed uplink packet access (HSUPA).
     */
    RADIO_TECHNOLOGY_HSPA = 4,

    /**
     * Indicates that RAT is evolved high-speed packet access (HSPA+), including HSPA+ and dual-carrier
     * HSPA+ (DC-HSPA+).
     */
    RADIO_TECHNOLOGY_HSPAP = 5,

    /**
     * Indicates that RAT is time division-synchronous code division multiple access (TD-SCDMA).
     */
    RADIO_TECHNOLOGY_TD_SCDMA = 6,

    /**
     * Indicates that RAT is evolution data only (EVDO), including EVDO Rev.0, EVDO Rev.A, and EVDO Rev.B.
     */
    RADIO_TECHNOLOGY_EVDO = 7,

    /**
     * Indicates that RAT is evolved high rate packet data (EHRPD).
     */
    RADIO_TECHNOLOGY_EHRPD = 8,

    /**
     * Indicates that RAT is long term evolution (LTE).
     */
    RADIO_TECHNOLOGY_LTE = 9,

    /**
     * Indicates that RAT is LTE carrier aggregation (LTE-CA).
     */
    RADIO_TECHNOLOGY_LTE_CA = 10,

    /**
     * Indicates that RAT is interworking WLAN (I-WLAN).
     */
    RADIO_TECHNOLOGY_IWLAN = 11,

    /**
     * Indicates that RAT is 5G new radio (NR).
     */
    RADIO_TECHNOLOGY_NR = 12,

    /**
     * Indicates the max value.
     */
    RADIO_TECHNOLOGY_MAX = RADIO_TECHNOLOGY_NR,
};

/**
 * Describes the nsa sa state.
 */
enum class NrState {
    /**
     * Indicates that a device is idle under or is connected to an LTE cell that does not support NSA.
     */
    NR_STATE_NOT_SUPPORT = 1,

    /**
     * Indicates that a device is idle under an LTE cell supporting NSA but not NR coverage detection.
     */
    NR_NSA_STATE_NO_DETECT = 2,

    /**
     * Indicates that a device is connected to an LTE network under an LTE cell
     * that supports NSA and NR coverage detection.
     */
    NR_NSA_STATE_CONNECTED_DETECT = 3,

    /**
     * Indicates that a device is idle under an LTE cell supporting NSA and NR coverage detection.
     */
    NR_NSA_STATE_IDLE_DETECT = 4,

    /**
     * Indicates that a device is connected to an LTE + NR network under an LTE cell that supports NSA.
     */
    NR_NSA_STATE_DUAL_CONNECTED = 5,

    /**
     * Indicates that a device is idle under or is connected to an NG-RAN cell while being attached to 5GC.
     */
    NR_NSA_STATE_SA_ATTACHED = 6
};

enum class NrMode {
    /** Indicates unknown NR networking mode. */
    NR_MODE_UNKNOWN,

    /** Indicates that the NR networking mode is NSA only. */
    NR_MODE_NSA_ONLY,

    /** Indicates that the NR networking mode is SA only. */
    NR_MODE_SA_ONLY,

    /** Indicates that the NR networking mode is NSA and SA. */
    NR_MODE_NSA_AND_SA,
};

enum class FrequencyType { FREQ_TYPE_UNKNOWN = 0, FREQ_TYPE_MMWAVE };

enum class PhoneType { PHONE_TYPE_IS_NONE, PHONE_TYPE_IS_GSM, PHONE_TYPE_IS_CDMA };

enum class SelectionMode { MODE_TYPE_UNKNOWN = -1, MODE_TYPE_AUTO = 0, MODE_TYPE_MANUAL = 1 };

enum class PreferredNetworkMode {
    CORE_NETWORK_MODE_AUTO = 0,
    CORE_NETWORK_MODE_GSM = 1,
    CORE_NETWORK_MODE_WCDMA = 2,
    CORE_NETWORK_MODE_LTE = 3,
    CORE_NETWORK_MODE_LTE_WCDMA = 4,
    CORE_NETWORK_MODE_LTE_WCDMA_GSM = 5,
    CORE_NETWORK_MODE_WCDMA_GSM = 6,
    CORE_NETWORK_MODE_CDMA = 7,
    CORE_NETWORK_MODE_EVDO = 8,
    CORE_NETWORK_MODE_EVDO_CDMA = 9,
    CORE_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA = 10,
    CORE_NETWORK_MODE_LTE_EVDO_CDMA = 11,
    CORE_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA = 12,
    CORE_NETWORK_MODE_TDSCDMA = 13,
    CORE_NETWORK_MODE_TDSCDMA_GSM = 14,
    CORE_NETWORK_MODE_TDSCDMA_WCDMA = 15,
    CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM = 16,
    CORE_NETWORK_MODE_LTE_TDSCDMA = 17,
    CORE_NETWORK_MODE_LTE_TDSCDMA_GSM = 18,
    CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA = 19,
    CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM = 20,
    CORE_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 21,
    CORE_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 22,
    CORE_NETWORK_MODE_NR = 31,
    CORE_NETWORK_MODE_NR_LTE = 32,
    CORE_NETWORK_MODE_NR_LTE_WCDMA = 33,
    CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM = 34,
    CORE_NETWORK_MODE_NR_LTE_EVDO_CDMA = 35,
    CORE_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA = 36,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA = 37,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA_GSM = 38,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA = 39,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM = 40,
    CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 41,
    CORE_NETWORK_MODE_MAX_VALUE = 99,
};

struct OperatorInformation {
    std::string operatorNumeric;
    std::string fullName;
    std::string shortName;
};

enum class RadioProtocolTech {
    RADIO_PROTOCOL_TECH_UNKNOWN = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_UNKNOWN),
    RADIO_PROTOCOL_TECH_GSM = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_GSM),
    RADIO_PROTOCOL_TECH_1XRTT = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_1XRTT),
    RADIO_PROTOCOL_TECH_WCDMA = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_WCDMA),
    RADIO_PROTOCOL_TECH_HSPA = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_HSPA),
    RADIO_PROTOCOL_TECH_HSPAP = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_HSPAP),
    RADIO_PROTOCOL_TECH_TD_SCDMA = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_TD_SCDMA),
    RADIO_PROTOCOL_TECH_EVDO = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_EVDO),
    RADIO_PROTOCOL_TECH_EHRPD = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_EHRPD),
    RADIO_PROTOCOL_TECH_LTE = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_LTE),
    RADIO_PROTOCOL_TECH_LTE_CA = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_LTE_CA),
    RADIO_PROTOCOL_TECH_IWLAN = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_IWLAN),
    RADIO_PROTOCOL_TECH_NR = 1 << static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_NR),
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_TYPES_H
