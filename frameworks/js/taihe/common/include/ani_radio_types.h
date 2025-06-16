/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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


#ifndef BASE_TELEPHONY_ANI_RADIO_TYPES_H
#define BASE_TELEPHONY_ANI_RADIO_TYPES_H

enum RegStatus {
    /**
     * Indicates a state in which a device cannot use any service.
     */
    REGISTRATION_STATE_NO_SERVICE = 0,

    /**
     * Indicates a state in which a device can use services properly.
     */
    REGISTRATION_STATE_IN_SERVICE = 1,

    /**
     * Indicates a state in which a device can use only the emergency call service.
     */
    REGISTRATION_STATE_EMERGENCY_CALL_ONLY = 2,

    /**
     * Indicates that the cellular radio is powered off.
     */
    REGISTRATION_STATE_POWER_OFF = 3
};

enum class RatType {
    /**
     * Indicates the invalid value.
     */
    RADIO_TECHNOLOGY_INVALID = -1,

    /**
     * Indicates unknown radio access technology (RAT).
     */
    RADIO_TECHNOLOGY_UNKNOWN = 0,

    /**
     * Indicates that RAT is global system for mobile communications (GSM),
     * including GSM, general packet radio system (GPRS), and enhanced data rates
     * for GSM evolution (EDGE).
     */
    RADIO_TECHNOLOGY_GSM = 1,

    /**
     * Indicates that RAT is code division multiple access (CDMA), including
     * Interim Standard 95 (IS95) and Single-Carrier Radio Transmission Technology
     * (1xRTT).
     */
    RADIO_TECHNOLOGY_1XRTT = 2,

    /**
     * Indicates that RAT is wideband code division multiple address (WCDMA).
     */
    RADIO_TECHNOLOGY_WCDMA = 3,

    /**
     * Indicates that RAT is high-speed packet access (HSPA), including HSPA,
     * high-speed downlink packet access (HSDPA), and high-speed uplink packet
     * access (HSUPA).
     */
    RADIO_TECHNOLOGY_HSPA = 4,

    /**
     * Indicates that RAT is evolved high-speed packet access (HSPA+), including
     * HSPA+ and dual-carrier HSPA+ (DC-HSPA+).
     */
    RADIO_TECHNOLOGY_HSPAP = 5,

    /**
     * Indicates that RAT is time division-synchronous code division multiple
     * access (TD-SCDMA).
     */
    RADIO_TECHNOLOGY_TD_SCDMA = 6,

    /**
     * Indicates that RAT is evolution data only (EVDO), including EVDO Rev.0,
     * EVDO Rev.A, and EVDO Rev.B.
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

enum class NetworkType {
    /**
     * Indicates unknown network type.
     */
    NETWORK_TYPE_UNKNOWN,

    /**
     * Indicates that the network type is GSM.
     */
    NETWORK_TYPE_GSM,

    /**
     * Indicates that the network type is CDMA.
     */
    NETWORK_TYPE_CDMA,

    /**
     * Indicates that the network type is WCDMA.
     */
    NETWORK_TYPE_WCDMA,

    /**
     * Indicates that the network type is TD-SCDMA.
     */
    NETWORK_TYPE_TDSCDMA,

    /**
     * Indicates that the network type is LTE.
     */
    NETWORK_TYPE_LTE,

    /**
     * Indicates that the network type is 5G NR.
     */
    NETWORK_TYPE_NR
};

#endif // ANI_RADIO_TYPES_H