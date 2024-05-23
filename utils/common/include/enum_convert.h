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

#ifndef ENUM_CONVERT_H
#define ENUM_CONVERT_H

#include <map>
#include <stdint.h>
#include <string>

#include "iosfwd"

namespace OHOS {
namespace Telephony {
/**
 * @brief Indicates the SIM card types.
 */
enum class TelephonyCardType {
    /**
     * Icc card type: unknown type Card.
     */
    UNKNOWN_CARD = -1,
    /**
     * Icc card type: Single sim card type.
     */
    SINGLE_MODE_SIM_CARD = 10,
    /**
     * Icc card type: Single usim card type.
     */
    SINGLE_MODE_USIM_CARD = 20,
    /**
     * Icc card type: Single ruim card type.
     */
    SINGLE_MODE_RUIM_CARD = 30,
    /**
     * Icc card type: Double card C+G.
     */
    DUAL_MODE_CG_CARD = 40,
    /**
     * Icc card type: China Telecom Internal Roaming Card (Dual Mode).
     */
    CT_NATIONAL_ROAMING_CARD = 41,
    /**
     * Icc card type: China Unicom Dual Mode Card.
     */
    CU_DUAL_MODE_CARD = 42,
    /**
     * Icc card type: China Telecom LTE Card (Dual Mode).
     */
    DUAL_MODE_TELECOM_LTE_CARD = 43,
    /**
     * Icc card type: Double card U+G.
     */
    DUAL_MODE_UG_CARD = 50,
    /**
     * Icc card type: Single isim card type.
     */
    SINGLE_MODE_ISIM_CARD = 60,
};

/**
 * @brief Indicates the SIM card states.
 */
enum class TelephonySimState {
    /**
     * Indicates unknown SIM card state, the accurate status cannot be obtained.
     */
    SIM_STATE_UNKNOWN,
    /**
     * Indicates the SIM card is in not present state, no SIM card is inserted into the card slot.
     */
    SIM_STATE_NOT_PRESENT,
    /**
     * Indicates the SIM card is in locked state, the SIM card is locked by
     * the personal identification number (PIN)/PIN unblocking key (PUK) or network.
     */
    SIM_STATE_LOCKED,
    /**
     * Indicates the SIM card is in not ready state, the SIM card is in position but cannot work properly.
     */
    SIM_STATE_NOT_READY,
    /**
     * Indicates the SIM card is in the ready state, the SIM card is in position and is working properly.
     */
    SIM_STATE_READY,
    /**
     * Indicates the SIM card is in the loaded state, the SIM card is in position and is working properly.
     */
    SIM_STATE_LOADED
};

/**
 * @brief Indicates the cellular data link connection state.
 */
enum class TelephonyDataConnectionStatus {
    /**
     * Indicates that a cellular data link is disconnected.
     */
    DATA_STATE_DISCONNECTED = 11,
    /**
     * Indicates that a cellular data link is being connected.
     */
    DATA_STATE_CONNECTING = 12,
    /**
     * Indicates that a cellular data link is connected.
     */
    DATA_STATE_CONNECTED = 13,
    /**
     * Indicates that a cellular data link is suspended.
     */
    DATA_STATE_SUSPENDED = 14
};

/**
 * @brief Indicates the state of call.
 */
enum class TelephonyCallState {
    /**
     * Indicates the call is active.
     */
    CALL_STATUS_ACTIVE = 0,
    /**
     * Indicates the call is holding.
     */
    CALL_STATUS_HOLDING,
    /**
     * Indicates the call is dialing.
     */
    CALL_STATUS_DIALING,
    /**
     * Indicates the call is alerting.
     */
    CALL_STATUS_ALERTING,
    /**
     * Indicates the call is incoming.
     */
    CALL_STATUS_INCOMING,
    /**
     * Indicates the call is waiting.
     */
    CALL_STATUS_WAITING,
    /**
     * Indicates the call is disconnected.
     */
    CALL_STATUS_DISCONNECTED,
    /**
     * Indicates the call is disconnecting.
     */
    CALL_STATUS_DISCONNECTING,
    /**
     * Indicates the call is idle.
     */
    CALL_STATUS_IDLE,
};

/**
 * @brief Indicates the radio access technology.
 */
enum class TelephonyRadioTech {
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
    RADIO_TECHNOLOGY_NR = 12
};

/**
 * @brief Indicates the cellular data flow type.
 */
enum class TelephonyCellDataFlowType {
    /**
     * Indicates that there is no uplink or downlink data.
     */
    DATA_FLOW_TYPE_NONE = 0,
    /**
     * Indicates that there is only downlink data.
     */
    DATA_FLOW_TYPE_DOWN = 1,
    /**
     * Indicates that there is only uplink data.
     */
    DATA_FLOW_TYPE_UP = 2,
    /**
     * Indicates that there is uplink and downlink data.
     */
    DATA_FLOW_TYPE_UP_DOWN = 3,
    /**
     * Indicates that there is no uplink or downlink data, and the bottom-layer link is in the dormant state.
     */
    DATA_FLOW_TYPE_DORMANT = 4
};

/**
 * @brief Indicates SIM card lock type.
 */
enum class TelephonyLockReason {
    /**
     * Indicates no SIM lock.
     */
    SIM_NONE,
    /**
     * Indicates the PIN lock.
     */
    SIM_PIN,
    /**
     * Indicates the PUK lock.
     */
    SIM_PUK,
    /**
     * Indicates network personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_PN_PIN,
    /**
     * Indicates network personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_PN_PUK,
    /**
     * Indicates network subset personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_PU_PIN,
    /**
     * Indicates network subset personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_PU_PUK,
    /**
     * Indicates service provider personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_PP_PIN,
    /**
     * Indicates service provider personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_PP_PUK,
    /**
     * Indicates corporate personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_PC_PIN,
    /**
     * Indicates corporate personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_PC_PUK,
    /**
     * Indicates SIM/USIM personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_SIM_PIN,
    /**
     * Indicates SIM/USIM personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     */
    SIM_SIM_PUK,
};

/**
 * @brief Indicates the reg service states.
 */
enum class TelephonyRegServiceState {
    REG_STATE_UNKNOWN,
    REG_STATE_IN_SERVICE,
    REG_STATE_NO_SERVICE,
    REG_STATE_EMERGENCY_ONLY,
    REG_STATE_SEARCH,
    REG_STATE_POWER_OFF
};

/**
 * @brief Indicates the ril register states.
 */
enum class TelephonyRilRegisterState {
    REG_STATE_NOT_REG = 0,
    REG_STATE_HOME_ONLY = 1,
    REG_STATE_SEARCH = 2,
    REG_STATE_NO_SERVICE = 3,
    REG_STATE_INVALID = 4,
    REG_STATE_ROAMING = 5,
    REG_STATE_EMERGENCY_ONLY = 6
};

/**
 * @brief Indicates the sim Icc state.
 */
enum class TelephonySimIccState {
    ICC_CONTENT_UNKNOWN = -1,
    ICC_CARD_ABSENT,
    ICC_CONTENT_READY,
    ICC_CONTENT_PIN,
    ICC_CONTENT_PUK
};

const std::map<int32_t, std::string> simIccStatusMap_ = {
    { static_cast<int32_t>(TelephonySimIccState::ICC_CONTENT_UNKNOWN), "ICC_CONTENT_UNKNOWN" },
    { static_cast<int32_t>(TelephonySimIccState::ICC_CARD_ABSENT), "ICC_CARD_ABSENT" },
    { static_cast<int32_t>(TelephonySimIccState::ICC_CONTENT_READY), "ICC_CONTENT_READY" },
    { static_cast<int32_t>(TelephonySimIccState::ICC_CONTENT_PIN), "ICC_CONTENT_PIN" },
    { static_cast<int32_t>(TelephonySimIccState::ICC_CONTENT_PUK), "ICC_CONTENT_PUK" },
};

const std::map<int32_t, std::string> regServiceStateMap_ = {
    { static_cast<int32_t>(TelephonyRegServiceState::REG_STATE_UNKNOWN), "REG_STATE_UNKNOWN" },
    { static_cast<int32_t>(TelephonyRegServiceState::REG_STATE_IN_SERVICE), "REG_STATE_IN_SERVICE" },
    { static_cast<int32_t>(TelephonyRegServiceState::REG_STATE_NO_SERVICE), "REG_STATE_NO_SERVICE" },
    { static_cast<int32_t>(TelephonyRegServiceState::REG_STATE_EMERGENCY_ONLY), "REG_STATE_EMERGENCY_ONLY" },
    { static_cast<int32_t>(TelephonyRegServiceState::REG_STATE_SEARCH), "REG_STATE_SEARCH" },
    { static_cast<int32_t>(TelephonyRegServiceState::REG_STATE_POWER_OFF), "REG_STATE_POWER_OFF" },
};

const std::map<int32_t, std::string> rilRegisterStateMap_ = {
    { static_cast<int32_t>(TelephonyRilRegisterState::REG_STATE_NOT_REG), "REG_STATE_NOT_REG" },
    { static_cast<int32_t>(TelephonyRilRegisterState::REG_STATE_HOME_ONLY), "REG_STATE_HOME_ONLY" },
    { static_cast<int32_t>(TelephonyRilRegisterState::REG_STATE_SEARCH), "REG_STATE_SEARCH" },
    { static_cast<int32_t>(TelephonyRilRegisterState::REG_STATE_NO_SERVICE), "REG_STATE_NO_SERVICE" },
    { static_cast<int32_t>(TelephonyRilRegisterState::REG_STATE_INVALID), "REG_STATE_INVALID" },
    { static_cast<int32_t>(TelephonyRilRegisterState::REG_STATE_ROAMING), "REG_STATE_ROAMING" },
    { static_cast<int32_t>(TelephonyRilRegisterState::REG_STATE_EMERGENCY_ONLY), "REG_STATE_EMERGENCY_ONLY" },
};

/**
 * @brief Get the string of bool value.
 *
 * @param value
 * @return Return "FALSE" if the value is {@code 0}, return "TRUE" otherwise.
 */
std::string GetBoolValue(int32_t value);

/**
 * @brief Get the string of SIM state.
 *
 * @param state Indicates the state of SIM.
 * @return Return the string of SIM state.
 */
std::string GetSimState(int32_t state);

/**
 * @brief Get the string of call state.
 *
 * @param state Indicates the state of call.
 * @return Return the string of call state.
 */
std::string GetCallState(int32_t state);

/**
 * @brief Get the string of SIM card type.
 *
 * @param type Indicates the type of SIM card.
 * @return Return the string of SIM card type.
 */
std::string GetCardType(int32_t type);

/**
 * @brief Get the string of cellular data connection state.
 *
 * @param state Indicates the state of cellular data connection.
 * @return Return the string of cellular data connection state.
 */
std::string GetCellularDataConnectionState(int32_t state);

/**
 * @brief Get the string of cellular data flow type.
 *
 * @param flowData Indicates the cellular data flow type.
 * @return Return the string of cellular data flow type.
 */
std::string GetCellularDataFlow(int32_t flowData);

/**
 * @brief Get the string of radio access technology for cellular data.
 *
 * @param type Indicates the radio access technology.
 * @return Return the string of radio access technology.
 */
std::string GetCellularDataConnectionNetworkType(int32_t type);

/**
 * @brief Get the string of SIM lock reason.
 *
 * @param reason Indicates the the SIM lock reason.
 * @return Return the string of SIM lock reason.
 */
std::string GetLockReason(int32_t reason);
} // namespace Telephony
} // namespace OHOS

#endif // ENUM_CONVERT_H
