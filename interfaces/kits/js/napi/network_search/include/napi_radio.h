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

#ifndef NAPI_RADIO_H
#define NAPI_RADIO_H

#include <codecvt>
#include <locale>
#include <string>

#include <mutex>
#include <condition_variable>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_util.h"
#include "network_state.h"
#include "signal_information.h"
#include "network_information.h"
#include "telephony_napi_hril_error_code.h"
#include "telephony_napi_common_error.h"
#include "core_manager.h"

namespace OHOS {
namespace Telephony {
constexpr int DEFAULT_ERROR = ERROR_SERVICE_UNAVAILABLE;
constexpr int RESOLVED = 1;
constexpr int REJECT = 0;
constexpr int BUF_SIZE = 32;
constexpr int WAIT_TIME_SECOND = 60 * 3;

enum RadioType {
    /**
     * Indicates unknown radio access technology (RAT).
     */
    RADIO_TECH_UNKNOWN = 0,

    /**
     * Indicates that RAT is global system for mobile communications (GSM), including GSM, general packet
     * radio system (GPRS), and enhanced data rates for GSM evolution (EDGE).
     */
    RADIO_TECH_GSM = 1,

    /**
     * Indicates that RAT is code division multiple access (CDMA), including Interim Standard 95 (IS95) and
     * Single-Carrier Radio Transmission Technology (1xRTT).
     */
    RADIO_TECH_1XRTT = 2,

    /**
     * Indicates that RAT is wideband code division multiple address (WCDMA).
     */
    RADIO_TECH_WCDMA = 3,

    /**
     * Indicates that RAT is high-speed packet access (HSPA), including HSPA, high-speed downlink packet
     * access (HSDPA), and high-speed uplink packet access (HSUPA).
     */
    RADIO_TECH_HSPA = 4,

    /**
     * Indicates that RAT is evolved high-speed packet access (HSPA+), including HSPA+ and dual-carrier
     * HSPA+ (DC-HSPA+).
     */
    RADIO_TECH_HSPAP = 5,

    /**
     * Indicates that RAT is time division-synchronous code division multiple access (TD-SCDMA).
     */
    RADIO_TECH_TD_SCDMA = 6,

    /**
     * Indicates that RAT is evolution data only (EVDO), including EVDO Rev.0, EVDO Rev.A, and EVDO Rev.B.
     */
    RADIO_TECH_EVDO = 7,

    /**
     * Indicates that RAT is evolved high rate packet data (EHRPD).
     */
    RADIO_TECH_EHRPD = 8,

    /**
     * Indicates that RAT is long term evolution (LTE).
     */
    RADIO_TECH_LTE = 9,

    /**
     * Indicates that RAT is LTE carrier aggregation (LTE-CA).
     */
    RADIO_TECH_LTE_CA = 10,

    /**
     * Indicates that RAT is interworking WLAN (I-WLAN).
     */
    RADIO_TECH_IWLAN = 11,

    /**
     * Indicates that RAT is 5G new radio (NR).
     */
    RADIO_TECH_NR = 12
};

enum NetworkType {
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

enum NsaState {
    /**
     * Indicates that a device is idle under or is connected to an LTE cell that does not support NSA.
     */
    NSA_STATE_NOT_SUPPORT = 1,

    /**
     * Indicates that a device is idle under an LTE cell supporting NSA but not NR coverage detection.
     */
    NSA_STATE_NO_DETECT = 2,

    /**
     * Indicates that a device is connected to an LTE network under an LTE cell
     * that supports NSA and NR coverage detection.
     */
    NSA_STATE_CONNECTED_DETECT = 3,

    /**
     * Indicates that a device is idle under an LTE cell supporting NSA and NR coverage detection.
     */
    NSA_STATE_IDLE_DETECT = 4,

    /**
     * Indicates that a device is connected to an LTE + NR network under an LTE cell that supports NSA.
     */
    NSA_STATE_DUAL_CONNECTED = 5,

    /**
     * Indicates that a device is idle under or is connected to an NG-RAN cell while being attached to 5GC.
     */
    NSA_STATE_SA_ATTACHED = 6
};

enum NativeSelectionMode { NATIVE_NETWORK_SELECTION_AUTOMATIC = 0, NATIVE_NETWORK_SELECTION_MANUAL = 1 };

enum NetworkSelectionMode {
    /** Unknown network selection modes. */
    NETWORK_SELECTION_UNKNOWN,

    /** Automatic network selection modes. */
    NETWORK_SELECTION_AUTOMATIC,

    /** Manual network selection modes. */
    NETWORK_SELECTION_MANUAL
};

enum NetworkInformationState {
    /** Indicates that the network state is unknown. */
    NETWORK_UNKNOWN,

    /** Indicates that the network is available for registration. */
    NETWORK_AVAILABLE,

    /** Indicates that you have already registered with the network. */
    NETWORK_CURRENT,

    /** Indicates that the network is unavailable for registration. */
    NETWORK_FORBIDDEN
};

struct AsyncContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    int status = DEFAULT_ERROR;
    int32_t result = DEFAULT_ERROR;
};

struct CallbackContext : BaseContext {
    std::mutex callbackMutex;
    std::condition_variable cv;
    bool callbackEnd = false;
    bool sendRequest = false;
    int32_t errorCode = HRIL_ERR_GENERIC_FAILURE;
};

struct RadioTechContext : BaseContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    int32_t csTech = DEFAULT_ERROR;
    int32_t psTech = DEFAULT_ERROR;
};

struct SignalInfoListContext : BaseContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    std::vector<sptr<SignalInformation>> signalInfoList;
};

struct GetSelectModeContext : CallbackContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    int32_t selectMode = DEFAULT_ERROR;
};

struct SetSelectModeContext : CallbackContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    int32_t selectMode = DEFAULT_ERROR;
    std::string operatorName = "";
    std::string operatorNumeric = "";
    int32_t state = NETWORK_UNKNOWN;
    std::string radioTech = "";
    bool resumeSelection = false;
    bool setResult = false;
};

struct GetSearchInfoContext : CallbackContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    NetworkSearchResult *searchResult = nullptr;
};

struct GetStateContext : BaseContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    std::string longOperatorName = "";
    std::string shortOperatorName = "";
    std::string plmnNumeric = "";
    bool isRoaming = false;
    int32_t regStatus = 0;
    int32_t nsaState = NSA_STATE_NOT_SUPPORT;
    bool isCaActive = false;
    bool isEmergency = false;
};

struct GetISOCountryCodeContext : BaseContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    std::string countryCode = "";
};

struct IsRadioOnContext : CallbackContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    bool isRadioOn = false;
};

struct SwitchRadioContext : CallbackContext {
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
};
} // namespace Telephony
} // namespace OHOS
#endif // NAPI_RADIO_H