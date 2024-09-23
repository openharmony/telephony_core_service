/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_RADIO_UTILS_H
#define TELEPHONY_RADIO_UTILS_H

#include <condition_variable>
#include <locale>
#include <mutex>
#include <string>

#include "telephony_errors.h"
#include "telephony_napi_common_error.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
    constexpr int DEFAULT_ERROR = ERROR_SERVICE_UNAVAILABLE;
    constexpr int BUF_SIZE = 32;
    constexpr int WAIT_TIME_SECOND = 60 * 3;

    inline char* MallocCString(const std::string& origin)
    {
        if (origin.empty()) {
            return nullptr;
        }
        auto lenth = origin.length() + 1;
        char* res = static_cast<char*>(malloc(sizeof(char) * lenth));
        if (res == nullptr) {
            return nullptr;
        }
        return std::char_traits<char>::copy(res, origin.c_str(), lenth);
    }

    struct CNetworkRadioTech {
        int32_t psRadioTech;
        int32_t csRadioTech;
    };

    enum class NetworkType : int32_t {
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

    enum class RatType : int32_t {
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

    enum class NsaState : int32_t {
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

    enum CJErrorCode {
        /**
         * The input parameter value is out of range.
         */
        CJ_ERROR_TELEPHONY_ARGUMENT_ERROR = 8300001,

        /**
         * Operation failed. Cannot connect to service.
         */
        CJ_ERROR_TELEPHONY_SERVICE_ERROR = 8300002,

        /**
         * System internal error.
         */
        CJ_ERROR_TELEPHONY_SYSTEM_ERROR = 8300003,

        /**
         * Do not have sim card.
         */
        CJ_ERROR_TELEPHONY_NO_SIM_CARD = 8300004,

        /**
         * Airplane mode is on.
         */
        CJ_ERROR_TELEPHONY_AIRPLANE_MODE_ON = 8300005,

        /**
         * Network not in service.
         */
        CJ_ERROR_TELEPHONY_NETWORK_NOT_IN_SERVICE = 8300006,

        /**
         * Unknown error code.
         */
        CJ_ERROR_TELEPHONY_UNKNOW_ERROR = 8300999,

        /**
         * SIM card is not activated.
         */
        CJ_ERROR_SIM_CARD_IS_NOT_ACTIVE = 8301001,

        /**
         * SIM card operation error.
         */
        CJ_ERROR_SIM_CARD_OPERATION_ERROR = 8301002,

        /**
         * Operator config error.
         */
        CJ_ERROR_OPERATOR_CONFIG_ERROR = 8301003,

        /**
         * Permission verification failed, usually the result returned by VerifyAccessToken.
         */
        CJ_ERROR_TELEPHONY_PERMISSION_DENIED = 201,

        /**
         * Permission verification failed, application which is not a system application uses system API.
         */
        CJ_ERROR_ILLEGAL_USE_OF_SYSTEM_API = 202,
    };

    struct CNetworkState {
        char* longOperatorName;
        char* shortOperatorName;
        char* plmnNumeric;
        bool isRoaming;
        int32_t regState;
        int32_t cfgTech;
        int32_t nsaState;
        bool isCaActive;
        bool isEmergency;
    };

    struct CSignalInformation {
        int32_t signalType;
        int32_t signalLevel;
        int32_t dBm;
    };

    struct CArraySignalInformation {
        CSignalInformation* head;
        int64_t size;
    };

    struct CallbackContext {
        std::mutex callbackMutex;
        std::condition_variable cv;
        bool callbackEnd = false;
        bool sendRequest = false;
        bool resolved = false;
        int32_t errorCode = ERROR_DEFAULT;
    };

    struct GetSelectModeContext : CallbackContext {
        int32_t slotId = DEFAULT_SIM_SLOT_ID;
        int32_t selectMode = DEFAULT_ERROR;
    };

    struct IsRadioOnContext : CallbackContext {
        int32_t slotId = DEFAULT_SIM_SLOT_ID;
        bool isRadioOn = false;
        bool sendRequestSlot2 = false;
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
}
}

#endif