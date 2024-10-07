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

#ifndef NATIVE_TELEPHONY_RADIO_TYPE_H
#define NATIVE_TELEPHONY_RADIO_TYPE_H

/**
 * @file telephony_radio_type.h
 *
 * @brief Provides the data structures for the C APIs of the the telephony radio.
 *
 * @kit TelephonyKit
 * @syscap SystemCapability.Telephony.CoreService
 * @library libtelephony_radio.so
 * @since 13
 */

#ifdef __cplusplus
extern "C" {
#endif

#define TELEPHONY_MAX_OPERATOR_LEN 64
#define TELEPHONY_MAX_PLMN_NUMERIC_LEN 6

/**
 * @brief Result code.
 *
 * @since 13
 */
typedef enum Telephony_RadioResult {
    /* @error success */
    TEL_RADIO_SUCCESS = 0,
    /* @error permission denied */
    TEL_RADIO_PERMISSION_DENIED = 201,
    /* @error invalid parameter */
    TEL_RADIO_ERR_INVALID_PARAM = 401,
    /* @error marshalling failed, this is a low probability error, try again later when get this error */
    TEL_RADIO_ERR_MARSHALLING_FAILED = 8300001,
    /* @error unable to connect to telephony service, try again later when get this error */
    TEL_RADIO_ERR_SERVICE_CONNECTION_FAILED = 8300002,
    /* @error operation failed in telephony service, try again later when get this error */
    TEL_RADIO_ERR_OPERATION_FAILED = 8300003,
} Telephony_RadioResult;

/**
 * @brief network registration status.
 *
 * @since 13
 */
typedef enum Telephony_RegState {
    /* can not use any services */
    TEL_REG_STATE_NO_SERVICE = 0,
    /* can use services properly */
    TEL_REG_STATE_IN_SERVICE = 1,
    /* can use emergency call only */
    TEL_REG_STATE_EMERGENCY_CALL_ONLY = 2,
    /* radio power off */
    TEL_REG_STATE_POWER_OFF = 3,
} Telephony_RegState;

/**
 * @brief radio access technologies.
 *
 * @since 13
 */
typedef enum Telephony_RadioTechnology {
    /* Unknown radio technology */
    TEL_RADIO_TECHNOLOGY_UNKNOWN = 0,
    /* Global System for Mobile Communication (GSM) */
    TEL_RADIO_TECHNOLOGY_GSM = 1,
    /* Single-Carrier Radio Transmission Technology (1XRTT) */
    TEL_RADIO_TECHNOLOGY_1XRTT = 2,
    /* Wideband Code Division Multiple Access (WCDMA) */
    TEL_RADIO_TECHNOLOGY_WCDMA = 3,
    /* High Speed Packet Access (HSPA) */
    TEL_RADIO_TECHNOLOGY_HSPA = 4,
    /* Evolved High Speed Packet Access (HSPA+) */
    TEL_RADIO_TECHNOLOGY_HSPAP = 5,
    /* Time Division-Synchronous Code Division Multiple Access(TD-SCDMA) */
    TEL_RADIO_TECHNOLOGY_TD_SCDMA = 6,
    /* Evolution-Data Optimized (EVDO) */
    TEL_RADIO_TECHNOLOGY_EVDO = 7,
    /* Evolved High Rate Package Data (EHRPD) */
    TEL_RADIO_TECHNOLOGY_EHRPD = 8,
    /* Long Term Evolution (LTE) */
    TEL_RADIO_TECHNOLOGY_LTE = 9,
    /* Long Term Evolution_Carrier Aggregation (LTE_CA) */
    TEL_RADIO_TECHNOLOGY_LTE_CA = 10,
    /* Industrial Wireless LAN (IWLAN) */
    TEL_RADIO_TECHNOLOGY_IWLAN = 11,
    /* New Radio (NR) */
    TEL_RADIO_TECHNOLOGY_NR = 12,
} Telephony_RadioTechnology;

/**
 * @brief NSA network state.
 *
 * @since 13
 */
typedef enum Telephony_NsaState {
    /* The device is in idle or connected state in an LTE cell that does not support NSA */
    TEL_NSA_STATE_NOT_SUPPORTED = 1,
    /* The device is in the idle state in an LTE cell that supports NSA but not NR coverage detection */
    TEL_NSA_STATE_NO_DETECTED = 2,
    /* The device is connected to the LTE network in an LTE cell that supports NSA and NR coverage detection */
    TEL_NSA_STATE_CONNECTED_DETECTED = 3,
    /* The device is in the idle state in an LTE cell that supports NSA and NR coverage detection */
    TEL_NSA_STATE_IDLE_DETECTED = 4,
    /* The device is connected to the LTE/NR network in an LTE cell that supports NSA */
    TEL_NSA_STATE_DUAL_CONNECTED = 5,
    /* The device is idle or connected to the NG-RAN cell when being attached to the 5G Core */
    TEL_NSA_STATE_SA_ATTACHED = 6,
} Telephony_NsaState;

/**
 * @brief Network status.
 *
 * @since 13
 */
typedef struct Telephony_NetworkState {
    /* Long carrier name of the registered network */
    char longOperatorName_[TELEPHONY_MAX_OPERATOR_LEN];
    /* Short carrier name of the registered network */
    char shortOperatorName_[TELEPHONY_MAX_OPERATOR_LEN];
    /* PLMN code of the registered network */
    char plmnNumeric_[TELEPHONY_MAX_PLMN_NUMERIC_LEN];
    /* Whether in roaming */
    bool isRoaming_;
    /* Network registration status */
    Telephony_RegState regState_;
    /* Radio technology. */
    Telephony_RadioTechnology cfgTech_;
    /* NSA state */
    Telephony_NsaState nsaState_;
    /* Whether Carrier Aggregation(CA) is active */
    bool isCaActive_;
    /* Whether in emergency call only */
    bool isEmergency_;
} Telephony_NetworkState;

#ifdef __cplusplus
}
#endif

#endif // NATIVE_TELEPHONY_RADIO_TYPE_H
