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

#ifndef OHOS_TEL_RIL_TYPES_H
#define OHOS_TEL_RIL_TYPES_H

#include <locale>

namespace OHOS {
namespace Telephony {
enum class ErrType : int32_t {
    /** No error */
    NONE = 0,

    /** An error that not included in bellow items */
    ERR_GENERIC_FAILURE,

    /** Invalid parameter */
    ERR_INVALID_PARAMETER,

    /** Full memory */
    ERR_MEMORY_FULL,

    /** Send command failed */
    ERR_CMD_SEND_FAILURE,

    /** NO CARRIER response returned */
    ERR_CMD_NO_CARRIER,

    /** The response is invalid */
    ERR_INVALID_RESPONSE,

    /** The new status of radio to set is same with previous */
    ERR_REPEAT_STATUS,

    /** Network search error */
    ERR_NETWORK_SEARCHING,

    /** Network search interrupted */
    ERR_NETWORK_SEARCHING_INTERRUPTED,

    /** The AT channel is closed */
    ERR_MODEM_DEVICE_CLOSE,

    /** No sim card error */
    ERR_NO_SIMCARD_INSERTED,

    /** Need pin code */
    ERR_NEED_PIN_CODE,

    /** Need puk code */
    ERR_NEED_PUK_CODE,

    /** Network search timeout */
    ERR_NETWORK_SEARCH_TIMEOUT,

    /** Pin or puk password is not correct */
    ERR_PINPUK_PASSWORD_NOCORRECT,

    /** Invalid modem parameter */
    ERR_INVALID_MODEM_PARAMETER = 50,

    /** IPC failure */
    ERR_HDF_IPC_FAILURE = 300,

    /** Null point error */
    ERR_NULL_POINT,

    /** Vendor not implement error. */
    ERR_VENDOR_NOT_IMPLEMENT
};

/**
 * @brief Indicates the response type.
 */
enum ResponseTypes {
    RESPONSE_REQUEST,
    RESPONSE_NOTICE,
    RESPONSE_REQUEST_ACK,
    RESPONSE_REQUEST_MUST_ACK,
    RESPONSE_NOTICE_MUST_ACK,
};

/**
 * @brief From 3GPP TS 27.007 V4.3.0 (2001-12) 8.5, AT + CSQ.
 */
struct GsmRssi {
    /**
     * Received Signal Strength Indication, value range 0 ~ 31, max is 99,
     * if unknown then set to max
     */
    int32_t rxlev = 0;

    /**
     * Bit error rate, value range 0 ~ 7, max is 99, if unknown then set to
     * max as RXQUAL values in the table in TS 45.008 [20] subclauses 8.2.4.
     */
    int32_t ber = 0;
};

/**
 * @brief From 3GPP TS 27.007 V17.1.0 (2021-03) 8.69.
 */
struct CdmaRssi {
    /**
     * Absolute value of signal strength. This value is the actual Rssi value
     * multiplied by -1. e.g: Rssi is -75, then this response value will be 75.
     */
    int32_t absoluteRssi = 0;

    /**
     * integer type, ratio of the received energy per PN chip to the total
     * received power spectral density (see 3GPP TS 25.133 [95] subclauses)
     */
    int32_t ecno = 0;
};

/**
 * @brief Indicates some parameters which can reflect the strength of WCDMA signal.
 */
struct WCdmaRssi {
    /**
     * integer type, received signal strength level (see 3GPP TS 45.008 [20]
     * sub-clause 8.1.4) value 0~99.
     */
    int32_t rxlev = 0;

    /**
     * integer type, ratio of the received energy per PN chip to the total
     * received power spectral density (see 3GPP TS 25.133 [95] sub-clause).
     */
    int32_t ecio = 0;

    /**
     * integer type, received signal code power (see 3GPP TS 25.133 [95]
     * sub-clause 9.1.1.3 and 3GPP TS 25.123 [96] sub-clause 9.1.1.1.3).
     * range value 0 ~ 96, 255 not known or not detectable.
     */
    int32_t rscp = 0;

    /**
     * Bit error rate, value range 0 ~ 7, max is 99, if unknown then set to
     * max
     */
    int32_t ber = 0;
};

/**
 * @brief Indicates some parameters which can reflect the strength of LTE signal.
 */
struct LteRssi {
    /**
     * integer type, received signal strength level
     * (see 3GPP TS 45.008 [20] sub-clause 8.1.4) value 0~99.
     */
    int32_t rxlev = 0;

    /**
     * integer type, reference signal received quality (see 3GPP TS 36.133 [96] sub-clause 9.1.7)
     * value range 0~33, 255 not known or not detectable.
     */
    int32_t rsrq = 0;

    /**
     * integer type, reference signal received power (see 3GPP TS 36.133 [96] sub-clause 9.1.4)
     * value range 0~97, 255 not known or not detectable.
     */
    int32_t rsrp = 0;

    /**
     * integer type, representing the signal-to-interference plus noise ratio, suitable for LTE mode
     * value range 0~251, 255 not known or not detectable.
     */
    int32_t snr = 0;
};

/**
 * @brief Indicates some parameters which can reflect the strength of TD-SCDMA signal.
 */
struct TdScdmaRssi {
    int32_t rscp = 0;
};

/**
 * @brief Indicates some parameters which can reflect the strength of NR signal.
 */
struct NrRssi {
    int32_t rsrp = 0;
    int32_t rsrq = 0;
    int32_t sinr = 0;
};

/**
 * @brief Indicates signal level of some RATs.
 */
struct Rssi {
    GsmRssi gw;
    CdmaRssi cdma;
    WCdmaRssi wcdma;
    LteRssi lte;
    TdScdmaRssi tdScdma;
    NrRssi nr;
};

struct ResponseHeadInfo {
    int32_t slotId = 0;
    ResponseTypes type = ResponseTypes::RESPONSE_REQUEST;
};

/**
 * @brief Indicates the response information, for example whether the
 * request is success, serial number, response type etc.
 */
struct RadioResponseInfo {
    int32_t flag = -1;
    int32_t serial = -1;
    ErrType error = ErrType::NONE;
    ResponseTypes type = ResponseTypes::RESPONSE_REQUEST;
};

struct RadioStateInfo {
    int64_t flag = 0;
    int32_t state = 0;
};

enum CommonNumber {
    DEC = 10,
    INVALID_HEX_CHAR = 16,
    UPPER_CASE_LETTERS_OFFSET = 32,
    RIL_ADAPTER_RADIO_INDICATION = 2001,
    RIL_ADAPTER_RADIO_RESPONSE = 2002,
    RIL_ADAPTER_RADIO_SEND_ACK,
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_TYPES_H
