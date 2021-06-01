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
#ifndef TELEPHONY_N_TYPE_H
#define TELEPHONY_N_TYPE_H

#include <codecvt>
#include <locale>
#include <string>
#include <vector>
#include "hril.h"

namespace OHOS {
enum class HRilErrType { NONE, HRIL_ERR_INVALID_RESPONSE };

enum class HRilResponseType {
    HRIL_RESPONSE,
    HRIL_RESP_ACK,
    HRIL_RESP_ACK_NEED,
};

enum class HRilNotiType {
    HRIL_NOTIFICATION,
    HRIL_NOTIFICATION_ACK_NEED,
};

enum class HRilApnTypes : int32_t {
    NONE = 0,
    DEFAULT = 2 ^ 0,
    MMS = 2 ^ 1,
    SUPL = 2 ^ 2,
    DUN = 2 ^ 3,
    HIPRI = 2 ^ 4,
    FOTA = 2 ^ 5,
    IMS = 2 ^ 6,
    CBS = 2 ^ 7,
    IA = 2 ^ 8,
    EMERGENCY = 2 ^ 9,
    ALL = (2 ^ 10) - 1,
};

/* From 3GPP TS 27.007 V4.3.0 (2001-12) 8.5, AT + CSQ */
struct GsmRssi {
    uint32_t rssi; /* Received Signal Strength Indication, value range 0 ~ 31, max is 99, if unknown then set to max */
    uint32_t ber; /* bit error rate, value range 0 ~ 7, max is 99, if unknown then set to max
                   * as RXQUAL values in the table in TS 45.008 [20] subclause 8.2.4. */
    int32_t ta; /* Timing Advance in bit periods. if unknown then set to max, e.g: 1 bit period = 48/13 us */
};

/* From 3GPP TS 27.007 8.69 */
struct CdmaRssi {
    uint32_t absoluteRssi; /* Absolute value of signal strength.  This value is the actual Rssi value
                            * multiplied by -1.
                            * e.g: Rssi is -75, then this response value will be 75 */
    uint32_t ecno; /* ratio of the received energy per PN chip to the total received power spectral density,
                    * e.g: If the actual Ec/Io is -12.5 dB, then this response value will be 125.
                    * from 3GPP TS 25.133[95] */
};

struct Rssi {
    int32_t slotId;
    GsmRssi gw;
    CdmaRssi cdma;
};

struct HRilRadioResponseInfo {
    int32_t serial;
    HRilResponseType type;
    HRilErrType error;
};

struct CommonInfo {
    int32_t serial;
    int32_t type;
    bool flag;
    int32_t arg1;
    int32_t arg2;
};

enum HRilCommonNumber {
    HRIL_DEC = 10,
    HRIL_INVALID_HEX_CHAR = 16,
    HRIL_UPPER_CASE_LETTERS_OFFSET = 32,
    HRIL_SIGNAL_STRENGTH_MAX = 99,
    HRIL_ADAPTER_RADIO_INDICATION = 2001,
    HRIL_ADAPTER_RADIO_RESPONSE = 2002
};

enum HRilOperatorInfoResult {
    HRIL_LONE_NAME = 0,
    HRIL_SHORT_NAME,
    HRIL_NUMERIC,
};

enum HRilCircuitModeRegState {
    HRIL_STAT_NO_REG_MT_NO_SEARCHING_OP = 0, /* not registered, MT is not searching an operator */
    HRIL_STAT_REGISTERED_HOME_NETWORK = 1, /* registered, home network */
    HRIL_STAT_NO_REGISTERED_MT_TRY_ATTACH = 2, /* not registered, but MT is currently trying
                                                * to attach or searching an operator */
    HRIL_STAT_REGISTERED_DENIED = 3, /* registration denied */
    HRIL_STAT_UNKNOWN = 4, /* unknown (e.g. out of GERAN/UTRAN coverage) */
    HRIL_STAT_REGISTERED_ROAMING = 5, /* registered, roaming */
    HRIL_STAT_REGISTERED_SMS_HOME_NETWORK = 6, /* registered for "SMS only", home network (not applicable) */
    HRIL_STAT_REGISTERED_SMS_ROAMING = 7,
};

enum HRilServiceSupportStat {
    HRIL_SERVICE_NO_SUPPORT = 0,
    HRIL_SERVICE_SUPPORT = 1,
};

/* from 3GPP TS 27.007 V17.1.0 9.2.2.1.1 */
enum HRilReasonDataDenied {
    HREASON_GPRS_SERVICE_NOT_ALLOW = 0,
    HREASON_GPRS_AND_NONGPRS_SERVICE_NOT_ALLOW = 1,
    HREASON_MS_INDENTITY_CANNOT_BE_DERIVED = 2,
    HREASON_IMPLICITLY_DETACHED = 3,
    HREASON_GPRS_SERVICE_NOT_ALLOW_IN_PLMN = 4,
    HREASON_MSC_TEM_NOT_REACH = 5,
    HREASON_NO_DPD_CONTEXT_ACTIVATED = 6,
};

// cs registration response
static constexpr uint32_t HRIL_CS_REG_STATE = 0;
static constexpr uint32_t HRIL_CS_REG_RESP_RAT = 3;
static constexpr uint32_t HRIL_RSSNR = 7;
static constexpr uint32_t HRIL_CS_REG_RESP_ROMING_INDICATOR = 10;
static constexpr uint32_t HRIL_CS_REG_RESP_SYSTEM_IS_IN_PRL = 11;
static constexpr uint32_t HRIL_CS_REG_RESP_DEFAULT_ROAMING_INDICATOR = 12;
static constexpr uint32_t HRIL_CS_REG_RESP_TIMING_ADVANCE = 13;
static constexpr uint32_t HRIL_CS_REG_STATUS_MAX_LEN = 15;
// ps registration response
static constexpr uint32_t HRIL_PS_REG_STATUS_MAX_LEN = 6;
static constexpr uint32_t HRIL_PS_REG_STATE = 0;
static constexpr uint32_t HRIL_PS_RADIO_TECHNOLOGY = 3;
static constexpr uint32_t HRIL_PS_DENIED_ERROR_CODE = 4;
static constexpr uint32_t HRIL_PS_MAX_DATA_CALLS = 5;
static constexpr uint32_t HRIL_PS_DEF_DATA_CALLS_VAL = 1;
} // namespace OHOS
#endif // TELEPHONY_N_TYPE_H