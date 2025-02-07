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

#ifndef OHOS_TEL_RIL_CALL_PARCEL_H
#define OHOS_TEL_RIL_CALL_PARCEL_H

#include "tel_ril_base_parcel.h"
#include "tel_ril_enum.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Defines the dial information in 3GPP TS 27.007 V4.3.0 (2001-12) 7.7,
 * AT + ATD
 */
struct DialInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /**
     * Type of address octet in integer format (refer TS 24.008 [8]
     * subclauses 10.5.4.7); default 145 when dialling string includes
     * international access code character "+", otherwise 129.
     */
    std::string address = "";

    /**
     * Calling Line Identification Restriction. From TS 27.007 V3.4.0
     * (2000-03).
     */
    int32_t clir = 0;
};

/**
 * @brief Defines the call status information in 3GPP TS 27.007 V4.3.0
 * (2001-12) AT+CGDCONT.
 */
struct CallInfo {
    /**
     * Call identification number as described in 3GPP TS 22.030 [19]
     * sub-clause 6.5.5.1. This number can be used in +CHLD command operations.
     */
    int32_t index = 0;

    /** Call direction. The value 0 indicates the calling party, and the value
     * 1 indicates the called party. */
    int32_t dir = 0;

    /**
     * Indicates the call state:
     * 0: activated state
     * 1: call hold state
     * 2: calling party, dialing state
     * 3: calling party, ringback tone state
     * 4: called party, incoming call state
     * 5: called party, call waiting state
     * 6: disconnected state
     * 7: disconnecting state
     * 8: idle state
     */
    int32_t state = 0;

    /**
     * Indicates the call mode:
     * 0: voice call
     * 1: data call
     * 2: fax
     */
    int32_t mode = 0;

    /**
     * Indicates the Multi-party call status:
     * 0: not a multi-party(conference) call
     * 1: a multi-party(conference) call
     */
    int32_t mpty = 0;

    /**
     * Indicates the call domain of the voice call:
     * 0: CS domain
     * 1: IP multimedia system (IMS) domain
     */
    int32_t voiceDomain = 0;

    /**
     * Indicates the call type:
     * 0: Voice call
     * 1: Video call: send one-way video, two-way voice
     * 2: Video call: one-way receiving video, two-way voice
     * 3: Video call: two-way video, two-way voice
     */
    int32_t callType = 0;

    /** phone number in format specified by <type> */
    std::string number = "";

    /**
     * Type of address octet in integer format (refer TS 24.008 [8]
     * subclauses 10.5.4.7); default 145 when dialling string includes
     * international access code character "+", otherwise 129. See 3GPP
     * TS 27.007 V4.3.0 (2001-12) 6.1.
     */
    int32_t type = 0;

    /**
     * Alphanumeric representation of <number> corresponding to the entry found
     * in phonebook; used character set should be the one selected with command
     * select TE character set +CSCS.
     */
    std::string alpha = "";

    /**
     * Indicates remote party name.
     */
    std::string name = "";
 
    /**
     * Identifies the CNAP display name;
     * - 0：Allowed
     * - 1：Restricted
     * - 2：Not Specified/Unknown
     * - 3：Payphone
     */
    int32_t namePresentation = 0;
};

/**
 * @brief Defines the call status information list.
 */
struct CallInfoList {
    /** The size of CallInfoList. */
    int32_t callSize = 0;

    /** The ID of the call status information list. */
    int32_t flag = 0;

    /** Call status information list. */
    std::vector<CallInfo> calls {};
};

/**
 * @brief Defines the emergency information.
 */
struct EmergencyInfo {
    /** Number index. */
    int32_t index = 0;

    /** Total number of numbers. */
    int32_t total = 0;

    /** Emergency call number in string format. */
    std::string eccNum = "";

    /**
     * Emergency call type:
     * 0: Interface message of initiating an emergency call
     * 1: Bandit police
     * 2: Rescue
     * 4: Fire alarm
     * 8: Marine Police
     * 16: Alpine rescue
     */
    int32_t category = 0;

    /**
     * Whether the number is valid with or without a card:
     * 0: valid without card
     * 1: Valid with card
     */
    int32_t simpresent = 0;

    /** Mobile country code. */
    std::string mcc = "";

    /**
     * Distinguishes CS domain abnormal service status:
     * 0: all States are valid
     * 1: the CS domain is not in normal service
     */
    int32_t abnormalService = 0;
};

/**
 * @brief Defines the emergency info list.
 */
struct EmergencyInfoList {
    /** The size of the emergency info list. */
    int32_t callSize = 0;

    /** The ID of emergency info list. */
    int32_t flag = 0;

    /** Emergency info list. */
    std::vector<EmergencyInfo> calls {};
};

/**
 * @brief Defines the call forwarding information.
 */
struct CallForwardSetInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /**
     * Call forwarding type:
     * 0: call forwarding unconditional
     * 1: call forwarding on busy
     * 2: call forwarding on no reply
     * 3: call forwarding not reachable (no network service, or power-off)
     * 4: any call forwarding
     * 5: any call forwarding conditional
     */
    int32_t reason = 0;

    /**
     * Call forwarding operation mode:
     * 0: deactivation
     * 1: activation
     * 2: status query
     * 3: registration
     * 4: deletion
     */
    int32_t mode = 0;

    /** Phone number. */
    std::string number = "";

    /** Service class. For details, see 3GPP TS 27.007. */
    int32_t classx = 0;
};

/**
 * @brief Defines the Unstructured Supplementary Data Service (USSD)
 * information.
 */
struct UssdNoticeInfo {
    /**
     * Integer value.
     * 0: The network does not require a TE reply (USSD-Notify initiated by the
     *    network or TE. The network does not need further information after
     *    starting operation);
     * 1: The network needs a TE reply (USSD-Request initiated by the network,
     *    or TE sent After starting the operation, the network needs further
     *    information);
     * 2: The USSD session is released by the network;
     * 3: Other local clients have responded;
     * 4: The operation is not supported;
     * 5: The network timed out.
     */
    int32_t m = 0;
    /** USSD string, the maximum length is 160 characters. */
    std::string str = "";
};

/**
 * @brief Defines the supplementary service information.
 */
struct SsNoticeInfo {
    /**
     * Service type:
     * 0: call forwarding unconditional
     * 1: call forwarding on busy
     * 2: call forwarding on no reply
     * 3: call forwarding not reachable (no network service, or power-off)
     */
    int32_t serviceType = 0;

    /**
     * Request type:
     * 0: deactivation
     * 1: activated
     * 2: status query
     * 3: registration
     * 4: deletion
     */
    int32_t requestType = 0;

    /** Service class. For details, see 3GPP TS 27.007. */
    int32_t serviceClass = 0;

    /** Query result. For details, see {@link RilErrType}. */
    int32_t result = 0;
};

/**
 * @brief Active reporting of SRVCC status is controlled by the +CIREP command.
 *
 * This command complies with the 3GPP TS 27.007 protocol.
 */
struct SrvccStatus {
    /**
     * SRVCC status.
     * 1: SRVCC starts;
     * 2: SRVCC is successful;
     * 3: SRVCC is cancelled;
     * 4: SRVCC failed.
     */
    int32_t status = 1;
};

/**
 * @brief ringback voice event reported by the modem during dialing.
 *
 * Modem private commands, not a reported field specified by the 3gpp
 * protocol.
 */
struct RingbackVoice {
    /** 0 network alerting; 1 local alerting */
    int32_t status = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_CALL_PARCEL_H
