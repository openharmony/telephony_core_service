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

#ifndef OHOS_TEL_RIL_SIM_PARCEL_H
#define OHOS_TEL_RIL_SIM_PARCEL_H

#include "tel_ril_base_parcel.h"
#include "tel_ril_enum.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Defines the SIM card status information.
 */
struct CardStatusInfo {
    /** SIM card index. */
    int32_t index = 0;

    /**
     * SIM card type:
     * 0: unknown.
     * 1: common SIM card.
     * 2: USIM, supporting 4G.
     */
    int32_t simType = 0;

    /**
     * SIM card status:
     * 1: unknown
     * 0: SIM card not inserted
     * 1: SIM card detected normally
     * 2: PIN required
     * 3: PUK required
     * 4: PIN2 required
     * 5: PUK2 required
     */
    int32_t simState = 0;
};

/**
 * @brief Defines the SIM data request information in 3GPP TS 27.007 V4.3.0
 * (2001-12) 8.18, + CRSM.
 */
struct SimIoRequestInfo {
    /** Command passed on by the ME to the SIM; refer GSM 51.011 [28] */
    int32_t command = 0;

    /**
     * This is the identifier of an elementary datafile on SIM.
     * Mandatory for every command except STATUS
     */
    int32_t fileId = 0;

    /**
     * Parameters passed on by the MT to the SIM.
     * These parameters are mandatory for every command,
     * except GET RESPONSE and STATUS.
     * The values are described in 3GPP TS 51.011 [28]
     */
    int32_t p1 = 0;
    int32_t p2 = 0;
    int32_t p3 = 0;

    /**
     * Information which shall be written to the SIM(hexadecimal character
     * format; refer +CSCS).
     */
    std::string data = "";

    /**
     * Contains the path of an elementary file on the SIM/UICC in hexadecimal
     * format as defined in ETSI TS 102 221 [60] (e.g. "7F205F70" in SIM and
     * UICC case). The <pathid> shall only be used in the mode "select by path
     * from MF" as defined in  ETSI TS 102 221 [60].
     */
    std::string path = "";

    /** Request serial number. */
    int32_t serial = 0;

    /** PIN2 */
    std::string pin2 = "";

    /** App ID. */
    std::string aid = "";
};

/**
 * @brief Defines the response to the SIM data request in 3GPP TS 27.007 V4.3.0
 * (2001-12) 8.18, + CRSM.
 */
struct IccIoResultInfo {
    /**
     * Information from the SIM about the execution of the actual command.
     * These parameters are delivered to the TE in both cases, on successful or
     * failed execution of the command
     */
    int32_t sw1 = 0;
    int32_t sw2 = 0;

    /** Response information */
    std::string response = "";
};

/**
 * @brief Defines the SIM card lock information.
 */
struct SimLockInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /**
     * String type, which specifies the object operated by this command.
     * "SC": SIM PIN1;
     * "AO": prohibit all outgoing calls;
     * "OI": All international outgoing calls are prohibited;
     * "OX": All international outgoing calls are prohibited, except for the country of origin;
     * "AI": All incoming calls are prohibited;
     * "IR": When roaming outside the home area, all incoming calls are prohibited;
     * "AB": prohibit all services (applicable only when <mode>=0);
     * "AG": Outgoing call is prohibited (applicable only when <mode>=0);
     * "AC": Incoming calls are prohibited (applicable only when <mode>=0);
     * "FD": FDN;
     * "PN": lock the network;
     * "PU": lock subnet;
     * "PP": Lock SP.
     */
    std::string fac = "";

    /**
     * Mode:
     * 0: deactivation (When fac is set to PN, PU, or PP, the operation is equivalent to unlocking.)
     * 1: activation (When fac is set to PN, PU, or PP, activation is not supported.)
     * 2: query
     */
    int32_t mode = 0;

    /**
     * SIM card lock status.
     * It indicates the activation status of the first three layers of locks when fac is set to PN, PU, or PP.
     * 0: not activated
     * 1: activated
     */
    int32_t status = 0;

    /** Password text */
    std::string passwd = "";

    /**
     * Service type. The value is the sum of integers that represent the service type. The default value is 255.
     * 1: telephony service
     * 2: data service
     * 4: fax service
     * 8: SMS service
     * 16: data circuit sync
     * 32: data circuit async
     * 64: dedicated packet access
     * 128: dedicated portable device (PAD) access
     */
    int32_t classx = 0;
};

/**
 * @brief Defines the SIM card password information.
 */
struct SimPasswordInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /**
     * String type, which specifies the object operated by this command.
     * “SC”：SIM PIN1；
     * “P2”：SIM PIN2；
     * "OI": All international outgoing calls are prohibited;
     * "OX": All international outgoing calls are prohibited, except for the country of origin;
     * "AI": All incoming calls are prohibited;
     * "IR": When roaming outside the home area, all incoming calls are prohibited;
     * "AB": prohibit all services (applicable only when <mode>=0);
     * "AG": Outgoing call is prohibited (applicable only when <mode>=0);
     * "AC": Incoming call service is prohibited (applicable only when <mode>=0).
     */
    std::string fac = "";

    /** Old password text */
    std::string oldPassword = "";

    /** New password text */
    std::string newPassword = "";

    /** Max length of oldPassword or newPassword */
    int32_t passwordLength = 0;
};

/**
 * @brief Defines the maximum number of SIM password attempts.
 */
struct SimPinInputTimes {
    /** Request serial number. */
    int32_t serial = 0;

    /**
     * Param of string.
     * SIM PIN2 is mean that SIM PIN2 request. SIM PUK2 is mean that SIM PUK2
     * request.
     */
    std::string code = "";

    /**
     * The remaining number of entries, for PIN2, the maximum number of entries is 3 times;
     * for PUK2, the maximum number of entries is 10 times.
     */
    int32_t times = 0;

    /**
     * The remaining number of PUK, the maximum number of entries is 10 times.
     */
    int32_t pukTimes = 0;

    /**
     * The remaining number of PIN, the maximum number of entries is 3 times.
     */
    int32_t pinTimes = 0;

    /**
     * The remaining number of PUK2, the maximum number of entries is 10
     * times.
     */
    int32_t puk2Times = 0;

    /**
     * The remaining number of PIN2, the maximum number of entries is 3 times.
     */
    int32_t pin2Times = 0;
};

/**
 * @brief Defines the APDU data transmission request information.
 */
struct ApduSimIORequestInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** Channel ID */
    int32_t channelId = 0;

    /** APDU instruction type. For details, see ETSI 102 221 [55]. */
    int32_t type = 0;

    /** APDU instruction. For details, see ETSI 102 221 [55]. */
    int32_t instruction = 0;

    /**
     * Command parameter 1 of the SIM data request. For details, see 3GPP
     * TS 51.011[28].
     */
    int32_t p1 = 0;

    /**
     * Command parameter 2 of the SIM data request. For details, see 3GPP
     * TS 51.011[28].
     */
    int32_t p2 = 0;

    /**
     * Command parameter 3 of the SIM data request. For details, see 3GPP
     * TS 51.011[28]. If p3 is a negative value, a 4-byte APDU is sent to the
     * SIM card.
     */
    int32_t p3 = 0;

    /** Data to be transmitted */
    std::string data = "";
};

/**
 * @brief Defines the SIM card authentication request information.
 */
struct SimAuthenticationRequestInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** App ID */
    std::string aid = "";

    /** Authentication data */
    std::string authData = "";
};

/**
 * @brief Defines the Send SIM matched operator info request information.
 */
struct NcfgOperatorInfo {
    /** Operator Name Matched with SIM card */
    std::string operName = "";

    /** Operator Key Matched with SIM card */
    std::string operKey = "";

    /** Current SIM State */
    int32_t state = 0;

    /** Reserved Field */
    std::string reserve = "";
};

/**
 * @brief Defines the response to the request for enabling the logical channel of the APDU.
 */
struct OpenLogicalChannelResponse {
    /**
     * Information from the SIM about the execution of the actual command.
     * These parameters are delivered to the TE in both cases, on successful or
     * failed execution of the command
     */
    int32_t sw1 = 0;

    /**
     * Status word 2 of the SIM card, which is returned by the SIM card after
     * command execution.
     */
    int32_t sw2 = 0;

    /** ID of the opened logical channel */
    int32_t channelId = 0;

    /** Response information */
    std::string response = "";
};

/**
 * @brief Defines the response to the request for unlocking the SIM card.
 */
struct LockStatusResp {
    /** Query result. For details, see {@link RilErrType}. */
    int32_t result = 0;

    /** Number of remaining attempts */
    int32_t remain = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_SIM_PARCEL_H
