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

#ifndef OHOS_TEL_RIL_SMS_PARCEL_H
#define OHOS_TEL_RIL_SMS_PARCEL_H

#include "tel_ril_base_parcel.h"
#include "tel_ril_enum.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Defines a GSM SMS message.
 */
struct GsmSmsMessageInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** Short Message Service Center Protocol Data Unit see GSM 03.40 */
    std::string smscPdu = "";

    /** Protocol Data Unit */
    std::string pdu = "";

    /** GSM SMS Status. */
    int32_t state = 0;
};

/**
 * @brief Defines a CDMA SMS message.
 */
struct SendCdmaSmsMessageInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** Short Message Service Center Protocol Data Unit see GSM 03.40 */
    std::string smscPdu = "";

    /** CDMA SMS Status. */
    int32_t state = 0;
};

/**
 * @brief Defines the SMS message information in a SIM card.
 */
struct SmsMessageIOInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** Short Message Service Center Protocol Data Unit see GSM 03.40. */
    std::string smscPdu = "";

    /** Protocol Data Unit */
    std::string pdu = "";

    /** The status of SMS message information in a SIM card. */
    int32_t state = 0;

    /** Message index. */
    int32_t index = 0;
};

/**
 * @brief Defines the SMSC address information.
 */
struct ServiceCenterAddress {
    /** Request serial number. */
    int32_t serial = 0;

    /** SMSC address type. For details, see 3GPP TS 24.011 [6]. */
    int32_t tosca = 0;

    /** Protocol Data Unit */
    std::string address = "";
};

/**
 * @brief Defines the GSM cell broadcast configuration information in 3GPP
 * TS 27.005  AT+CSCB = [<mode>[,<mids>[,<dcss>]]].
 */
struct CBConfigInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** Mode (activated or not). */
    int32_t mode = 0;

    /**
     * Response type:
     * 0: query and report
     * 1: report
     */
    int32_t indicationType = 0;

    /** Message IDs. */
    std::string mids = "";

    /** Data coding schemes. */
    std::string dcss = "";
};

/**
 * @brief Defines the CDMA cell broadcast configuration information.
 */
struct CdmaCBConfigInfo {
    /** Service. */
    int32_t service = 0;

    /** Language. */
    int32_t language = 0;

    /** Selected or not. */
    int32_t checked = 0;
};

/**
 * @brief Defines the CDMA cell broadcast configuration information list.
 */
struct CdmaCBConfigInfoList {
    /** Request serial number. */
    int32_t serial = 0;

    /** The size of CB config information list. */
    int32_t size = 0;

    /** CB config information list. */
    std::vector<CdmaCBConfigInfo> list {};
};

/**
 * @brief Defines the cell broadcast report information.
 *
 * From 3GPP TS 27.005   if text mode (+CMGF=1):
 *  <CR><LF>+CBM:
 *  <sn>,<mid>,<dcs>,<page>,<pages><CR><LF><data><CR>
 *  <LF> if PDU mode
 *  (+CMGF=0):
 *  <CR><LF>+CBM: <length><CR><LF><pdu><CR><LF>
 */
struct CBConfigReportInfo {
    /**
     * Response type:
     * 0: query and report
     * 1: report
     */
    int32_t indicationType = 0;

    /** Cell broadcast SN */
    int32_t sn = 0;

    /** Message IDs */
    int32_t mid = 0;

    /** Cell broadcast page number. */
    int32_t page = 0;

    /** Total number of cell broadcast pages. */
    int32_t pages = 0;

    /** Data coding schemes. */
    std::string dcs = "";

    /** Decoded cell broadcast content. */
    std::string data = "";

    /** Number of PDU bytes. */
    int32_t length = 0;

    /** Protocol data unit. */
    std::string pdu = "";
};

/**
 * @brief Defines the SMS message information.
 */
struct SmsMessageInfo {
    /**
     * Response type:
     * 0: query and report
     * 1: report
     */
    int32_t indicationType = 0;

    /** Total number. */
    int32_t size = 0;

    /** Protocol data unit. */
    std::vector<uint8_t> pdu {};
};

/**
 * @brief Defines the processing mode of received SMS messages.
 */
struct ModeData {
    /** Request serial number. */
    int32_t serial = 0;

    /** Whether to receive SMS messages */
    bool result = false;

    /**
     * Processing mode of received SMS messages. For details, see {@link
     * AckIncomeCause}.
     */
    int32_t mode = 0;

    /** Protocol Data Unit. */
    std::string pdu = "";
};

/**
 * @brief Defines an SMS message response.
 */
struct SendSmsResultInfo {
    /**
     * TP-Message-Reference for GSM, and BearerData MessageId for CDMA
     * from 3GPP2 C.S0015-B, v2.0, 4.5-1
     */
    int32_t msgRef = 0;

    /** Protocol Data Unit */
    std::string pdu = "";

    /** Error code */
    int32_t errCode = 0;

    /** SMS message response ID */
    int64_t flag = 0;
};

struct CdmaSmsAddress {
    int32_t digitMode = 0;
    int32_t mode = 0;
    int32_t type = 0;
    int32_t plan = 0;
    unsigned char number = 0;
    unsigned char bytes[36] = { 0 };
};

struct CdmaSmsSubAddress {
    int32_t type = 0;
    unsigned char odd = 0;
    unsigned char number = 0;
    unsigned char bytes[36] = { 0 };
};

struct CdmaSmsMessageInfo {
    int32_t serial = 0;
    int32_t serviceId = 0;
    unsigned char isExist = 0;
    int32_t type = 0;
    CdmaSmsAddress address;
    CdmaSmsSubAddress subAddress;
    int32_t size = 0;
    unsigned char bytes[255] = { 0 };
};

struct CdmaSmsInfo {
    /**
     * Response type:
     * 0: query and report
     * 1: report
     */
    int32_t indicationType = 0;

    /**
     * TP-Message-Reference for GSM, and BearerData MessageId for CDMA
     * from 3GPP2 C.S0015-B, v2.0, 4.5-1
     */
    int32_t msgRef = 0;

    /** Protocol Data Unit. */
    std::string pdu = "";

    /**
     * If unknown or not applicable, that is -1 from 3GPP 27.005, 3.2.5 for
     * GSM/UMTS, 3GPP2 N.S0005 (IS-41C) Table 171 for CDMA
     */
    int32_t errCode = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_SMS_PARCEL_H
