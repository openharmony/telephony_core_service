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

#ifndef OHOS_TEL_RIL_DATA_PARCEL_H
#define OHOS_TEL_RIL_DATA_PARCEL_H

#include "tel_ril_base_parcel.h"
#include "tel_ril_enum.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Defines the data service activation result.
 */
struct SetupDataCallResultInfo {
    /** Activation result ID. */
    int32_t flag = 0;

    /** Data call fail reason, success is 0. */
    int32_t reason = 0;

    /** If errorCode != 0, suggested retry time. */
    int32_t retryTime = 0;

    /**
     * From 3GPP TS 27.007 V17.3.0 (2021-09), specifies a particular PDP
     * context definition. The parameter is local to the TE-MT interface and is
     * used in other PDP context-related commands.
     */
    int32_t cid = 0;

    /**
     * From 3GPP TS 27.007 V17.3.0 (2021-09), indicates the state of PDP
     * context activation.
     * 0: deactivated
     * 1: activated
     */
    int32_t active = 0;

    /**
     * PDP_type values from 3GPP TS 27.007 V17.3.0 (2021-09)
     * Specifies the type of packet data protocol. The default value is
     * manufacturer specific.
     */
    std::string type = "";

    /** Network interface name. */
    std::string netPortName = "";

    /**
     * From 3GPP TS 27.007 V17.3.0 (2021-09)
     * <local_addr and subnet_mask>: string type;
     * shows the IP address and subnet mask of the MT. The string is given as
     * dot-separated numeric (0-255) parameters on the form:
     * 1. "a1.a2.a3.a4.m1.m2.m3.m4" for IPv4 or
     * 2. "a1.a2.a3.a4.a5.a6.a7.a8.a9.a10.a11.a12.a13.a14.a15.a16.
     *    m1.m2.m3.m4.m5.m6.m7.m8.m9.m10.m11.m12.m13.m14.m15.m16" for IPv6.
     * When +CGPIAF is supported, its settings can influence the format of this
     * parameter returned with the execute form of +CGCONTRDP
     */
    std::string address = "";

    /**
     * If the MT indicates more than two IP addresses of P-CSCF servers string
     * type; shows the IP address of the secondary DNS server.When +CGPIAF is
     * supported, its settings can influence the format of this parameter
     * returned with the execute form of +CGCONTRDP.
     */
    std::string dns = "";

    /**
     * From 3GPP TS 27.007 10.1.23 V4.3.0 (2001-12)
     * string type; shows the IP address of the secondary DNS server.When
     * +CGPIAF is supported, its settings can influence the format of this
     * parameter returned with the execute form of +CGCONTRDP.
     */
    std::string dnsSec = "";

    /** Network gateway address. */
    std::string gateway = "";

    /**
     * Maximum Transfer Unit. The range of permitted values (minimum value = 1
     * or if the initial PDP context is supported minimum value = 0) is
     * returned by the test form of the command.
     */
    int32_t maxTransferUnit = 0;

    /**
     * From 3GPP TS 27.007 10.1.23 V4.3.0 (2001-12)
     * string type; shows the IP address of the primary P-CSCF server.When
     * +CGPIAF is supported, its settings can influence the format of this
     * parameter returned with the execute form of +CGCONTRDP.
     */
    std::string pCscfPrimAddr = "";

    /**
     * From 3GPP TS 27.007 10.1.23 V4.3.0 (2001-12)
     * string type; shows the IP address of the secondary P-CSCF server. When
     * +CGPIAF is supported, its settings can influence the format of this
     * parameter returned with the execute form of +CGCONTRDP.
     */
    std::string pCscfSecAddr = "";

    /**
     * From 3GPP TS 27.007 10.1.23 V4.3.0 (2001-12)
     * integer type; identifies the PDU session, see 3GPP TS 24.501 [161].
     */
    int32_t pduSessionId = 0;

    /** retry scene,
     * 0 - setup datacall fail, 1 - modem deactivate, 2 - others
     */
    int32_t retryScene = 2;
};

/**
 * @brief Defines the list of data service activation results.
 */
struct DataCallResultList {
    /** Size of DataCall List */
    size_t size = 0;

    /** DataCall List. */
    std::vector<SetupDataCallResultInfo> dcList {};
};

/**
 * @brief Defines PDP context information in 3GPP TS 27.007 10.1 V4.3.0
 * (2001-12)
 */
struct DataProfileDataInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** Id of data profiles. */
    int32_t profileId = 0;

    /** Access Point Name. */
    std::string apn = "";

    /**
     * (Packet Data Protocol type) a string parameter which specifies the type
     * of packet data protocol.
     */
    std::string protocol = "";

    /** Roaming protocol version. */
    std::string roamingProtocol = "";

    /** APN verification type. */
    int32_t verType = 0;

    /** Indicates the username of pdp profile. */
    std::string userName = "";

    /** Indicates the password of pdp profile. */
    std::string password = "";
};

/**
 * @brief Defines the PDP context list.
 */
struct DataProfilesInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** Number of PDP contexts. */
    int32_t profilesSize = 0;

    /** PDP context list. */
    std::vector<DataProfileDataInfo> profiles {};

    /** Roaming or not. */
    bool isRoaming = false;
};

/**
 * @brief Defines the data service information.
 */
struct DataCallInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /** Voice radio technology. */
    int32_t radioTechnology = 0;

    /** PDP context information. */
    DataProfileDataInfo dataProfileInfo;

    /**
     * Whether the PDP context is set for the modem. The value true indicates
     * that PDP context is set for the modem, and the value false indicates the
     * opposite.
     */
    bool modemCognitive = false;

    /**
     * Whether roaming is allowed. The value true indicates that roaming is
     * allowed, and the value false indicates the opposite.
     */
    bool roamingAllowed = false;

    /**
     * Whether the user is roaming. The value true indicates that the user is
     * roaming, and the value false indicates the opposite.
     */
    bool isRoaming = false;
};

/**
 * @brief Defines the network bandwidth information.
 */
struct DataLinkBandwidthInfo {
    /** Request serial number. */
    int32_t serial = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * integer type; specifies a particular QoS flow definition, Traffic Flows
     * definition and a PDP Context definition (see the +CGDCONT and +CGDSCONT
     * commands).
     */
    int32_t cid = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * 0, 5：QI is selected by network
     * [1 - 4]: value range for guaranteed bit rate QoS flows
     * 65, 66, 67: values for guaranteed bit rate QoS flows
     * [71 - 76]: value range for guaranteed bit rate QoS flows
     * [5 - 9]: value range for non-guaranteed bit rate QoS flows
     * 69, 70, 79, 80: values for non-guaranteed bit rate QoS flows
     * [82 - 85]: value range for delay critical guaranteed bit rate QoS flows
     * [128 - 254]: value range for Operator-specific 5QIs
     */
    int32_t qi = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * integer type; indicates DL GFBR in case of GBR 5QI. The value is in
     * kbit/s. This parameter is omitted for a non-GBR 5QI (see 3GPP TS 24.501
     * [161]).
     */
    int32_t dlGfbr = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * integer type; indicates UL GFBR in case of GBR 5QI. The value is in
     * kbit/s. This parameter is omitted for a non-GBR 5QI (see 3GPP TS 24.501
     * [161]).
     */
    int32_t ulGfbr = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * integer type; indicates DL MFBR in case of GBR 5QI. The value is in
     * kbit/s. This parameter is omitted for a non-GBR 5QI (see 3GPP TS 24.501
     * [161]).
     */
    int32_t dlMfbr = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * integer type; indicates UL MFBR in case of GBR 5QI. The value is in
     * kbit/s. This parameter is omitted for a non-GBR 5QI (see 3GPP TS 24.501
     * [161]).
     */
    int32_t ulMfbr = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * integer type; indicates the UL session AMBR(see 3GPP TS 24.501 [161]).
     * The value is in kbit/s.
     */
    int32_t ulSambr = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * integer type; indicates the DL session AMBR(see 3GPP TS 24.501 [161]).
     * The value is in kbit/s.
     */
    int32_t dlSambr = 0;

    /**
     * From 3GPP TS 27.007 10.1.50 V4.3.0 (2021-10)
     * integer type; indicates the averaging window(see 3GPP TS 24.501 [161]).
     * The value is in milliseconds.
     */
    int32_t averagingWindow = 0;
};

/**
 * @brief Defines the network bandwidth reporting rule.
 */
struct DataLinkBandwidthReportingRule {
    /** Request serial number. */
    int32_t serial = 0;

    /** Radio access technology. */
    int32_t rat = 0;

    /** Delay time. */
    int32_t delayMs = 0;

    /** Uplink delay. */
    int32_t delayUplinkKbps = 0;

    /** Downlink delay. */
    int32_t delayDownlinkKbps = 0;

    /** Maximum number of uplink parameters. */
    int32_t maximumUplinkKbpsSize = 0;

    /** Maximum number of downlink parameters. */
    int32_t maximumDownlinkKbpsSize = 0;

    /** Maximum uplink parameter list. */
    std::vector<int32_t> maximumUplinkKbps {};

    /** Maximum downlink parameter list. */
    std::vector<int32_t> maximumDownlinkKbps {};
};

/**
 * @brief Defines the data service performance mode.
 */
struct DataPerformanceInfo {
    /** Data Performance Enable. eg: 1-enable, 0-disable */
    int32_t performanceEnable = 0;

    /** Whether Enforce Data Performance. eg: 1-enable, 0-disable */
    int32_t enforce = 0;
};

/**
 * @brief Defines the sleep mode for data services.
 */
struct DataSleepInfo {
    /** Sleep Mode Enable. eg: 1-enable, 0-disable */
    int32_t sleepEnable = 0;
};

/**
 * @brief Defines the data link capability.
 */
struct DataLinkCapability {
    /** Primary downlink capability in kbps. */
    int32_t primaryDownlinkKbps;

    /** Primary uplink capability in kbps. */
    int32_t primaryUplinkKbps;

    /** Secondary downlink capability in kbps. */
    int32_t secondaryDownlinkKbps;

    /** Secondary uplink capability in kbps. */
    int32_t secondaryUplinkKbps;
};

struct NetworkSliceUrspInfo {
    /** urspInfo. */
    std::vector<uint8_t> urspInfo {};
};

struct NetworkSliceAllowedNssaiInfo {
    /** allowednssaiInfo. */
    std::vector<uint8_t> allowednssaiInfo {};
};

struct NetworkSliceEhplmnInfo {
    /** ehplmnInfo. */
    std::vector<uint8_t> ehplmnInfo {};
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_DATA_PARCEL_H
