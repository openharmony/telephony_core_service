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

#ifndef DATA_STORAGE_PDP_PROFILE_DATA_H
#define DATA_STORAGE_PDP_PROFILE_DATA_H

namespace OHOS {
namespace Telephony {
const std::string PROFILE_ID = "profile_id";
const std::string PROFILE_NAME = "profile_name";
const std::string MCC = "mcc";
const std::string MNC = "mnc";
const std::string APN = "apn";
const std::string AUTH_TYPE = "auth_type";
const std::string AUTH_USER = "auth_user";
const std::string AUTH_PWD = "auth_pwd";
const std::string APN_TYPES = "apn_types";
const std::string IS_ROAMING_APN = "is_roaming_apn";
const std::string PROFILE_ENABLE = "profile_enable";
const std::string HOME_URL = "home_url";
const std::string PROXY_IP_ADDRESS = "proxy_ip_address";
const std::string MMS_IP_ADDRESS = "mms_ip_address";
const std::string APN_PROTOCOL = "apn_protocol";
const std::string APN_ROAM_PROTOCOL = "apn_roam_protocol";
const std::string BEARING_SYSTEM_TYPE = "bearing_system_type";

struct PdpProfileInfo {
    int profileId;
    std::string profileName;
    std::string mcc;
    std::string mnc;
    std::string apn;
    int authType;
    std::string authUser;
    std::string authPwd;
    std::string apnTypes; // see ApnType
    int isRoamingApn;
    std::string homeUrl;
    std::string proxyIpAddress;
    std::string mmsIpAddress;
    std::string pdpProtocol; // see PdpProtocol
    std::string roamPdpProtocol;
    int bearingSystemType; // see BearingSystemType
};

enum ApnType { DEFAULT, IMS, MMS, ALL };

enum ApnAuthType { None = 0, PAP, CHAP, PAP_OR_CHAP };

enum PdpProtocol { IPV4 = 0, IPV6, IPV4V6 };

enum BearingSystemType {
    UNKNOWN = 0,
    LTE,
    HSPAP,
    HSPA,
    HSUPA,
    HSDPA,
    UMTS,
    EDGE,
    GPRS,
    eHRPD,
    EVDO_B,
    EVDO_A,
    EVDO_0,
    xRTT,
    IS95B,
    IS95AS
};

const std::string uri = "dataability://telephony.pdpprofile";
} // namespace Telephony
} // namespace OHOS
#endif // DATA_STORAGE_PDP_PROFILE_DATA_H
