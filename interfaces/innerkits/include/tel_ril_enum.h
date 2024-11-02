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

#ifndef OHOS_TEL_RIL_ENUM_H
#define OHOS_TEL_RIL_ENUM_H
namespace OHOS {
namespace Telephony {
enum TelRilRegStatus {
    NO_REG_MT_NO_SEARCH = 0,
    REG_MT_HOME = 1,
    NO_REG_MT_SEARCHING = 2,
    REG_MT_REJECTED = 3,
    REG_MT_UNKNOWN = 4,
    REG_MT_ROAMING = 5,
    REG_MT_EMERGENCY = 6,
};

enum RegNotifyMode {
    REG_NOT_NOTIFY = 0, /* AT command: +CREG,+CGREG,+CEREG,+C5GREG,n=0,Turn off notify function */
    REG_NOTIFY_STAT_ONLY, /* AT command: +CREG,+CGREG,+CEREG,+C5GREG,n=1,notify data format type 1 */
    REG_NOTIFY_STAT_LAC_CELLID, /* AT command: +CREG,+CGREG,+CEREG,+C5GREG,n=2,notify data format type 2 */
};

enum PinPukResultType {
    UNLOCK_SUCCESS = 0,
    UNLOCK_PASSWORD_ERR = 1,
    UNLOCK_OTHER_ERR = 2,
};

enum TelRilRatType {
    NETWORK_TYPE_UNKNOWN = 0, /* indicates no cell information */
    NETWORK_TYPE_GSM,
    NETWORK_TYPE_CDMA,
    NETWORK_TYPE_WCDMA,
    NETWORK_TYPE_TDSCDMA,
    NETWORK_TYPE_LTE,
    NETWORK_TYPE_NR
}; /* Radio Access Technology  */

enum SimStatus {
    USIM_INVALID = 0,
    USIM_VALID = 1,
    USIM_CS_INVALID = 2,
    USIM_PS_INVALID = 3,
    USIM_CS_PS_INVALID = 4,
    ROM_SIM = 240,
    NO_USIM = 255,
};

enum SimLockStatus {
    SIM_CARD_UNLOCK = 0,
    SIM_CARD_LOCK = 1,
};

enum RoamStatus {
    NO_ROAM = 0,
    ROAMING = 1,
    ROAM_UNKNOWN = 2,
};

enum SrvStatus {
    NO_SRV_SERVICE = 0,
    RESTRICTED_SERVICE = 1,
    SERVICE_VALID = 2,
    REGIONAL_SERVICE = 3,
    ENERGY_SAVING_SERVICE = 4,
};

enum SrvDomain {
    NO_DOMAIN_SERVICE = 0,
    CS_SERVICE = 1,
    PS_SERVICE = 2,
    CS_PS_SERVICE = 3,
    CS_PS_SEARCHING = 4,
    CDMA_NOT_SUPPORT = 255,
};

enum SysMode {
    NO_SYSMODE_SERVICE = 0,
    GSM_MODE = 1,
    CDMA_MODE = 2,
    WCDMA_MODE = 3,
    TDSCDMA_MODE = 4,
    WIMAX_MODE = 5,
    LTE_MODE = 6,
    LTE_CA_MODE = 7,
    NR_MODE = 8,
};

enum TelRilRadioTech {
    RADIO_TECHNOLOGY_UNKNOWN = 0,
    RADIO_TECHNOLOGY_GSM = 1,
    RADIO_TECHNOLOGY_1XRTT = 2,
    RADIO_TECHNOLOGY_WCDMA = 3,
    RADIO_TECHNOLOGY_HSPA = 4,
    RADIO_TECHNOLOGY_HSPAP = 5,
    RADIO_TECHNOLOGY_TD_SCDMA = 6,
    RADIO_TECHNOLOGY_EVDO = 7,
    RADIO_TECHNOLOGY_EHRPD = 8,
    RADIO_TECHNOLOGY_LTE = 9,
    RADIO_TECHNOLOGY_LTE_CA = 10,
    RADIO_TECHNOLOGY_IWLAN = 11,
    RADIO_TECHNOLOGY_NR = 12,
    RADIO_TECHNOLOGY_INVALID = 65535,
};

/* reference 3GPP TS 24.008 V17.4.0 (2021-09)
 * Unsuccessful PDP context activation initiated by the MS */
enum PdpErrorReason {
    PDP_ERR_NONE = 0,
    PDP_ERR_RETRY,
    PDP_ERR_UNKNOWN = 65535, /* Unknown error */
    PDP_ERR_OPERATOR_DETERMINED_BARRING = 8, /* Operator Determined Barring */
    PDP_ERR_SHORTAGE_RESOURCES = 26, /* insufficient resources */
    PDP_ERR_MISSING_OR_UNKNOWN_APN, /* missing or unknown APN */
    PDP_ERR_UNKNOWN_PDP_ADDR_OR_TYPE, /* unknown PDP address or PDP type */
    PDP_ERR_USER_VERIFICATION, /* user authentication failed */
    PDP_ERR_ACTIVATION_REJECTED_GGSN, /* activation rejected by GGSN, Serving GW or PDN GW */
    PDP_ERR_ACTIVATION_REJECTED_UNSPECIFIED, /* activation rejected, unspecified */
    PDP_ERR_SERVICE_OPTION_NOT_SUPPORTED, /* service option not supported */
    PDP_ERR_REQUESTED_SERVICE_OPTION_NOT_SUBSCRIBED, /* requested service option not subscribed
                                                           *  */
    PDP_ERR_SERVICE_OPTION_TEMPORARILY_OUT_OF_ORDER, /* service option temporarily out of order */
    PDP_ERR_NSAPI_ALREADY_USED, /* NSAPI already used */
    PDP_ERR_IPV4_ONLY_ALLOWED = 50, /* PDP type IPv4 only allowed */
    PDP_ERR_IPV6_ONLY_ALLOWED, /* PDP type IPv6 only allowed */
    PDP_ERR_IPV4V6_ONLY_ALLOWED = 57, /* PDP type IPv4v6 only allowed */
    PDP_ERR_NON_IP_ONLY_ALLOWED, /* PDP type non IP only allowed */
    PDP_ERR_MAX_NUM_OF_PDP_CONTEXTS = 65, /* maximum number of PDP contexts reached */
    PDP_ERR_APN_NOT_SUPPORTED_IN_CURRENT_RAT_PLMN, /* requested APN not supported in current RAT
                                                         * and PLMN combination */
    PDP_ERR_PROTOCOL_ERRORS = 111, /* protocol errors */
    PDP_ERR_APN_RESTRICTION_VALUE_INCOMPATIBLE = 112, /* APN restriction value incompatible
                                                            * with active PDP context */
    PDP_ERR_MULT_ACCESSES_PDN_NOT_ALLOWED = 113, /* Multiple accesses to a PDN connection not allowed */
    PDP_ERR_TO_NORMAL = 0x10010, /* convert to DisConnectionReason::REASON_NORMAL */
    PDP_ERR_TO_GSM_AND_CALLING_ONLY, /* convert to DisConnectionReason::REASON_GSM_AND_CALLING_ONLY */
    PDP_ERR_TO_CLEAR_CONNECTION, /* convert to DisConnectionReason::REASON_CLEAR_CONNECTION */
    PDP_ERR_TO_CHANGE_CONNECTION, /* convert to DisConnectionReason::REASON_CHANGE_CONNECTION */
    PDP_ERR_TO_PERMANENT_REJECT, /* convert to DisConnectionReason::REASON_PERMANENT_REJECT */
};

enum NotificationFilter {
    NOTIFICATION_FILTER_ALL = -1,
    NOTIFICATION_FILTER_NONE = 0,
    NOTIFICATION_FILTER_SIGNAL_STRENGTH = 1,
    NOTIFICATION_FILTER_NETWORK_STATE = 2,
    NOTIFICATION_FILTER_DATA_CALL = 4,
    NOTIFICATION_FILTER_LINK_CAPACITY = 8,
    NOTIFICATION_FILTER_PHYSICAL_CHANNEL_CONFIG = 16
};

enum DeviceStateType {
    TEL_POWER_SAVE_MODE,
    TEL_CHARGING_STATE,
    TEL_LOW_DATA_STATE
};

enum CellConnectionStatus {
    SERVING_CELL_UNKNOWN,
    SERVING_CELL_PRIMARY,
    SERVING_CELL_SECONDARY
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_ENUM_H
