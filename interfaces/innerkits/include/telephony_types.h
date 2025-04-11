/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_TELEPHONY_TYPES_H
#define TELEPHONY_TELEPHONY_TYPES_H

#include <string>
#include <vector>

#include "network_search_types.h"
#include "operator_config_types.h"
#include "parameter.h"
#include "parameters.h"
#include "telephony_common_utils.h"

namespace OHOS {
namespace Telephony {
#define SIM_SLOT_COUNT GetMaxSlotCount<int32_t>()
#define SIM_SLOT_COUNT_REAL GetRealMaxSlotCount<int32_t>()
#define PREFERRED_NETWORK_TYPE GetPreferredNetworkType<int32_t>()
#define VSIM_MODEM_COUNT GetVSimModemCount<int32_t>()
#define IS_SUPPORT_VSIM (VSIM_MODEM_COUNT > 0)
#define DEFAULT_ESIM_ID GetDefaultEsimSlotId<int32_t>()
namespace {
const int32_t SYSPARA_SIZE = 128;
constexpr size_t ARRAY_SIZE = 1024;
const int32_t DEFAULT_SIM_SLOT_ID = 0;
const int32_t DEFAULT_OPERATOR_STATE = 0;
const int32_t DEFAULT_SIM_SLOT_ID_REMOVE = -1;
const int32_t INVALID_MAIN_CARD_SLOTID = -2;
const int32_t ERROR_SLOT_OPKEY = -2;
const int32_t DSDS_MODE_V2 = 0;
const int32_t DSDS_MODE_V3 = 1;
const size_t MAX_PARAMETER_LENGTH = 100;
const int32_t DUAL_SLOT_COUNT = 2;
const int32_t MAX_SLOT_COUNT = 3;
const int32_t VSIM_DEFAULT_VALUE = -1;
const int32_t ESIM_DEFAULT_SLOTID = -1;
const uint8_t DEC_TYPE = 10;
std::atomic<int32_t> maxRealSlotCount_ = 0;
int32_t maxSlotCount_ = 0;
int32_t esimDefaultSlotId_ = ESIM_DEFAULT_SLOTID;
int32_t vSimModemCount_ = VSIM_DEFAULT_VALUE;
constexpr const char *SATELLITE_DEFAULT_VALUE = "0";
constexpr const char *DEFAULT_SLOT_COUNT = "1";
constexpr const char *DEFAULT_ESIM_SLOT_ID = "0";
constexpr const char *TEL_SIM_SLOT_COUNT = "const.telephony.slotCount";
constexpr const char *VIRTUAL_MODEM_SWITCH = "const.booster.virtual_modem_switch";
constexpr const char *VIRTUAL_MODEM_DEFAULT_SWITCH = "false";
constexpr const char *DEFAULT_PREFERRED_NETWORK_TYPE = "5"; // CORE_NETWORK_MODE_LTE_WCDMA_GSM
constexpr const char *TEL_PREFERRED_NETWORK_TYPE = "const.telephony.preferredNetworkType";
constexpr const char *DEFAULT_OPERATOR_KEY = "";
constexpr const char *INITIAL_OPKEY = "-1";
constexpr const char *DEFAULT_OPERATOR_CONFIG = "default_operator_config.json";
constexpr const char *OPKEY_PROP_PREFIX = "telephony.sim.opkey";
constexpr const char *COUNTRY_CODE_KEY = "telephony.sim.countryCode";
constexpr const char *TEL_SATELLITE_SUPPORTED = "const.telephony.satellite.supported";
constexpr const char *DEFAULT_VSIM_MODEM_COUNT = "0";
constexpr const char *VSIM_MODEM_COUNT_STR = "const.telephony.vsimModemCount";
constexpr const char *TEL_ESIM_SUPPORT = "persist.telephony.esim.supported";
constexpr const char *TEL_DEFAULT_ESIM_SLOT_ID = "const.telephony.esim.slotID";
constexpr const char *DYNAMIC_POWEROFF_MODEM = "telephony.dynamic_poweroff_modem";
constexpr const char *DYNAMIC_POWEROFF_MODEM_WITH_STR = "telephony.dynamic_poweroff_modem_with_str";
}

template<typename T>
inline T GetVirtualModemSwitch()
{
    char virtualModemSwitch[SYSPARA_SIZE] = {0};
    GetParameter(VIRTUAL_MODEM_SWITCH, VIRTUAL_MODEM_DEFAULT_SWITCH, virtualModemSwitch, SYSPARA_SIZE);
    if (strcmp(virtualModemSwitch, "true") == 0) {
        return true;
    }
    return false;
}

template<typename T>
inline T GetMaxSlotCount()
{
    if (maxSlotCount_ == 0) {
        char simSlotCount[SYSPARA_SIZE] = { 0 };
        GetParameter(TEL_SIM_SLOT_COUNT, DEFAULT_SLOT_COUNT, simSlotCount, SYSPARA_SIZE);
        maxSlotCount_ = std::atoi(simSlotCount);
        if (GetVirtualModemSwitch<bool>() && maxSlotCount_ == 0) {
            maxSlotCount_ = 1;
        }
    }
    return maxSlotCount_;
}

template<typename T>
inline T GetRealMaxSlotCount()
{
    if (maxRealSlotCount_ == 0) {
        char realSimSlotCount[SYSPARA_SIZE] = { 0 };
        GetParameter(TEL_SIM_SLOT_COUNT, DEFAULT_SLOT_COUNT, realSimSlotCount, SYSPARA_SIZE);
        maxRealSlotCount_ = std::atoi(realSimSlotCount);
    }
    return maxRealSlotCount_;
}

template<typename T>
inline T GetDefaultEsimSlotId()
{
    if (esimDefaultSlotId_ == ESIM_DEFAULT_SLOTID) {
        char esimDefaultSlotId[SYSPARA_SIZE] = { 0 };
        GetParameter(TEL_DEFAULT_ESIM_SLOT_ID, DEFAULT_ESIM_SLOT_ID, esimDefaultSlotId, SYSPARA_SIZE);
        esimDefaultSlotId_ = std::stoi(esimDefaultSlotId);
        ConvertStrToInt(esimDefaultSlotId, esimDefaultSlotId_, DEC_TYPE);
    }
    return esimDefaultSlotId_;
}

template<typename T>
inline T GetVSimModemCount()
{
    if (vSimModemCount_ == VSIM_DEFAULT_VALUE) {
        char vSimModemCount[SYSPARA_SIZE] = { 0 };
        GetParameter(VSIM_MODEM_COUNT_STR, DEFAULT_VSIM_MODEM_COUNT, vSimModemCount, SYSPARA_SIZE);
        vSimModemCount_ = std::atoi(vSimModemCount);
    }
    return vSimModemCount_;
}

template<typename T>
inline T GetPreferredNetworkType()
{
    char preferredNetworkType[SYSPARA_SIZE] = { 0 };
    GetParameter(TEL_PREFERRED_NETWORK_TYPE, DEFAULT_PREFERRED_NETWORK_TYPE, preferredNetworkType, SYSPARA_SIZE);
    T networkType = std::atoi(preferredNetworkType);
    return networkType;
}

inline bool GetDynamicPowerOffModeSwitch()
{
    return system::GetBoolParameter(DYNAMIC_POWEROFF_MODEM, false);
}

inline bool GetDynamicPowerOffModeSwitchWithStr()
{
    return system::GetBoolParameter(DYNAMIC_POWEROFF_MODEM_WITH_STR, false);
}

enum SatelliteValue {
    SATELLITE_NOT_SUPPORTED = 0,
    SATELLITE_SUPPORTED = 1,
};

enum SimSlotId {
    SIM_SLOT_0 = 0,
    SIM_SLOT_1,
    SIM_SLOT_2,
    SIM_SLOT_3,
};

/**
 * @brief The modem power status.
 */
enum ModemPowerState {
    /**
     * Power Not Available
     */
    CORE_SERVICE_POWER_NOT_AVAILABLE = -1,
    /**
     * Power OFF
     */
    CORE_SERVICE_POWER_OFF = 0,
    /**
     * Power ON
     */
    CORE_SERVICE_POWER_ON = 1
};

template<typename T>
struct TelRilResponseInfo {
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    int32_t flag = 0;
    int32_t errorNo = 0;
    T object;
};

/**
 * @brief Defines the network bandwidth reporting rule.
 */
struct LinkBandwidthRule {
    /**
     * Radio access technology
     */
    int32_t rat = 0;
    /**
     * Delay time
     */
    int32_t delayMs = 0;
    /**
     * Uplink delay
     */
    int32_t delayUplinkKbps = 0;
    /**
     * Downlink delay
     */
    int32_t delayDownlinkKbps = 0;
    /**
     * Maximum uplink parameter list
     */
    std::vector<int32_t> maximumUplinkKbps {};
    /**
     * Maximum downlink parameter list
     */
    std::vector<int32_t> maximumDownlinkKbps {};
};

/**
 * @brief Defines PDP context information.
 */
struct DataProfile {
    /**
     * Profile Id
     */
    int profileId = 0;
    /**
     * (Access Point Name) a string parameter which is a logical name that is used to select the
     * GGSN or the external packet data network. from 3GPP TS 27.007 10.1 V4.3.0 (2001-12)
     */
    std::string apn = "";
    /**
     * (Packet Data Protocol type) a string parameter which specifies the type of packet
     * data protocol from 3GPP TS 27.007 10.1 V4.3.0 (2001-12)
     */
    std::string protocol = "";
    /**
     * Authentication Type
     */
    int32_t verType = 0;
    /**
     * Username
     */
    std::string userName = "";
    /**
     * Password
     */
    std::string password = "";
    /**
     * Roaming protocol version
     */
    std::string roamingProtocol = "";
    /**
     * Supported apn types bitmap
     */
    int32_t supportedApnTypesBitmap = 0;

    std::string snssai = "";
    uint8_t sscMode = 0;
};

/**
 * @brief Defines activate data information.
 */
struct ActivateDataParam {
    /**
     * eg:AppExecFwk::InnerEvent::Get(eventId, activateData.param);
     */
    int32_t param = 0;
    /**
     * Radio access technology
     */
    int32_t radioTechnology = 0;
    /**
     * DataProfile
     */
    struct DataProfile dataProfile;
    /**
     * Whether the user is roaming. The value true indicates that the user is roaming,
     * and the value false indicates the opposite.
     */
    bool isRoaming = false;
    /**
     * Whether allow roaming
     */
    bool allowRoaming = false;
};

/**
 * @brief Defines deactivate data information.
 */
struct DeactivateDataParam {
    /**
     * eg:AppExecFwk::InnerEvent::Get(eventId, deactivateData.param);
     */
    int32_t param = 0;
    /**
     * Packet Data Protocol (PDP) context ID
     */
    int32_t cid = 0;
    /**
     * Reason code of the data service activation failure. For details, see 3GPP TS 24.008.
     */
    int32_t reason = 0;
};

/**
 * @brief Defines the call forwarding information.
 */
struct CallTransferParam {
    /**
     * Call forwarding operation mode:
     *- 0: deactivation
     *- 1: activation
     *- 2: status query
     *- 3: registration
     *- 4: deletion
     */
    int32_t mode = 0;
    /**
     * Call forwarding type:
     *- 0: call forwarding unconditional
     *- 1: call forwarding on busy
     *- 2: call forwarding on no reply
     *- 3: call forwarding not reachable (no network service, or power-off)
     *- 4: any call forwarding
     *- 5: any call forwarding conditional
     */
    int32_t reason = 0;
    /**
     * Service class. For details, see 3GPP TS 27.007.
     */
    int32_t classx = 0;
    /**
     * Phone number
     */
    std::string number = "";
};

/**
 * @brief Defines the call restriction information.
 */
struct CallRestrictionParam {
    /**
     * Operation mode:
     *- 0: deactivation
     *- 1: activation
     */
    int32_t mode = 0;
    /**
     * Password
     */
    char password[MAX_PARAMETER_LENGTH + 1] = { 0 };
    /**
     * Operation object
     */
    std::string fac = "";
};

/**
 * @brief Defines the dual tone multi-frequency (DTMF) information.
 */
struct DtmfParam {
    /**
     * Call ID
     */
    int32_t index = 0;
    /**
     * Duration for playing the DTMF tone
     */
    int32_t switchOn = 0;
    /**
     * Interval for sending DTMF signals
     */
    int32_t switchOff = 0;
    /**
     * DTMF keyword
     */
    std::string sDTMFCode = "";
};

/**
 * @brief Defines the GSM cell broadcast configuration information.
 */
struct CBConfigParam {
    /**
     * Mode (activated or not)
     */
    int32_t mode = 0;
    /**
     * Message IDs
     */
    std::string idList = "";
    /**
     * Data coding schemes
     */
    std::string dcsList = "";
};

/**
 * @brief Defines the SMS message information in a SIM card.
 */
struct CdmaSimMessageParam {
    /**
     * Message index.
     */
    int32_t cdmaIndex = 0;
    /**
     * Status
     */
    int32_t status = 0;
    /**
     * Protocol data unit
     */
    std::string pdu = "";
};

/**
 * @brief GSM SMS message parameter.
 */
struct GsmSimMessageParam {
    /**
     * Reference Id
     */
    int64_t refId = 0;
    /**
     * Short message service center
     */
    std::string smscPdu = "";
    /**
     * Protocol data unit
     */
    std::string pdu = "";
};

/**
 * @brief Defines the SMS message information in a SIM card.
 */
struct SimMessageParam {
    /**
     * Message index.
     */
    int32_t gsmIndex = 0;
    /**
     * Status
     */
    int32_t status = 0;
    /**
     * Short message service center
     */
    std::string smscPdu = "";
    /**
     * Protocol data unit
     */
    std::string pdu = "";
};

/**
 * @brief Defines the SIM card lock information.
 */
struct SimLockParam {
    /**
     * SIM lock type:
     *- AO: barring of all outgoing calls
     *- OI: barring of all outgoing international calls
     *- OX: barring of all outgoing international calls except those directed to the home country
     *- AI: barring of all incoming calls
     *- IR: barring of all incoming calls when roaming outside the home location
     *- AB: barring of all services (applicable only when the mode is greater than or equal to 0)
     *- AG: barring of the outgoing call service (applicable only when the mode is greater than or equal to 0)
     *- AC: barring of the incoming call service (applicable only when the mode is greater than or equal to 0)
     *- FD: fixed dialing number (FDN)
     *- PN: network locking
     *- PU: subnet locking
     *- PP: SP locking
     */
    std::string fac = "";
    /**
     * Mode:
     *- 0: deactivation (When fac is set to PN, PU, or PP, the operation is equivalent to unlocking.)
     *- 1: activation (When fac is set to PN, PU, or PP, activation is not supported.)
     *- 2: query
     */
    int32_t mode = 0;
    /**
     * Password text
     */
    std::string passwd = "";
};

/**
 * @brief Defines the SIM card password information.
 */
struct SimPasswordParam {
    /**
     * Maximum password length
     */
    int32_t passwordLength = 0;
    /**
     * SIM lock type:
     *- AO: barring of all outgoing calls
     *- OI: barring of all outgoing international calls
     *- OX: barring of all outgoing international calls except those directed to the home country
     *- AI: barring of all incoming calls
     *- IR: barring of all incoming calls when roaming outside the home location
     *- AB: barring of all services (applicable only when the mode is greater than or equal to 0)
     *- AG: barring of the outgoing call service (applicable only when the mode is greater than or equal to 0)
     *- AC: barring of the incoming call service (applicable only when the mode is greater than or equal to 0)
     *- FD: fixed dialing number (FDN)
     *- PN: network locking
     *- PU: subnet locking
     *- PP: SP locking
     */
    std::string fac = "";
    /**
     * Old password text
     */
    std::string oldPassword = "";
    /**
     * New password text
     */
    std::string newPassword = "";
};

/**
 * @brief Enumerates emergency call types.
 */
enum class EccType : int32_t {
    /**
     * Default
     */
    TYPE_CATEGORY = 0,
    /**
     * Police
     */
    TYPE_POLICE = 1,
    /**
     * Ambulance
     */
    TYPE_AMBULANCE = 2,
    /**
     * Fire alarm
     */
    TYPE_FIRE = 4,
    /**
     * Marine police
     */
    TYPE_SEA = 8,
    /**
     * Mountain rescue
     */
    TYPE_MOUNTAIN = 16,
};

/**
 * @brief Specifies whether a number is valid when there is a card or no card.
 */
enum class SimpresentType : int32_t {
    /**
     * Valid when there is no card
     */
    TYPE_NO_CARD = 0,
    /**
     * Valid when there is a card
     */
    TYPE_HAS_CARD = 1,
};

/**
 * @brief Specifies whether a number is valid for all states or only for the abnormal service state of
 * the circuit switched (CS) domain.
 */
enum class AbnormalServiceType : int32_t {
    /**
     * Vaild for all states
     */
    TYPE_ALL = 0,
    /**
     * Valid only for the abnormal service state of the CS domain
     */
    TYPE_ONLY_CS = 1,
};

/**
 * @brief Defines the emergency call number.
 */
struct EmergencyCall {
    /**
     * Emergency number
     */
    std::string eccNum = "";
    /**
     * Mobile country code
     */
    std::string mcc = "";
    /**
     * Enumerates emergency call types. For details, see EccType.
     */
    EccType eccType = EccType::TYPE_CATEGORY;
    /**
     * Whether a number is valid when there is a card or no card. For details, see SimpresentType.
     */
    SimpresentType simpresent = SimpresentType::TYPE_NO_CARD;
    /**
     * Whether a number is valid for all states or only for the abnormal service state of the CS domain.
     * For details, see AbnormalService.
     */
    AbnormalServiceType abnormalService = AbnormalServiceType::TYPE_ALL;
    bool operator==(const EmergencyCall &call)
    {
        return (eccNum == call.eccNum && mcc == call.mcc);
    }
};

/**
 * @brief Defines the response info of SetEmergencyCallList.
 */
struct SetEccListResponse {
    /**
     * Response result
     */
    int32_t result = 0;
    /**
     * Response value
     */
    int32_t value = 0;
};

/**
 * @brief Defines the Public Land Mobile Network name.
 */
struct PlmnNetworkName {
    /**
     * Long name of the registered network
     */
    std::string longName = "";
    /**
     * Short name of the registered network
     */
    std::string shortName = "";
};

/**
 * @brief Defines the Operator PLMN information see 3GPP TS 31.102 Section 4.2.59.
 */
struct OperatorPlmnInfo {
    /**
     * PLMN numeric
     */
    std::string plmnNumeric = "";
    /**
     * Start of the LAC range
     */
    int32_t lacStart = 0;
    /**
     * End of the LAC range
     */
    int32_t lacEnd = 0;
    /**
     * Identifier of operator name in PNN to be displayed
     */
    int32_t pnnRecordId = 0;
};

/**
 * @brief Enumerates radio protocol phases.
 *
 * @enum RadioProtocolPhase
 */
enum class RadioProtocolPhase {
    /**
     * The value of Initial radio protocol phase
     */
    RADIO_PROTOCOL_PHASE_INITIAL,
    /**
     * The value of execute check communication phase
     */
    RADIO_PROTOCOL_PHASE_CHECK,
    /**
     * The value of execute update communication phase
     */
    RADIO_PROTOCOL_PHASE_UPDATE,
    /**
     * The value of unsol radio phase
     */
    RADIO_PROTOCOL_PHASE_NOTIFY,
    /**
     * The value of execute complete communication phase
     */
    RADIO_PROTOCOL_PHASE_COMPLETE,
};

/**
 * @brief Enumerates radio protocol states.
 */
enum class RadioProtocolStatus {
    /**
     * Unknow radio protocol state
     */
    RADIO_PROTOCOL_STATUS_NONE,
    /**
     * Set radio protocol successed
     */
    RADIO_PROTOCOL_STATUS_SUCCESS,
    /**
     * Set radio protocol failed
     */
    RADIO_PROTOCOL_STATUS_FAIL,
};

/**
 * @brief Defines the protocol stack information of the primary and secondary SIM cards.
 */
struct RadioProtocol {
    /**
     * Card slot ID
     */
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    /**
     * Session ID
     */
    int32_t sessionId = 0;
    /**
     * Radio protocol parameters. For details, see RadioProtocolPhase.
     */
    RadioProtocolPhase phase = RadioProtocolPhase::RADIO_PROTOCOL_PHASE_INITIAL;
    /**
     * Radio protocol technology:
     *- 1: GSM
     *- 2: 1XRTT
     *- 4: WCDMA
     *- 8: HSPA
     *- 16: HSPAP
     *- 32: TDSCDMA
     *- 64: EV-DO
     *- 128: EHRPD
     *- 256: LTE
     *- 512: LTE_CA
     *- 1024: IWLAN
     *- 2048: NR
     */
    int32_t technology = 0;
    /**
     * Modem ID, corresponding to slotId at the bottom layer
     */
    int32_t modemId = 0;
    /**
     * Radio protocol status. For details, see RadioProtocolStatus.
     */
    RadioProtocolStatus status = RadioProtocolStatus::RADIO_PROTOCOL_STATUS_NONE;
};

/**
 * @brief Defines the result info of ss command.
 */
struct SsBaseResult {
    /**
     * Command index, use for find the ss command to retry
     */
    int32_t index = 0;
    /**
     * The result of execute command
     */
    int32_t result = 0;
    /**
     * This use for remaind message code
     */
    int32_t reason = 0;
    /**
     * This use for remaind message
     */
    std::string message = "";
};

/**
 * @brief Defines the result info of GetClip.
 */
struct GetClipResult {
    /**
     * Query results
     */
    SsBaseResult result;
    /**
     * Parameter sets/shows the result code presentation status in the TA
     */
    int32_t action = 0;
    /**
     * Parameter shows the subscriber CLIP service status in the network, <0-4>
     */
    int32_t clipStat = 0;
};

/**
 * @brief Defines the result info of GetClir.
 */
struct GetClirResult {
    /**
     * Query results
     */
    SsBaseResult result;
    /**
     * Parameter sets/shows the result code presentation status in the TA
     */
    int32_t action = 0;
    /**
     * Parameter shows the subscriber CLIP service status in the network, <0-4>
     */
    int32_t clirStat = 0;
};

/**
 * @brief Defines the result info of GetColr.
 */
struct GetColrResult {
    /**
     * Query results
     */
    SsBaseResult result;
    /**
     * Parameter sets/shows the result code presentation status in the TA
     */
    int32_t action = 0;
    /**
     * Parameter shows the subscriber COLR service status in the network, <0-4>
     */
    int32_t colrStat = 0;
};

/**
 * @brief Defines the result info of GetColp.
 */
struct GetColpResult {
    /**
     * Query results
     */
    SsBaseResult result;
    /**
     * Parameter sets/shows the result code presentation status in the TA
     */
    int32_t action = 0;
    /**
     * Parameter shows the subscriber COLP service status in the network, <0-4>
     */
    int32_t colpStat = 0;
};

/**
 * @brief Defines the result info of CallWait.
 */
struct CallWaitResult {
    /**
     * Query results
     */
    SsBaseResult result;
    /**
     * Parameter sets/shows the result code presentation status in the TA
     */
    int32_t status = 0;
    /**
     * Parameter shows the subscriber CLIP service status in the network, <0-4>
     */
    int32_t classCw = 0;
};

/**
 * @brief Defines the result info of CallRestriction.
 */
struct CallRestrictionResult {
    /**
     * Query results
     */
    SsBaseResult result;
    /**
     * Parameter sets/shows the result code presentation status in the TA
     */
    int32_t status = 0;
    /**
     * Parameter shows the subscriber CLIP service status in the network, <0-4>
     */
    int32_t classCw = 0;
};

/**
 * @brief Defines the call forwarding query result.
 */
struct CallForwardQueryResult {
    /**
     * Request SN
     */
    int32_t serial = 0;
    /**
     * Query result
     */
    int32_t result = 0;
    /**
     * Status:
     *- 0: not activated
     *- 1: activated
     */
    int32_t status = 0;
    /**
     * Service class. For details, see 3GPP TS 27.007.
     */
    int32_t classx = 0;
    /**
     * Phone number
     */
    std::string number = "";
    /**
     * Number type:
     *-129: common number
     *- 145: international number
     */
    int32_t type = 0;
    /**
     * Call forwarding type:
     *- 0: call forwarding unconditional
     *- 1: call forwarding on busy
     *- 2: call forwarding on no reply
     *- 3: call forwarding not reachable (no network service or power-off)
     *- 4: any call forwarding
     *- 5: any call forwarding conditional
     */
    int32_t reason = 0;
    /**
     * Waiting time
     */
    int32_t time = 0;
    /**
     * Start hour
     */
    int32_t startHour = 0;
    /**
     * Start minute
     */
    int32_t startMinute = 0;
    /**
     * End hour
     */
    int32_t endHour = 0;
    /**
     * End minute
     */
    int32_t endMinute = 0;
};

/**
 * @brief Defines the list of call forwarding information.
 */
struct CallForwardQueryInfoList {
    /**
     * Query results
     */
    SsBaseResult result;
    /**
     * Total number
     */
    int32_t callSize = 0;
    /**
     * ID of the call forwarding query result
     */
    int32_t flag = 0;
    /**
     * Call forwarding query result
     */
    std::vector<CallForwardQueryResult> calls {};
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_TELEPHONY_TYPES_H
