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

#ifndef RESOURCE_UTILS_H
#define RESOURCE_UTILS_H

#include <any>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "resource_manager.h"

namespace OHOS {
namespace Telephony {
/*
 * 3GPP TS 24.008
 * V17.4.0 10.5.4.11 Cause
 * The purpose of the cause information element is to describe the reason for generating
 * certain messages, to provide diagnostic information in the event of procedural
 * errors and to indicate the location of the cause originator.
 */
enum DisconnectedReasons {
    UNASSIGNED_NUMBER = 1,
    NO_ROUTE_TO_DESTINATION = 3,
    CHANNEL_UNACCEPTABLE = 6,
    OPERATOR_DETERMINED_BARRING = 8,
    CALL_COMPLETED_ELSEWHERE = 13,
    NORMAL_CALL_CLEARING = 16,
    FAILED_USER_BUSY = 17,
    NO_USER_RESPONDING = 18,
    USER_ALERTING_NO_ANSWER = 19,
    CALL_REJECTED = 21,
    NUMBER_CHANGED = 22,
    CALL_REJECTED_DUE_TO_FEATURE_AT_THE_DESTINATION = 24,
    FAILED_PRE_EMPTION = 25,
    NON_SELECTED_USER_CLEARING = 26,
    DESTINATION_OUT_OF_ORDER = 27,
    INVALID_NUMBER_FORMAT = 28,
    FACILITY_REJECTED = 29,
    RESPONSE_TO_STATUS_ENQUIRY = 30,
    NORMAL_UNSPECIFIED = 31,
    NO_CIRCUIT_CHANNEL_AVAILABLE = 34,
    NETWORK_OUT_OF_ORDER = 38,
    TEMPORARY_FAILURE = 41,
    SWITCHING_EQUIPMENT_CONGESTION = 42,
    ACCESS_INFORMATION_DISCARDED = 43,
    REQUEST_CIRCUIT_CHANNEL_NOT_AVAILABLE = 44,
    RESOURCES_UNAVAILABLE_UNSPECIFIED = 47,
    QUALITY_OF_SERVICE_UNAVAILABLE = 49,
    REQUESTED_FACILITY_NOT_SUBSCRIBED = 50,
    INCOMING_CALLS_BARRED_WITHIN_THE_CUG = 55,
    BEARER_CAPABILITY_NOT_AUTHORIZED = 57,
    BEARER_CAPABILITY_NOT_PRESENTLY_AVAILABLE = 58,
    SERVICE_OR_OPTION_NOT_AVAILABLE_UNSPECIFIED = 63,
    BEARER_SERVICE_NOT_IMPLEMENTED = 65,
    ACM_EQUALTO_OR_GREATE_THAN_ACMMAX = 68,
    REQUESTED_FACILITY_NOT_IMPLEMENTED = 69,
    ONLY_RESTRICTED_DIGITAL_INFO_BEARER_CAPABILITY_IS_AVAILABLE = 70,
    SERVICE_OR_OPTION_NOT_IMPLEMENTED_UNSPECIFIED = 79,
    INVALID_TRANSACTION_IDENTIFIER_VALUE = 81,
    USER_NOT_MEMBER_OF_CUG = 87,
    INCOMPATIBLE_DESTINATION = 88,
    INVALID_TRANSIT_NETWORK_SELECTION = 91,
    SEMANTICALLY_INCORRECT_MESSAGE = 95,
    INVALID_MANDATORY_INFORMATION = 96,
    MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED = 97,
    MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE = 98,
    INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED = 99,
    CONDITIONAL_IE_ERROR = 100,
    MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE = 101,
    RECOVERY_ON_TIMER_EXPIRED = 102,
    PROTOCOL_ERROR_UNSPECIFIED = 111,
    INTERWORKING_UNSPECIFIED = 127,
    CALL_BARRED = 240,
    FDN_BLOCKED = 241,
    IMSI_UNKNOWN_IN_VLR = 242,
    IMEI_NOT_ACCEPTED = 243,
    DIAL_MODIFIED_TO_USSD = 244, // STK Call Control
    DIAL_MODIFIED_TO_SS = 245,
    DIAL_MODIFIED_TO_DIAL = 246,
    RADIO_OFF = 247, // Radio is OFF
    OUT_OF_SERVICE = 248, // No cellular coverage
    NO_VALID_SIM = 249, // No valid SIM is present
    RADIO_INTERNAL_ERROR = 250, // Internal error at Modem
    NETWORK_RESP_TIMEOUT = 251, // No response from network
    NETWORK_REJECT = 252, // Explicit network reject
    RADIO_ACCESS_FAILURE = 253, // RRC connection failure. Eg.RACH
    RADIO_LINK_FAILURE = 254, // Radio Link Failure
    RADIO_LINK_LOST = 255, // Radio link lost due to poor coverage
    RADIO_UPLINK_FAILURE = 256, // Radio uplink failure
    RADIO_SETUP_FAILURE = 257, // RRC connection setup failure
    RADIO_RELEASE_NORMAL = 258, // RRC connection release, normal
    RADIO_RELEASE_ABNORMAL = 259, // RRC connection release, abnormal
    ACCESS_CLASS_BLOCKED = 260, // Access class barring
    NETWORK_DETACH = 261, // Explicit network detach
    FAILED_INVALID_PARAMETER = 1025,
    SIM_NOT_EXIT = 1026,
    SIM_PIN_NEED = 1027,
    CALL_NOT_ALLOW = 1029,
    SIM_INVALID = 1045,
    FAILED_UNKNOWN = 1279,
};

class ResourceUtils {
public:
    static const std::string IS_NOTIFY_USER_RESTRICTIED_CHANGE;
    static const std::string IS_CS_CAPABLE;
    static const std::string IS_SWITCH_PHONE_REG_CHANGE;
    static const std::string SPN_FORMATS;
    static const std::string EMERGENCY_CALLS_ONLY;
    static const std::string OUT_OF_SERIVCE;
    static const std::string CMCC;
    static const std::string CUCC;
    static const std::string CTCC;
    static const std::string CALL_FAILED_UNASSIGNED_NUMBER;
    static const std::string CALL_FAILED_NO_ROUTE_TO_DESTINATION;
    static const std::string CALL_FAILED_CHANNEL_UNACCEPTABLE;
    static const std::string CALL_FAILED_OPERATOR_DETERMINED_BARRING;
    static const std::string CALL_FAILED_NORMAL_CALL_CLEARING;
    static const std::string CALL_FAILED_USER_BUSY;
    static const std::string CALL_FAILED_NO_USER_RESPONDING;
    static const std::string CALL_FAILED_USER_ALERTING_NO_ANSWER;
    static const std::string CALL_FAILED_CALL_REJECTED;
    static const std::string CALL_FAILED_NUMBER_CHANGED;
    static const std::string CALL_FAILED_CALL_REJECTED_DESTINATION;
    static const std::string CALL_FAILED_FAILED_PRE_EMPTION;
    static const std::string CALL_FAILED_NON_SELECTED_USER_CLEARING;
    static const std::string CALL_FAILED_DESTINATION_OUT_OF_ORDER;
    static const std::string CALL_FAILED_INVALID_NUMBER_FORMAT;
    static const std::string CALL_FAILED_FACILITY_REJECTED;
    static const std::string CALL_FAILED_RESPONSE_TO_STATUS_ENQUIRY;
    static const std::string CALL_FAILED_NORMAL_UNSPECIFIED;
    static const std::string CALL_FAILED_NO_CIRCUIT_CHANNEL_AVAILABLE;
    static const std::string CALL_FAILED_NETWORK_OUT_OF_ORDER;
    static const std::string CALL_FAILED_TEMPORARY_FAILURE;
    static const std::string CALL_FAILED_SWITCHING_EQUIPMENT_CONGESTION;
    static const std::string CALL_FAILED_ACCESS_INFORMATION_DISCARDED;
    static const std::string CALL_FAILED_REQUEST_CIRCUIT_CHANNEL_NOT_AVAILABLE;
    static const std::string CALL_FAILED_RESOURCES_UNAVAILABLE_UNSPECIFIED;
    static const std::string CALL_FAILED_QUALITY_OF_SERVICE_UNAVAILABLE;
    static const std::string CALL_FAILED_REQUESTED_FACILITY_NOT_SUBSCRIBED;
    static const std::string CALL_FAILED_INCOMING_CALLS_BARRED_WITHIN_THE_CUG;
    static const std::string CALL_FAILED_BEARER_CAPABILITY_NOT_AUTHORIZED;
    static const std::string CALL_FAILED_BEARER_CAPABILITY_NOT_PRESENTLY_AVAILABLE;
    static const std::string CALL_FAILED_SERVICE_OR_OPTION_NOT_AVAILABLE_UNSPECIFIED;
    static const std::string CALL_FAILED_BEARER_SERVICE_NOT_IMPLEMENTED;
    static const std::string CALL_FAILED_ACM_EQUALTO_OR_GREATE_THAN_ACMMAX;
    static const std::string CALL_FAILED_REQUESTED_FACILITY_NOT_IMPLEMENTED;
    static const std::string CALL_FAILED_ONLY_RESTRICTED_DIGITAL_INFO_BEARER_CAPABILITY_IS_AVAILABLE;
    static const std::string CALL_FAILED_SERVICE_OR_OPTION_NOT_IMPLEMENTED_UNSPECIFIED;
    static const std::string CALL_FAILED_INVALID_TRANSACTION_IDENTIFIER_VALUE;
    static const std::string CALL_FAILED_USER_NOT_MEMBER_OF_CUG;
    static const std::string CALL_FAILED_INCOMPATIBLE_DESTINATION;
    static const std::string CALL_FAILED_INVALID_TRANSIT_NETWORK_SELECTION;
    static const std::string CALL_FAILED_SEMANTICALLY_INCORRECT_MESSAGE;
    static const std::string CALL_FAILED_INVALID_MANDATORY_INFORMATION;
    static const std::string CALL_FAILED_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED;
    static const std::string CALL_FAILED_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE;
    static const std::string CALL_FAILED_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED;
    static const std::string CALL_FAILED_CONDITIONAL_IE_ERROR;
    static const std::string CALL_FAILED_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE;
    static const std::string CALL_FAILED_RECOVERY_ON_TIMER_EXPIRED;
    static const std::string CALL_FAILED_PROTOCOL_ERROR_UNSPECIFIED;
    static const std::string CALL_FAILED_INTERWORKING_UNSPECIFIED;
    static const std::string CALL_FAILED_CALL_BARRED;
    static const std::string CALL_FAILED_FDN_BLOCKED;
    static const std::string CALL_FAILED_IMSI_UNKNOWN_IN_VLR;
    static const std::string CALL_FAILED_IMEI_NOT_ACCEPTED;
    static const std::string CALL_FAILED_DIAL_MODIFIED_TO_USSD;
    static const std::string CALL_FAILED_DIAL_MODIFIED_TO_SS;
    static const std::string CALL_FAILED_DIAL_MODIFIED_TO_DIAL;
    static const std::string CALL_FAILED_RADIO_OFF;
    static const std::string CALL_FAILED_OUT_OF_SERVICE;
    static const std::string CALL_FAILED_NO_VALID_SIM;
    static const std::string CALL_FAILED_RADIO_INTERNAL_ERROR;
    static const std::string CALL_FAILED_NETWORK_RESP_TIMEOUT;
    static const std::string CALL_FAILED_NETWORK_REJECT;
    static const std::string CALL_FAILED_RADIO_ACCESS_FAILURE;
    static const std::string CALL_FAILED_RADIO_LINK_FAILURE;
    static const std::string CALL_FAILED_RADIO_LINK_LOST;
    static const std::string CALL_FAILED_RADIO_UPLINK_FAILURE;
    static const std::string CALL_FAILED_RADIO_SETUP_FAILURE;
    static const std::string CALL_FAILED_RADIO_RELEASE_NORMAL;
    static const std::string CALL_FAILED_RADIO_RELEASE_ABNORMAL;
    static const std::string CALL_FAILED_ACCESS_CLASS_BLOCKED;
    static const std::string CALL_FAILED_NETWORK_DETACH;
    static const std::string CALL_FAILED_INVALID_PARAMETER;
    static const std::string CALL_FAILED_SIM_NOT_EXIT;
    static const std::string CALL_FAILED_SIM_PIN_NEED;
    static const std::string CALL_FAILED_CALL_NOT_ALLOW;
    static const std::string CALL_FAILED_SIM_INVALID;
    static const std::string CALL_FAILED_UNKNOWN;

    static ResourceUtils &Get();
    bool Init();
    void ShowAllValue();
    ~ResourceUtils() = default;

    bool GetCallFailedMessageName(int32_t reason, std::string &name);
    bool GetStringValueByName(const std::string &name, std::string &value);
    bool GetStringArrayValueByName(const std::string &name, std::vector<std::string> &value);
    bool GetBooleanValueByName(const std::string &name, bool &value);
    bool GetIntegerValueByName(const std::string &name, int32_t &value);
    bool GetIntArrayValueByName(const std::string &name, std::vector<int32_t> &value);

private:
    ResourceUtils();
    void SaveAllValue();
    bool GetStringByName(std::string name, std::string &value);
    bool GetIntegerByName(std::string name, int &value);
    bool GetBooleanByName(std::string name, bool &value);
    bool GetStringArrayByName(std::string name, std::vector<std::string> &value);
    bool GetIntArrayByName(std::string name, std::vector<int32_t> &value);
    bool IsFileExist(const std::string &filePath);

private:
    std::unique_ptr<Global::Resource::ResourceManager> resourceManager_ = nullptr;
    bool beSourceAdd_ = false;
    std::map<std::string, std::any> mapResourceValues_;
    std::mutex mutex_;

    enum class ResourceType {
        ResourceTypeUnkown,
        ResourceTypeString,
        ResourceTypeInteger,
        ResourceTypeBoolean,
        ResourceTypeArrayString,
        ResourceTypeArrayInteger
    };

    static const std::map<std::string, ResourceType> mapResourceNameType_;
    static const std::map<int32_t, std::string> callFailedResourceName_;
    static const std::string RESOURCE_HAP_BUNDLE_NAME;
    static const std::string RESOURCE_INDEX_PATH;
};
} // namespace Telephony
} // namespace OHOS

#endif