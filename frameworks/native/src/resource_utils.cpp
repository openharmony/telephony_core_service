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

#include "resource_utils.h"

#include <sys/stat.h>

#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t HAP_USER_ID = 100;
const std::string ResourceUtils::RESOURCE_HAP_BUNDLE_NAME = "ohos.telephony.resources";
const std::string ResourceUtils::IS_NOTIFY_USER_RESTRICTIED_CHANGE = "is_notify_user_restrictied_change";
const std::string ResourceUtils::IS_CS_CAPABLE = "is_cs_capable";
const std::string ResourceUtils::IS_SWITCH_PHONE_REG_CHANGE = "is_switch_phone_reg_change";
const std::string ResourceUtils::SPN_FORMATS = "spn_formats";
const std::string ResourceUtils::EMERGENCY_CALLS_ONLY = "emergency_calls_only";
const std::string ResourceUtils::OUT_OF_SERIVCE = "out_of_serivce";
const std::string ResourceUtils::CMCC = "cmcc";
const std::string ResourceUtils::CUCC = "cucc";
const std::string ResourceUtils::CTCC = "ctcc";
const std::string ResourceUtils::CALL_FAILED_UNASSIGNED_NUMBER = "call_failed_unassigned_number";
const std::string ResourceUtils::CALL_FAILED_NO_ROUTE_TO_DESTINATION = "call_failed_no_route_to_destination";
const std::string ResourceUtils::CALL_FAILED_CHANNEL_UNACCEPTABLE = "call_failed_channel_unacceptable";
const std::string ResourceUtils::CALL_FAILED_OPERATOR_DETERMINED_BARRING = "call_failed_operator_determined_barring";
const std::string ResourceUtils::CALL_FAILED_NORMAL_CALL_CLEARING = "call_failed_normal_call_clearing";
const std::string ResourceUtils::CALL_FAILED_USER_BUSY = "call_failed_user_busy";
const std::string ResourceUtils::CALL_FAILED_NO_USER_RESPONDING = "call_failed_no_user_responding";
const std::string ResourceUtils::CALL_FAILED_USER_ALERTING_NO_ANSWER = "call_failed_user_no_answer";
const std::string ResourceUtils::CALL_FAILED_CALL_REJECTED = "call_failed_call_rejected";
const std::string ResourceUtils::CALL_FAILED_NUMBER_CHANGED = "call_failed_number_changed";
const std::string ResourceUtils::CALL_FAILED_CALL_REJECTED_DESTINATION = "call_failed_call_rejected_destination";
const std::string ResourceUtils::CALL_FAILED_FAILED_PRE_EMPTION = "call_failed_pre_emption";
const std::string ResourceUtils::CALL_FAILED_NON_SELECTED_USER_CLEARING = "call_failed_non_selected_user_clearing";
const std::string ResourceUtils::CALL_FAILED_DESTINATION_OUT_OF_ORDER = "call_failed_destination_out_of_order";
const std::string ResourceUtils::CALL_FAILED_INVALID_NUMBER_FORMAT = "call_failed_invalid_number_format";
const std::string ResourceUtils::CALL_FAILED_FACILITY_REJECTED = "call_failed_facility_rejected";
const std::string ResourceUtils::CALL_FAILED_RESPONSE_TO_STATUS_ENQUIRY = "call_failed_response_to_status_enquiry";
const std::string ResourceUtils::CALL_FAILED_NORMAL_UNSPECIFIED = "call_failed_normal_unspecified";
const std::string ResourceUtils::CALL_FAILED_NO_CIRCUIT_CHANNEL_AVAILABLE = "call_failed_no_circuit_channel_available";
const std::string ResourceUtils::CALL_FAILED_NETWORK_OUT_OF_ORDER = "call_failed_network_out_of_order";
const std::string ResourceUtils::CALL_FAILED_TEMPORARY_FAILURE = "call_failed_temporary_failure";
const std::string ResourceUtils::CALL_FAILED_SWITCHING_EQUIPMENT_CONGESTION =
    "call_failed_switching_equipment_congestion";
const std::string ResourceUtils::CALL_FAILED_ACCESS_INFORMATION_DISCARDED = "call_failed_access_information_discarded";
const std::string ResourceUtils::CALL_FAILED_REQUEST_CIRCUIT_CHANNEL_NOT_AVAILABLE =
    "call_failed_requested_circuit_or_channel_not_available";
const std::string ResourceUtils::CALL_FAILED_RESOURCES_UNAVAILABLE_UNSPECIFIED =
    "call_failed_resources_unavailable_or_unspecified";
const std::string ResourceUtils::CALL_FAILED_QUALITY_OF_SERVICE_UNAVAILABLE =
    "call_failed_quality_of_service_unavailable";
const std::string ResourceUtils::CALL_FAILED_REQUESTED_FACILITY_NOT_SUBSCRIBED =
    "call_failed_requested_facility_not_subscribed";
const std::string ResourceUtils::CALL_FAILED_INCOMING_CALLS_BARRED_WITHIN_THE_CUG =
    "call_failed_incoming_calls_barred_within_the_CUG";
const std::string ResourceUtils::CALL_FAILED_BEARER_CAPABILITY_NOT_AUTHORIZED =
    "call_failed_bearer_capability_not_authorized";
const std::string ResourceUtils::CALL_FAILED_BEARER_CAPABILITY_NOT_PRESENTLY_AVAILABLE =
    "call_failed_bearer_capability_not_presently_unavailable";
const std::string ResourceUtils::CALL_FAILED_SERVICE_OR_OPTION_NOT_AVAILABLE_UNSPECIFIED =
    "call_failed_service_or_option_not_available_or_unspecified";
const std::string ResourceUtils::CALL_FAILED_BEARER_SERVICE_NOT_IMPLEMENTED =
    "call_failed_bearer_service_not_implemented";
const std::string ResourceUtils::CALL_FAILED_ACM_EQUALTO_OR_GREATE_THAN_ACMMAX =
    "call_failed_acm_equal_to_or_greater_than_acmmax";
const std::string ResourceUtils::CALL_FAILED_REQUESTED_FACILITY_NOT_IMPLEMENTED =
    "call_failed_requested_facility_not_implemented";
const std::string ResourceUtils::CALL_FAILED_ONLY_RESTRICTED_DIGITAL_INFO_BEARER_CAPABILITY_IS_AVAILABLE =
    "call_failed_only_restricted_digital_info_bearer_capability_is_available";
const std::string ResourceUtils::CALL_FAILED_SERVICE_OR_OPTION_NOT_IMPLEMENTED_UNSPECIFIED =
    "call_failed_service_or_option_not_implemented";
const std::string ResourceUtils::CALL_FAILED_INVALID_TRANSACTION_IDENTIFIER_VALUE =
    "call_failed_invalid_transaction_identifier_value";
const std::string ResourceUtils::CALL_FAILED_USER_NOT_MEMBER_OF_CUG = "call_failed_user_not_member_of_CUG";
const std::string ResourceUtils::CALL_FAILED_INCOMPATIBLE_DESTINATION = "call_failed_incompatible_destination";
const std::string ResourceUtils::CALL_FAILED_INVALID_TRANSIT_NETWORK_SELECTION =
    "call_failed_invalid_transit_network_selection";
const std::string ResourceUtils::CALL_FAILED_SEMANTICALLY_INCORRECT_MESSAGE =
    "call_failed_semantically_incorrect_message";
const std::string ResourceUtils::CALL_FAILED_INVALID_MANDATORY_INFORMATION =
    "call_failed_invalid_mandatory_information";
const std::string ResourceUtils::CALL_FAILED_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED =
    "call_failed_message_type_non_existent_or_not_implemented";
const std::string ResourceUtils::CALL_FAILED_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE =
    "call_failed_message_type_not_compatible_with_protocol_state";
const std::string ResourceUtils::CALL_FAILED_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED =
    "call_failed_information_element_non_existent_or_not_implemented";
const std::string ResourceUtils::CALL_FAILED_CONDITIONAL_IE_ERROR = "call_failed_conditional_IE_error";
const std::string ResourceUtils::CALL_FAILED_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE =
    "call_failed_message_not_compatible_with_protocol_state";
const std::string ResourceUtils::CALL_FAILED_RECOVERY_ON_TIMER_EXPIRED = "call_failed_recovery_on_timer_expired";
const std::string ResourceUtils::CALL_FAILED_PROTOCOL_ERROR_UNSPECIFIED = "call_failed_protocol_error_unspecified";
const std::string ResourceUtils::CALL_FAILED_INTERWORKING_UNSPECIFIED = "call_failed_interworking_unspecified";
const std::string ResourceUtils::CALL_FAILED_CALL_BARRED = "call_failed_call_barred";
const std::string ResourceUtils::CALL_FAILED_FDN_BLOCKED = "call_failed_fdn_blocked";
const std::string ResourceUtils::CALL_FAILED_IMSI_UNKNOWN_IN_VLR = "call_failed_imsi_unknow";
const std::string ResourceUtils::CALL_FAILED_IMEI_NOT_ACCEPTED = "call_failed_imei_not_accepted";
const std::string ResourceUtils::CALL_FAILED_IMEISV_NOT_ACCEPTED = "call_failed_imeisv_not_accepted";
const std::string ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_USSD = "call_failed_dial_modify_to_ussd";
const std::string ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_SS = "call_failed_dial_modify_to_ss";
const std::string ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_DIAL = "call_failed_dial_modify_to_dial";
const std::string ResourceUtils::CALL_FAILED_RADIO_OFF = "call_failed_radio_off";
const std::string ResourceUtils::CALL_FAILED_OUT_OF_SERVICE = "call_failed_out_of_service";
const std::string ResourceUtils::CALL_FAILED_NO_VALID_SIM = "call_failed_no_valid_sim";
const std::string ResourceUtils::CALL_FAILED_RADIO_INTERNAL_ERROR = "call_failed_radio_internal_error";
const std::string ResourceUtils::CALL_FAILED_NETWORK_RESP_TIMEOUT = "call_failed_network_response_timeout";
const std::string ResourceUtils::CALL_FAILED_NETWORK_REJECT = "call_failed_network_reject";
const std::string ResourceUtils::CALL_FAILED_RADIO_ACCESS_FAILURE = "call_failed_radio_access_failure";
const std::string ResourceUtils::CALL_FAILED_RADIO_LINK_FAILURE = "call_failed_radio_link_failure";
const std::string ResourceUtils::CALL_FAILED_RADIO_LINK_LOST = "call_failed_radio_link_lost";
const std::string ResourceUtils::CALL_FAILED_RADIO_UPLINK_FAILURE = "call_failed_radio_uplink_failure";
const std::string ResourceUtils::CALL_FAILED_RADIO_SETUP_FAILURE = "call_failed_radio_setup_failure";
const std::string ResourceUtils::CALL_FAILED_RADIO_RELEASE_NORMAL = "call_failed_radio_release_normal";
const std::string ResourceUtils::CALL_FAILED_RADIO_RELEASE_ABNORMAL = "call_failed_radio_release_abnormal";
const std::string ResourceUtils::CALL_FAILED_ACCESS_CLASS_BLOCKED = "call_failed_access_class_barring";
const std::string ResourceUtils::CALL_FAILED_NETWORK_DETACH = "call_failed_network_detach";
const std::string ResourceUtils::CALL_FAILED_INVALID_PARAMETER = "call_failed_invalid_parameter";
const std::string ResourceUtils::CALL_FAILED_SIM_NOT_EXIT = "call_failed_sim_not_exit";
const std::string ResourceUtils::CALL_FAILED_SIM_PIN_NEED = "call_failed_sim_pin_need";
const std::string ResourceUtils::CALL_FAILED_CALL_NOT_ALLOW = "call_failed_call_not_allow";
const std::string ResourceUtils::CALL_FAILED_SIM_INVALID = "call_failed_sim_invalid";
const std::string ResourceUtils::CALL_FAILED_UNKNOWN = "call_failed_unknow";

const std::map<std::string, ResourceUtils::ResourceType> ResourceUtils::mapResourceNameType_ = {
    { ResourceUtils::IS_NOTIFY_USER_RESTRICTIED_CHANGE, ResourceUtils::ResourceType::ResourceTypeBoolean },
    { ResourceUtils::IS_CS_CAPABLE, ResourceUtils::ResourceType::ResourceTypeBoolean },
    { ResourceUtils::IS_SWITCH_PHONE_REG_CHANGE, ResourceUtils::ResourceType::ResourceTypeBoolean },
    { ResourceUtils::SPN_FORMATS, ResourceUtils::ResourceType::ResourceTypeArrayString },
    { ResourceUtils::EMERGENCY_CALLS_ONLY, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::OUT_OF_SERIVCE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CMCC, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CUCC, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CTCC, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_UNASSIGNED_NUMBER, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NO_ROUTE_TO_DESTINATION, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_CHANNEL_UNACCEPTABLE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_OPERATOR_DETERMINED_BARRING, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NORMAL_CALL_CLEARING, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_USER_BUSY, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NO_USER_RESPONDING, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_USER_ALERTING_NO_ANSWER, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_CALL_REJECTED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NUMBER_CHANGED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_CALL_REJECTED_DESTINATION, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_FAILED_PRE_EMPTION, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NON_SELECTED_USER_CLEARING, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_DESTINATION_OUT_OF_ORDER, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INVALID_NUMBER_FORMAT, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_FACILITY_REJECTED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RESPONSE_TO_STATUS_ENQUIRY, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NORMAL_UNSPECIFIED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NO_CIRCUIT_CHANNEL_AVAILABLE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NETWORK_OUT_OF_ORDER, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_TEMPORARY_FAILURE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_SWITCHING_EQUIPMENT_CONGESTION, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_ACCESS_INFORMATION_DISCARDED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_REQUEST_CIRCUIT_CHANNEL_NOT_AVAILABLE,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RESOURCES_UNAVAILABLE_UNSPECIFIED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_QUALITY_OF_SERVICE_UNAVAILABLE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_REQUESTED_FACILITY_NOT_SUBSCRIBED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INCOMING_CALLS_BARRED_WITHIN_THE_CUG,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_BEARER_CAPABILITY_NOT_AUTHORIZED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_BEARER_CAPABILITY_NOT_PRESENTLY_AVAILABLE,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_SERVICE_OR_OPTION_NOT_AVAILABLE_UNSPECIFIED,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_BEARER_SERVICE_NOT_IMPLEMENTED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_ACM_EQUALTO_OR_GREATE_THAN_ACMMAX, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_REQUESTED_FACILITY_NOT_IMPLEMENTED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_ONLY_RESTRICTED_DIGITAL_INFO_BEARER_CAPABILITY_IS_AVAILABLE,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_SERVICE_OR_OPTION_NOT_IMPLEMENTED_UNSPECIFIED,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INVALID_TRANSACTION_IDENTIFIER_VALUE,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_USER_NOT_MEMBER_OF_CUG, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INCOMPATIBLE_DESTINATION, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INVALID_TRANSIT_NETWORK_SELECTION, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_SEMANTICALLY_INCORRECT_MESSAGE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INVALID_MANDATORY_INFORMATION, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_CONDITIONAL_IE_ERROR, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE,
        ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RECOVERY_ON_TIMER_EXPIRED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_PROTOCOL_ERROR_UNSPECIFIED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INTERWORKING_UNSPECIFIED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_CALL_BARRED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_FDN_BLOCKED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_IMSI_UNKNOWN_IN_VLR, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_IMEI_NOT_ACCEPTED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_IMEISV_NOT_ACCEPTED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_USSD, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_SS, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_DIAL, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_OFF, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_OUT_OF_SERVICE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NO_VALID_SIM, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_INTERNAL_ERROR, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NETWORK_RESP_TIMEOUT, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NETWORK_REJECT, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_ACCESS_FAILURE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_LINK_FAILURE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_LINK_LOST, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_UPLINK_FAILURE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_SETUP_FAILURE, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_RELEASE_NORMAL, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_RADIO_RELEASE_ABNORMAL, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_ACCESS_CLASS_BLOCKED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_NETWORK_DETACH, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_INVALID_PARAMETER, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_SIM_NOT_EXIT, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_SIM_PIN_NEED, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_CALL_NOT_ALLOW, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_SIM_INVALID, ResourceUtils::ResourceType::ResourceTypeString },
    { ResourceUtils::CALL_FAILED_UNKNOWN, ResourceUtils::ResourceType::ResourceTypeString },
};

const std::map<int32_t, std::string> ResourceUtils::callFailedResourceName_ = {
    { DisconnectedReasons::UNASSIGNED_NUMBER, ResourceUtils::CALL_FAILED_UNASSIGNED_NUMBER },
    { DisconnectedReasons::NO_ROUTE_TO_DESTINATION, ResourceUtils::CALL_FAILED_NO_ROUTE_TO_DESTINATION },
    { DisconnectedReasons::CHANNEL_UNACCEPTABLE, ResourceUtils::CALL_FAILED_CHANNEL_UNACCEPTABLE },
    { DisconnectedReasons::OPERATOR_DETERMINED_BARRING, ResourceUtils::CALL_FAILED_OPERATOR_DETERMINED_BARRING },
    { DisconnectedReasons::NORMAL_CALL_CLEARING, ResourceUtils::CALL_FAILED_NORMAL_CALL_CLEARING },
    { DisconnectedReasons::FAILED_USER_BUSY, ResourceUtils::CALL_FAILED_USER_BUSY },
    { DisconnectedReasons::NO_USER_RESPONDING, ResourceUtils::CALL_FAILED_NO_USER_RESPONDING },
    { DisconnectedReasons::USER_ALERTING_NO_ANSWER, ResourceUtils::CALL_FAILED_USER_ALERTING_NO_ANSWER },
    { DisconnectedReasons::CALL_REJECTED, ResourceUtils::CALL_FAILED_CALL_REJECTED },
    { DisconnectedReasons::NUMBER_CHANGED, ResourceUtils::CALL_FAILED_NUMBER_CHANGED },
    { DisconnectedReasons::CALL_REJECTED_DUE_TO_FEATURE_AT_THE_DESTINATION,
        ResourceUtils::CALL_FAILED_CALL_REJECTED_DESTINATION },
    { DisconnectedReasons::FAILED_PRE_EMPTION, ResourceUtils::CALL_FAILED_FAILED_PRE_EMPTION },
    { DisconnectedReasons::NON_SELECTED_USER_CLEARING, ResourceUtils::CALL_FAILED_NON_SELECTED_USER_CLEARING },
    { DisconnectedReasons::DESTINATION_OUT_OF_ORDER, ResourceUtils::CALL_FAILED_DESTINATION_OUT_OF_ORDER },
    { DisconnectedReasons::INVALID_NUMBER_FORMAT, ResourceUtils::CALL_FAILED_INVALID_NUMBER_FORMAT },
    { DisconnectedReasons::FACILITY_REJECTED, ResourceUtils::CALL_FAILED_FACILITY_REJECTED },
    { DisconnectedReasons::RESPONSE_TO_STATUS_ENQUIRY, ResourceUtils::CALL_FAILED_RESPONSE_TO_STATUS_ENQUIRY },
    { DisconnectedReasons::NORMAL_UNSPECIFIED, ResourceUtils::CALL_FAILED_NORMAL_UNSPECIFIED },
    { DisconnectedReasons::NO_CIRCUIT_CHANNEL_AVAILABLE, ResourceUtils::CALL_FAILED_NO_CIRCUIT_CHANNEL_AVAILABLE },
    { DisconnectedReasons::NETWORK_OUT_OF_ORDER, ResourceUtils::CALL_FAILED_NETWORK_OUT_OF_ORDER },
    { DisconnectedReasons::TEMPORARY_FAILURE, ResourceUtils::CALL_FAILED_TEMPORARY_FAILURE },
    { DisconnectedReasons::SWITCHING_EQUIPMENT_CONGESTION, ResourceUtils::CALL_FAILED_SWITCHING_EQUIPMENT_CONGESTION },
    { DisconnectedReasons::ACCESS_INFORMATION_DISCARDED, ResourceUtils::CALL_FAILED_ACCESS_INFORMATION_DISCARDED },
    { DisconnectedReasons::REQUEST_CIRCUIT_CHANNEL_NOT_AVAILABLE,
        ResourceUtils::CALL_FAILED_REQUEST_CIRCUIT_CHANNEL_NOT_AVAILABLE },
    { DisconnectedReasons::RESOURCES_UNAVAILABLE_UNSPECIFIED,
        ResourceUtils::CALL_FAILED_RESOURCES_UNAVAILABLE_UNSPECIFIED },
    { DisconnectedReasons::QUALITY_OF_SERVICE_UNAVAILABLE, ResourceUtils::CALL_FAILED_QUALITY_OF_SERVICE_UNAVAILABLE },
    { DisconnectedReasons::REQUESTED_FACILITY_NOT_SUBSCRIBED,
        ResourceUtils::CALL_FAILED_REQUESTED_FACILITY_NOT_SUBSCRIBED },
    { DisconnectedReasons::INCOMING_CALLS_BARRED_WITHIN_THE_CUG,
        ResourceUtils::CALL_FAILED_INCOMING_CALLS_BARRED_WITHIN_THE_CUG },
    { DisconnectedReasons::BEARER_CAPABILITY_NOT_AUTHORIZED,
        ResourceUtils::CALL_FAILED_BEARER_CAPABILITY_NOT_AUTHORIZED },
    { DisconnectedReasons::BEARER_CAPABILITY_NOT_PRESENTLY_AVAILABLE,
        ResourceUtils::CALL_FAILED_BEARER_CAPABILITY_NOT_PRESENTLY_AVAILABLE },
    { DisconnectedReasons::SERVICE_OR_OPTION_NOT_AVAILABLE_UNSPECIFIED,
        ResourceUtils::CALL_FAILED_SERVICE_OR_OPTION_NOT_AVAILABLE_UNSPECIFIED },
    { DisconnectedReasons::BEARER_SERVICE_NOT_IMPLEMENTED, ResourceUtils::CALL_FAILED_BEARER_SERVICE_NOT_IMPLEMENTED },
    { DisconnectedReasons::ACM_EQUALTO_OR_GREATE_THAN_ACMMAX,
        ResourceUtils::CALL_FAILED_ACM_EQUALTO_OR_GREATE_THAN_ACMMAX },
    { DisconnectedReasons::REQUESTED_FACILITY_NOT_IMPLEMENTED,
        ResourceUtils::CALL_FAILED_REQUESTED_FACILITY_NOT_IMPLEMENTED },
    { DisconnectedReasons::ONLY_RESTRICTED_DIGITAL_INFO_BEARER_CAPABILITY_IS_AVAILABLE,
        ResourceUtils::CALL_FAILED_ONLY_RESTRICTED_DIGITAL_INFO_BEARER_CAPABILITY_IS_AVAILABLE },
    { DisconnectedReasons::SERVICE_OR_OPTION_NOT_IMPLEMENTED_UNSPECIFIED,
        ResourceUtils::CALL_FAILED_SERVICE_OR_OPTION_NOT_IMPLEMENTED_UNSPECIFIED },
    { DisconnectedReasons::INVALID_TRANSACTION_IDENTIFIER_VALUE,
        ResourceUtils::CALL_FAILED_INVALID_TRANSACTION_IDENTIFIER_VALUE },
    { DisconnectedReasons::USER_NOT_MEMBER_OF_CUG, ResourceUtils::CALL_FAILED_USER_NOT_MEMBER_OF_CUG },
    { DisconnectedReasons::INCOMPATIBLE_DESTINATION, ResourceUtils::CALL_FAILED_INCOMPATIBLE_DESTINATION },
    { DisconnectedReasons::INVALID_TRANSIT_NETWORK_SELECTION,
        ResourceUtils::CALL_FAILED_INVALID_TRANSIT_NETWORK_SELECTION },
    { DisconnectedReasons::SEMANTICALLY_INCORRECT_MESSAGE, ResourceUtils::CALL_FAILED_SEMANTICALLY_INCORRECT_MESSAGE },
    { DisconnectedReasons::INVALID_MANDATORY_INFORMATION, ResourceUtils::CALL_FAILED_INVALID_MANDATORY_INFORMATION },
    { DisconnectedReasons::MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED,
        ResourceUtils::CALL_FAILED_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED },
    { DisconnectedReasons::MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE,
        ResourceUtils::CALL_FAILED_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE },
    { DisconnectedReasons::INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED,
        ResourceUtils::CALL_FAILED_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED },
    { DisconnectedReasons::CONDITIONAL_IE_ERROR, ResourceUtils::CALL_FAILED_CONDITIONAL_IE_ERROR },
    { DisconnectedReasons::MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE,
        ResourceUtils::CALL_FAILED_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE },
    { DisconnectedReasons::RECOVERY_ON_TIMER_EXPIRED, ResourceUtils::CALL_FAILED_RECOVERY_ON_TIMER_EXPIRED },
    { DisconnectedReasons::PROTOCOL_ERROR_UNSPECIFIED, ResourceUtils::CALL_FAILED_PROTOCOL_ERROR_UNSPECIFIED },
    { DisconnectedReasons::INTERWORKING_UNSPECIFIED, ResourceUtils::CALL_FAILED_INTERWORKING_UNSPECIFIED },
    { DisconnectedReasons::CALL_BARRED, ResourceUtils::CALL_FAILED_CALL_BARRED },
    { DisconnectedReasons::FDN_BLOCKED, ResourceUtils::CALL_FAILED_FDN_BLOCKED },
    { DisconnectedReasons::IMSI_UNKNOWN_IN_VLR, ResourceUtils::CALL_FAILED_IMSI_UNKNOWN_IN_VLR },
    { DisconnectedReasons::IMEI_NOT_ACCEPTED, ResourceUtils::CALL_FAILED_IMEI_NOT_ACCEPTED },
    { DisconnectedReasons::IMEISV_NOT_ACCEPTED, ResourceUtils::CALL_FAILED_IMEISV_NOT_ACCEPTED },
    { DisconnectedReasons::DIAL_MODIFIED_TO_USSD, ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_USSD },
    { DisconnectedReasons::DIAL_MODIFIED_TO_SS, ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_SS },
    { DisconnectedReasons::DIAL_MODIFIED_TO_DIAL, ResourceUtils::CALL_FAILED_DIAL_MODIFIED_TO_DIAL },
    { DisconnectedReasons::RADIO_OFF, ResourceUtils::CALL_FAILED_RADIO_OFF },
    { DisconnectedReasons::OUT_OF_SERVICE, ResourceUtils::CALL_FAILED_OUT_OF_SERVICE },
    { DisconnectedReasons::NO_VALID_SIM, ResourceUtils::CALL_FAILED_NO_VALID_SIM },
    { DisconnectedReasons::RADIO_INTERNAL_ERROR, ResourceUtils::CALL_FAILED_RADIO_INTERNAL_ERROR },
    { DisconnectedReasons::NETWORK_RESP_TIMEOUT, ResourceUtils::CALL_FAILED_NETWORK_RESP_TIMEOUT },
    { DisconnectedReasons::NETWORK_REJECT, ResourceUtils::CALL_FAILED_NETWORK_REJECT },
    { DisconnectedReasons::RADIO_ACCESS_FAILURE, ResourceUtils::CALL_FAILED_RADIO_ACCESS_FAILURE },
    { DisconnectedReasons::RADIO_LINK_FAILURE, ResourceUtils::CALL_FAILED_RADIO_LINK_FAILURE },
    { DisconnectedReasons::RADIO_LINK_LOST, ResourceUtils::CALL_FAILED_RADIO_LINK_LOST },
    { DisconnectedReasons::RADIO_UPLINK_FAILURE, ResourceUtils::CALL_FAILED_RADIO_UPLINK_FAILURE },
    { DisconnectedReasons::RADIO_SETUP_FAILURE, ResourceUtils::CALL_FAILED_RADIO_SETUP_FAILURE },
    { DisconnectedReasons::RADIO_RELEASE_NORMAL, ResourceUtils::CALL_FAILED_RADIO_RELEASE_NORMAL },
    { DisconnectedReasons::RADIO_RELEASE_ABNORMAL, ResourceUtils::CALL_FAILED_RADIO_RELEASE_ABNORMAL },
    { DisconnectedReasons::ACCESS_CLASS_BLOCKED, ResourceUtils::CALL_FAILED_ACCESS_CLASS_BLOCKED },
    { DisconnectedReasons::NETWORK_DETACH, ResourceUtils::CALL_FAILED_NETWORK_DETACH },
    { DisconnectedReasons::FAILED_INVALID_PARAMETER, ResourceUtils::CALL_FAILED_INVALID_PARAMETER },
    { DisconnectedReasons::SIM_NOT_EXIT, ResourceUtils::CALL_FAILED_SIM_NOT_EXIT },
    { DisconnectedReasons::SIM_PIN_NEED, ResourceUtils::CALL_FAILED_SIM_PIN_NEED },
    { DisconnectedReasons::CALL_NOT_ALLOW, ResourceUtils::CALL_FAILED_CALL_NOT_ALLOW },
    { DisconnectedReasons::SIM_INVALID, ResourceUtils::CALL_FAILED_SIM_INVALID },
    { DisconnectedReasons::FAILED_UNKNOWN, ResourceUtils::CALL_FAILED_UNKNOWN },
};

ResourceUtils &ResourceUtils::Get()
{
    static ResourceUtils utils_;
    if (!utils_.Init()) {
        TELEPHONY_LOGD("ResourceUtils::Get init failed.");
    }
    return utils_;
}

ResourceUtils::ResourceUtils()
{
    resourceManager_ = std::unique_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager());
}

bool ResourceUtils::Init()
{
    std::lock_guard<std::mutex> locker(mutex_);
    if (beSourceAdd_) {
        return true;
    }
    if (resourceManager_ == nullptr) {
        TELEPHONY_LOGE("ResourceUtils Init failed , resourceManager is null.");
        beSourceAdd_ = false;
        return false;
    }

    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        TELEPHONY_LOGE("systemAbilityManager is null.");
        return false;
    }
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);

    sptr<AppExecFwk::IBundleMgr> iBundleMgr = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        TELEPHONY_LOGE("iBundleMgr is null.");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    iBundleMgr->GetBundleInfo(
        RESOURCE_HAP_BUNDLE_NAME.c_str(), AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, HAP_USER_ID);
    std::string hapPath;
    std::string resPath;
    if (!bundleInfo.hapModuleInfos.empty()) {
        hapPath = bundleInfo.hapModuleInfos[0].hapPath;
    }
    if (!bundleInfo.moduleResPaths.empty()) {
        resPath = bundleInfo.moduleResPaths[0];
    }

    if (IsFileExist(hapPath)) {
        beSourceAdd_ = resourceManager_->AddResource(hapPath.c_str());
        TELEPHONY_LOGI(
            "ResourceUtils add hap path %{public}d", static_cast<int32_t>(beSourceAdd_));
    } else if (IsFileExist(resPath)) {
        beSourceAdd_ = resourceManager_->AddResource(resPath.c_str());
        TELEPHONY_LOGI("ResourceUtils add resource path %{public}d", static_cast<int32_t>(beSourceAdd_));
    } else {
        TELEPHONY_LOGE("moduleResPath and moduleHapPath is invalid");
    }

    if (beSourceAdd_) {
        SaveAllValue();
    }
    return beSourceAdd_;
}

void ResourceUtils::SaveAllValue()
{
    std::string strValue;
    int32_t intValue = 0;
    bool boolValue = false;
    std::vector<std::string> strVector;
    std::vector<int32_t> intVector;
    for (auto iter : mapResourceNameType_) {
        switch (iter.second) {
            case ResourceType::ResourceTypeString:
                if (GetStringByName(iter.first.c_str(), strValue)) {
                    mapResourceValues_[iter.first] = strValue;
                    TELEPHONY_LOGE("SaveAllValue strValue %{public}s", strValue.c_str());
                }
                break;
            case ResourceType::ResourceTypeInteger:
                if (GetIntegerByName(iter.first.c_str(), intValue)) {
                    mapResourceValues_[iter.first] = intValue;
                }
                break;
            case ResourceType::ResourceTypeBoolean:
                if (GetBooleanByName(iter.first.c_str(), boolValue)) {
                    mapResourceValues_[iter.first] = boolValue;
                }
                break;
            case ResourceType::ResourceTypeArrayString:
                if (GetStringArrayByName(iter.first.c_str(), strVector)) {
                    mapResourceValues_[iter.first] = strVector;
                }
                break;
            case ResourceType::ResourceTypeArrayInteger:
                if (GetIntArrayByName(iter.first.c_str(), intVector)) {
                    mapResourceValues_[iter.first] = intVector;
                }
                break;
            default:
                break;
        }
    }
}

bool ResourceUtils::GetStringByName(std::string name, std::string &value)
{
    Global::Resource::RState state = resourceManager_->GetStringByName(name.c_str(), value);
    TELEPHONY_LOGE("GetStringByName name %{public}s", name.c_str());
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

bool ResourceUtils::GetIntegerByName(std::string name, int &value)
{
    Global::Resource::RState state = resourceManager_->GetIntegerByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

bool ResourceUtils::GetBooleanByName(std::string name, bool &value)
{
    Global::Resource::RState state = resourceManager_->GetBooleanByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

bool ResourceUtils::GetStringArrayByName(std::string name, std::vector<std::string> &value)
{
    value.clear();
    Global::Resource::RState state = resourceManager_->GetStringArrayByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

bool ResourceUtils::GetIntArrayByName(std::string name, std::vector<int32_t> &value)
{
    value.clear();
    Global::Resource::RState state = resourceManager_->GetIntArrayByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

void ResourceUtils::ShowAllValue()
{
    std::lock_guard<std::mutex> locker(mutex_);
    for (auto iter : mapResourceNameType_) {
        switch (iter.second) {
            case ResourceType::ResourceTypeString:
                TELEPHONY_LOGI("resource[%{public}s]:\"%{public}s\"", iter.first.c_str(),
                    std::any_cast<std::string>(mapResourceValues_[iter.first]).c_str());
                break;
            case ResourceType::ResourceTypeInteger:
                TELEPHONY_LOGI("resource[%{public}s]:\"%{public}d\"", iter.first.c_str(),
                    std::any_cast<int32_t>(mapResourceValues_[iter.first]));
                break;
            case ResourceType::ResourceTypeBoolean:
                TELEPHONY_LOGI("resource[%{public}s]:\"%{public}s\"", iter.first.c_str(),
                    std::any_cast<bool>(mapResourceValues_[iter.first]) ? "true" : "false");
                break;
            case ResourceType::ResourceTypeArrayString: {
                std::vector<std::string> &vecString =
                    std::any_cast<std::vector<std::string> &>(mapResourceValues_[iter.first]);
                for (unsigned int i = 0; i < vecString.size(); i++) {
                    TELEPHONY_LOGI(
                        "resource[%{public}s][%{public}d]:\"%{public}s\"", iter.first.c_str(), i, vecString[i].c_str());
                }
                break;
            }
            case ResourceType::ResourceTypeArrayInteger: {
                std::vector<int32_t> &vecInt = std::any_cast<std::vector<int32_t> &>(mapResourceValues_[iter.first]);
                for (unsigned int i = 0; i < vecInt.size(); i++) {
                    TELEPHONY_LOGI("resource[%{public}s][%{public}d]:\"%{public}d\"", iter.first.c_str(), i, vecInt[i]);
                }
                break;
            }
            default:
                break;
        }
    }
}

bool ResourceUtils::GetCallFailedMessageName(int32_t reason, std::string &name)
{
    auto itor = callFailedResourceName_.find(reason);
    if (itor == callFailedResourceName_.end()) {
        name = (callFailedResourceName_.find(DisconnectedReasons::FAILED_UNKNOWN))->second;
        return true;
    }
    name = itor->second;
    return true;
}

bool ResourceUtils::GetStringValueByName(const std::string &name, std::string &value)
{
    std::lock_guard<std::mutex> locker(mutex_);
    auto itor = mapResourceValues_.find(name);
    if (itor == mapResourceValues_.end() || !itor->second.has_value()) {
        return false;
    }
    value = std::any_cast<std::string>(itor->second);
    return true;
}

bool ResourceUtils::IsFileExist(const std::string &filePath)
{
    struct stat buffer;
    return (stat(filePath.c_str(), &buffer) == 0);
}

bool ResourceUtils::GetStringArrayValueByName(const std::string &name, std::vector<std::string> &value)
{
    std::lock_guard<std::mutex> locker(mutex_);
    auto itor = mapResourceValues_.find(name);
    if (itor == mapResourceValues_.end() || !itor->second.has_value()) {
        return false;
    }
    value = std::any_cast<std::vector<std::string>>(itor->second);
    return true;
}

bool ResourceUtils::GetBooleanValueByName(const std::string &name, bool &value)
{
    std::lock_guard<std::mutex> locker(mutex_);
    auto itor = mapResourceValues_.find(name);
    if (itor == mapResourceValues_.end() || !itor->second.has_value()) {
        return false;
    }
    value = std::any_cast<bool>(itor->second);
    return true;
}

bool ResourceUtils::GetIntegerValueByName(const std::string &name, int32_t &value)
{
    std::lock_guard<std::mutex> locker(mutex_);
    auto itor = mapResourceValues_.find(name);
    if (itor == mapResourceValues_.end() || !itor->second.has_value()) {
        return false;
    }
    value = std::any_cast<int32_t>(itor->second);
    return true;
}

bool ResourceUtils::GetIntArrayValueByName(const std::string &name, std::vector<int32_t> &value)
{
    std::lock_guard<std::mutex> locker(mutex_);
    auto itor = mapResourceValues_.find(name);
    if (itor == mapResourceValues_.end() || !itor->second.has_value()) {
        return false;
    }
    value = std::any_cast<std::vector<int32_t>>(itor->second);
    return true;
}
} // namespace Telephony
} // namespace OHOS
