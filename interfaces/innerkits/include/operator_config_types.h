/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_OPERATOR_CONFIG_TYPES_H
#define TELEPHONY_OPERATOR_CONFIG_TYPES_H

#include <map>
#include <string>
#include <vector>
#include "parcel.h"

namespace OHOS {
namespace Telephony {
const std::string BROADCAST_ARG_SLOT_ID = "slotId";
const std::string KEY_EMERGENCY_CALL_STRING_ARRAY = "emergency_call_string_array";
const int32_t DEFAULT_CALL_WAITING_SERVICE_CLASS_CONFIG = 1;
const std::vector<std::string> IMS_CALL_DISCONNECT_REASONINFO_MAPPING_CONFIG = std::vector<std::string> {};
const int32_t CARRIER_NR_AVAILABILITY_NSA = 1;
const int32_t CARRIER_NR_AVAILABILITY_SA = 2;
constexpr const char *KEY_IMS_SWITCH_ON_BY_DEFAULT_BOOL = "ims_switch_on_by_default_bool";
constexpr const char *KEY_HIDE_IMS_SWITCH_BOOL = "hide_ims_switch_bool";
constexpr const char *KEY_VOLTE_SUPPORTED_BOOL = "volte_supported_bool";
constexpr const char *KEY_NR_MODE_SUPPORTED_LIST_INT_ARRAY = "nr_mode_supported_list_int_array";
constexpr const char *KEY_VOLTE_PROVISIONING_SUPPORTED_BOOL = "volte_provisioning_supported_bool";
constexpr const char *KEY_SS_OVER_UT_SUPPORTED_BOOL = "ss_over_ut_supported_bool";
constexpr const char *KEY_IMS_GBA_REQUIRED_BOOL = "ims_gba_required_bool";
constexpr const char *KEY_UT_PROVISIONING_SUPPORTED_BOOL = "ut_provisioning_supported_bool";
constexpr const char *KEY_IMS_PREFER_FOR_EMERGENCY_BOOL = "ims_prefer_for_emergency_bool";
constexpr const char *KEY_CALL_WAITING_SERVICE_CLASS_INT = "call_waiting_service_class_int";
constexpr const char *KEY_IMS_CALL_DISCONNECT_REASONINFO_MAPPING_STRING_ARRAY =
    "ims_call_disconnect_reasoninfo_mapping_string_array";
constexpr const char *KEY_FORCE_VOLTE_SWITCH_ON_BOOL = "force_volte_switch_on_bool";
/**
 * If true, customize the items related to operator name.
 */
constexpr const char *KEY_ENABLE_OPERATOR_NAME_CUST_BOOL = "enable_operator_name_cust_bool";
/**
 * Customize the operatoer name if #KEY_ENABLE_OPERATOR_NAME_CUST_BOOL is true.
 */
constexpr const char *KEY_OPERATOR_NAME_CUST_STRING = "operator_name_cust_string";
/**
 * Customize the SPN Display Condition bits if #KEY_ENABLE_OPERATOR_NAME_CUST_BOOL is true. The default value '-1' means
 * this field is not set.
 * b1 = 0: display of registered PLMN name not required when registered PLMN is either HPLMN or a PLMN in the service
 * provider PLMN list (see EF_SPDI).
 * b1 = 1: display of registered PLMN name required when registered PLMN is either HPLMN or a PLMN in the service
 * provider PLMN list(see EF_SPDI).
 * b2 = 0: display of the service provider name required when registered PLMN is neither HPLMN nor a PLMN in the
 * service provider PLMN list(see EF_SPDI).
 * b2 = 1: display of the service provider name not required when registered PLMN is neither HPLMN nor a PLMN in the
 * service provider PLMN list(see EF_SPDI).
 *
 * See 3GPP TS 31.102 v15.2.0 Section 4.2.12 EF_SPN.
 */
constexpr const char *KEY_SPN_DISPLAY_CONDITION_CUST_INT = "spn_display_condition_cust_int";
/**
 * Customize the PNN - a string array of comma-separated long and short names:
 * "long_name1,short_name1".
 *
 * See 3GPP TS 31.102 v15.2.0 Section 4.2.58 EF_PNN.
 */
constexpr const char *KEY_PNN_CUST_STRING_ARRAY = "pnn_cust_string_array";
/**
 * Customize the OPL - a string array of OPL records, each with comma-delimited data fields as follows:
 * "plmn1,lac_start,lac_end,index".
 *
 * See 3GPP TS 31.102 v15.2.0 Section 4.2.59 EF_OPL.
 */
constexpr const char *KEY_OPL_CUST_STRING_ARRAY = "opl_cust_string_array";
/**
 * Indicates whether a modem is used as the bandwidth reporting source.
 */
constexpr const char *KEY_BANDWIDTH_SOURCE_USE_MODEM_BOOL = "bandwidth_source_use_modem_bool";
/**
 * Indicates whether to use uplink bandwidth value of LTE if it is NR NSA.
 */
constexpr const char *KEY_UPLINK_BANDWIDTH_NR_NSA_USE_LTE_VALUE_BOOL = "uplink_bandwidth_nr_nsa_use_lte_value_bool";
/**
 * Indicates the uplink and downlink bandwidth values for the network.
 */
constexpr const char *KEY_BANDWIDTH_STRING_ARRAY = "bandwidth_string_array";
/**
 * Indicates the MTU size.
 */
constexpr const char *KEY_MTU_SIZE_STRING = "mtu_size_string";
/**
 * Indicates the whether support single pdp mode.
 */
constexpr const char *KEY_SINGLE_PDP_ENABLED_BOOL = "single_pdp_enabled_bool";
/**
 * Indicates the whether carry ESM information to network.
 */
constexpr const char *KEY_PLMN_ESM_FLAG_INT = "plmn_esm_flag_int";
/**
 * Indicates the whether only support single pdp radio type array.
 */
constexpr const char *KEY_SINGLE_PDP_RADIO_TYPE_INT_ARRAY = "single_pdp_radio_type_int_array";
/**
 * Indicates default value of data roaming bool.
 */
constexpr const char *KEY_DEFAULT_DATA_ROAMING_BOOL = "default_data_roaming_bool";
/**
 * Indicates the voice mail number from cust.
 */
constexpr const char *KEY_VOICE_MAIL_NUMBER_STRING = "voice_mail_number_string";
/**
 * Indicates the voice mail carrier from cust.
 */
constexpr const char *KEY_VOICE_MAIL_CARRIER_STRING = "voice_mail_carrier_string";
/**
 * Indicates the voice mail tag from cust.
 */
constexpr const char *KEY_VOICE_MAIL_TAG_STRING = "voice_mail_tag_string";
/**
 * Indicates whether to edit voice mail information to sim card.
 */
constexpr const char *KEY_VOICE_MAIL_EDIT_NOT_TO_SIM_BOOL = "voice_mail_edit_not_to_sim_bool";

struct OperatorConfig : public Parcelable {
    std::map<std::u16string, std::u16string> configValue {};
    std::map<std::string, std::string> stringValue {};
    std::map<std::string, std::vector<std::string>> stringArrayValue {};
    std::map<std::string, int32_t> intValue {};
    std::map<std::string, std::vector<int32_t>> intArrayValue {};
    std::map<std::string, int64_t> longValue {};
    std::map<std::string, std::vector<int64_t>> longArrayValue {};
    std::map<std::string, bool> boolValue {};
    const int32_t MAX_CONFIG_SIZE = 10000;
    bool Marshalling(Parcel &parcel) const;
    bool MarshallingU16StringMap(Parcel &parcel) const;
    bool MarshallingStringMap(Parcel &parcel) const;
    bool MarshallingBoolMap(Parcel &parcel) const;
    bool MarshallingIntMap(Parcel &parcel) const;
    bool MarshallingLongMap(Parcel &parcel) const;
    bool MarshallingStringArrayMap(Parcel &parcel) const;
    bool MarshallingIntArrayMap(Parcel &parcel) const;
    bool MarshallingLongArrayMap(Parcel &parcel) const;
    std::shared_ptr<OperatorConfig> UnMarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);
    bool ReadFromU16StringMap(Parcel &parcel);
    bool ReadFromStringMap(Parcel &parcel);
    bool ReadFromIntMap(Parcel &parcel);
    bool ReadFromBoolMap(Parcel &parcel);
    bool ReadFromLongMap(Parcel &parcel);
    bool ReadFromStringArrayMap(Parcel &parcel);
    bool ReadFromIntArrayMap(Parcel &parcel);
    bool ReadFromLongArrayMap(Parcel &parcel);
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_OPERATOR_CONFIG_TYPES_H
