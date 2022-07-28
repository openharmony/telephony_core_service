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
const std::string KEY_IMS_SWITCH_ON_BY_DEFAULT_BOOL = "ims_switch_on_by_default_bool";
const std::string KEY_HIDE_IMS_SWITCH_BOOL = "hide_ims_switch_bool";
const std::string KEY_VOLTE_SUPPORTED_BOOL = "volte_supported_bool";
const std::string KEY_NR_MODE_SUPPORTED_LIST_INT_ARRAY = "nr_mode_supported_list_int_array";
const std::string KEY_VOLTE_PROVISIONING_SUPPORTED_BOOL = "volte_provisioning_supported_bool";
const std::string KEY_SS_OVER_UT_SUPPORTED_BOOL = "ss_over_ut_supported_bool";
const std::string KEY_IMS_GBA_REQUIRED_BOOL = "ims_gba_required_bool";
const std::string KEY_UT_PROVISIONING_SUPPORTED_BOOL = "ut_provisioning_supported_bool";
const std::string KEY_IMS_PREFER_FOR_EMERGENCY_BOOL = "ims_prefer_for_emergency_bool";
const std::string KEY_CALL_WAITING_SERVICE_CLASS_INT = "call_waiting_service_class_int";
const std::string KEY_IMS_CALL_DISCONNECT_REASONINFO_MAPPING_STRING_ARRAY =
    "ims_call_disconnect_reasoninfo_mapping_string_array";
const std::string KEY_FORCE_VOLTE_SWITCH_ON_BOOL = "force_volte_switch_on_bool";
struct OperatorConfig : public Parcelable {
    std::map<std::u16string, std::u16string> configValue;
    std::map<std::string, std::string> stringValue;
    std::map<std::string, std::vector<std::string>> stringArrayValue;
    std::map<std::string, int32_t> intValue;
    std::map<std::string, std::vector<int32_t>> intArrayValue;
    std::map<std::string, int64_t> longValue;
    std::map<std::string, std::vector<int64_t>> longArrayValue;
    std::map<std::string, bool> boolValue;
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
