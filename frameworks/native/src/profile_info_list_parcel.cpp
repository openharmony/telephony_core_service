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

#include "profile_info_list_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t MAX_SIZE = 1000;
bool GetEuiccProfileInfoListResult::ReadProfileFromParcel(Parcel &parcel, EuiccProfile &profile)
{
    int32_t stateValue;
    int32_t profileClassValue;
    int32_t policyRulesValue;
    if (!parcel.ReadString16(profile.iccId_) || !parcel.ReadString16(profile.nickName_) ||
        !parcel.ReadString16(profile.serviceProviderName_) || !parcel.ReadString16(profile.profileName_) ||
        !parcel.ReadInt32(stateValue) || !parcel.ReadInt32(profileClassValue) ||
        !parcel.ReadString16(profile.carrierId_.mcc_) || !parcel.ReadString16(profile.carrierId_.mnc_) ||
        !parcel.ReadString16(profile.carrierId_.gid1_) || !parcel.ReadString16(profile.carrierId_.gid2_) ||
        !parcel.ReadInt32(policyRulesValue)) {
        return false;
    }
    profile.state_ = static_cast<ProfileState>(stateValue);
    profile.profileClass_ = static_cast<ProfileClass>(profileClassValue);
    profile.policyRules_ = static_cast<PolicyRules>(policyRulesValue);

    uint32_t count;
    if (!parcel.ReadUint32(count) || count > MAX_SIZE) {
        return false;
    }
    if (count > MAX_SIZE) {
        TELEPHONY_LOGE("over max size");
        return false;
    }
    profile.accessRules_.resize(count);
    for (auto &rule : profile.accessRules_) {
        if (!parcel.ReadString16(rule.certificateHashHexStr_) ||
            !parcel.ReadString16(rule.packageName_) || !parcel.ReadInt32(rule.accessType_)) {
            return false;
        }
    }
    return true;
}

bool GetEuiccProfileInfoListResult::ReadFromParcel(Parcel &parcel)
{
    int32_t resultValue;
    if (!parcel.ReadInt32(resultValue)) {
        return false;
    }
    result_ = static_cast<ResultState>(resultValue);

    uint32_t size;
    if (!parcel.ReadUint32(size)) {
        return false;
    }
    if (size > MAX_SIZE) {
        TELEPHONY_LOGE("over max size");
        return false;
    }
    profiles_.resize(size);
    for (auto &profile : profiles_) {
        if (!ReadProfileFromParcel(parcel, profile)) {
            return false;
        }
    }
    return true;
}

bool GetEuiccProfileInfoListResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(result_)) ||
        !parcel.WriteUint32(static_cast<uint32_t>(profiles_.size()))) {
        return false;
    }
    for (auto const &profile : profiles_) {
        int32_t stateValue = static_cast<int32_t>(profile.state_);
        int32_t profileClassValue = static_cast<int32_t>(profile.profileClass_);
        int32_t policyRulesValue = static_cast<int32_t>(profile.policyRules_);
        if (!parcel.WriteString16(profile.iccId_) ||
            !parcel.WriteString16(profile.nickName_) ||
            !parcel.WriteString16(profile.serviceProviderName_) ||
            !parcel.WriteString16(profile.profileName_) ||
            !parcel.WriteInt32(stateValue) ||
            !parcel.WriteInt32(profileClassValue) ||
            !parcel.WriteString16(profile.carrierId_.mcc_) ||
            !parcel.WriteString16(profile.carrierId_.mnc_) ||
            !parcel.WriteString16(profile.carrierId_.gid1_) ||
            !parcel.WriteString16(profile.carrierId_.gid2_) ||
            !parcel.WriteInt32(policyRulesValue) ||
            !parcel.WriteUint32(static_cast<uint32_t>(profile.accessRules_.size()))) {
            return false;
        }
        for (auto const &rule : profile.accessRules_) {
            if (!parcel.WriteString16(rule.certificateHashHexStr_) ||
                !parcel.WriteString16(rule.packageName_) ||
                !parcel.WriteInt32(rule.accessType_)) {
                return false;
            }
        }
    }
    return true;
}

GetEuiccProfileInfoListResult *GetEuiccProfileInfoListResult::Unmarshalling(Parcel &parcel)
{
    GetEuiccProfileInfoListResult *euiccProfileInfoListResult = new (std::nothrow) GetEuiccProfileInfoListResult();
    if (euiccProfileInfoListResult == nullptr) {
        return nullptr;
    }
    if (!euiccProfileInfoListResult->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("GetEuiccProfileInfoListResult:read from parcel failed");
        delete euiccProfileInfoListResult;
        euiccProfileInfoListResult = nullptr;
    }
    return euiccProfileInfoListResult;
}
} // namespace OHOS
} // namespace Telephony
