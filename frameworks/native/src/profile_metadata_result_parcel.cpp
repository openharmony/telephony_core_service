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

#include "profile_metadata_result_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr uint32_t MAX_SIZE = 1000;
bool GetDownloadableProfileMetadataResult::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString16(downloadableProfiles_.encodedActivationCode_) ||
        !parcel.ReadString16(downloadableProfiles_.confirmationCode_) ||
        !parcel.ReadString16(downloadableProfiles_.carrierName_)) {
        return false;
    }
    uint32_t size;
    if (!parcel.ReadUint32(size)) {
        return false;
    }

    if (size > MAX_SIZE) {
        TELEPHONY_LOGE("over max size");
        return false;
    }
    downloadableProfiles_.accessRules_.resize(size);
    for (auto &rule : downloadableProfiles_.accessRules_) {
        if (!parcel.ReadString16(rule.certificateHashHexStr_) ||
            !parcel.ReadString16(rule.packageName_) ||
            !parcel.ReadInt32(rule.accessType_)) {
            return false;
        }
    }

    int32_t resolvableErrorsValue;
    int32_t resultValue;
    int32_t profileClassValue;
    if (!parcel.ReadInt32(pprType_) || !parcel.ReadBool(pprFlag_) ||
        !parcel.ReadInt32(resolvableErrorsValue) || !parcel.ReadInt32(resultValue) ||
        !parcel.ReadString16(serviceProviderName_) || !parcel.ReadString16(profileName_) ||
        !parcel.ReadString16(iccId_) || !parcel.ReadInt32(profileClassValue)) {
        return false;
    }
    resolvableErrors_ = static_cast<SolvableErrors>(resolvableErrorsValue);
    result_ = static_cast<EsimResultCode>(resultValue);
    profileClass_ = static_cast<ProfileClass>(profileClassValue);

    return true;
}

bool GetDownloadableProfileMetadataResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(downloadableProfiles_.encodedActivationCode_) ||
        !parcel.WriteString16(downloadableProfiles_.confirmationCode_) ||
        !parcel.WriteString16(downloadableProfiles_.carrierName_) ||
        !parcel.WriteUint32(static_cast<uint32_t>(downloadableProfiles_.accessRules_.size()))) {
        return false;
    }
    for (auto const &rule : downloadableProfiles_.accessRules_) {
        if (!parcel.WriteString16(rule.certificateHashHexStr_) ||
            !parcel.WriteString16(rule.packageName_) ||
            !parcel.WriteInt32(rule.accessType_)) {
            return false;
        }
    }

    if (!parcel.WriteInt32(pprType_) || !parcel.WriteBool(pprFlag_) ||
        !parcel.WriteInt32(static_cast<int32_t>(resolvableErrors_)) ||
        !parcel.WriteInt32(static_cast<int32_t>(result_)) || !parcel.WriteString16(serviceProviderName_) ||
        !parcel.WriteString16(profileName_) || !parcel.WriteString16(iccId_) ||
        !parcel.WriteInt32(static_cast<int32_t>(profileClass_))) {
        return false;
    }
    return true;
}

GetDownloadableProfileMetadataResult *GetDownloadableProfileMetadataResult::Unmarshalling(Parcel &parcel)
{
    GetDownloadableProfileMetadataResult *metaData = new (std::nothrow) GetDownloadableProfileMetadataResult();
    if (metaData == nullptr) {
        return nullptr;
    }
    if (!metaData->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("GetDownloadableProfileMetadataResult:read from parcel failed");
        delete metaData;
        metaData = nullptr;
    }
    return metaData;
}
} // namespace OHOS
} // namespace Telephony
