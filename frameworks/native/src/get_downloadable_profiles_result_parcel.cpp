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

#include "get_downloadable_profiles_result_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool GetDownloadableProfilesResult::ReadFromParcel(Parcel &parcel)
{
    int32_t resultValue = static_cast<int32_t>(result_);
    if (!parcel.ReadInt32(resultValue)) {
        return false;
    }

    uint32_t size;
    if (!parcel.ReadUint32(size)) {
        return false;
    }
    downloadableProfiles_.resize(size);
    for (auto &profile : downloadableProfiles_) {
        if (!parcel.ReadString16(profile.encodedActivationCode_) ||
            !parcel.ReadString16(profile.confirmationCode_) ||
            !parcel.ReadString16(profile.carrierName_)) {
            return false;
        }

        uint32_t count;
        if (!parcel.ReadUint32(count)) {
            return false;
        }
        profile.accessRules_.resize(count);
        for (auto &rule : profile.accessRules_) {
            if (!parcel.ReadString16(rule.certificateHashHexStr_) ||
                !parcel.ReadString16(rule.packageName_) ||
                !parcel.ReadInt32(rule.accessType_)) {
                return false;
            }
        }
    }
    return true;
}

bool GetDownloadableProfilesResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(result_)) ||
        !parcel.WriteUint32(static_cast<uint32_t>(downloadableProfiles_.size()))) {
        return false;
    }

    for (const auto &profile : downloadableProfiles_) {
        if (!parcel.WriteString16(profile.encodedActivationCode_) ||
            !parcel.WriteString16(profile.confirmationCode_) ||
            !parcel.WriteString16(profile.carrierName_) ||
            !parcel.WriteUint32(static_cast<uint32_t>(profile.accessRules_.size()))) {
            return false;
        }

        for (const auto &rule : profile.accessRules_) {
            if (!parcel.WriteString16(rule.certificateHashHexStr_) ||
                !parcel.WriteString16(rule.packageName_) ||
                !parcel.WriteInt32(rule.accessType_)) {
                return false;
            }
        }
    }
    return true;
}

GetDownloadableProfilesResult *GetDownloadableProfilesResult::Unmarshalling(Parcel &parcel)
{
    GetDownloadableProfilesResult *downloadableProfilesResult = new (std::nothrow) GetDownloadableProfilesResult();
    if (downloadableProfilesResult == nullptr) {
        return nullptr;
    }
    if (!downloadableProfilesResult->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("GetDownloadableProfilesResult:read from parcel failed");
        delete downloadableProfilesResult;
        downloadableProfilesResult = nullptr;
    }
    return downloadableProfilesResult;
}
} // namespace OHOS
} // namespace Telephony
