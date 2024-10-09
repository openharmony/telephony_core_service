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

#include "downloadable_profile_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool DownloadableProfile::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString16(encodedActivationCode_) || !parcel.ReadString16(confirmationCode_) ||
        !parcel.ReadString16(carrierName_)) {
        return false;
    }

    uint32_t size;
    if (!parcel.ReadUint32(size)) {
        return false;
    }

    accessRules_.resize(size);
    for (auto &rule : accessRules_) {
        if (!parcel.ReadString16(rule.certificateHashHexStr_) || !parcel.ReadString16(rule.packageName_) ||
            !parcel.ReadInt32(rule.accessType_)) {
            return false;
        }
    }
    return true;
}

bool DownloadableProfile::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(encodedActivationCode_) || !parcel.WriteString16(confirmationCode_) ||
        !parcel.WriteString16(carrierName_) ||
        !parcel.WriteUint32(static_cast<uint32_t>(accessRules_.size()))) {
        return false;
    }
    for (auto const &rule : accessRules_) {
        if (!parcel.WriteString16(rule.certificateHashHexStr_) || !parcel.WriteString16(rule.packageName_) ||
            !parcel.WriteInt32(rule.accessType_)) {
            return false;
        }
    }
    return true;
}

DownloadableProfile *DownloadableProfile::Unmarshalling(Parcel &parcel)
{
    DownloadableProfile *downloadableProfile = new (std::nothrow) DownloadableProfile();
    if (downloadableProfile == nullptr) {
        return nullptr;
    }
    if (!downloadableProfile->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("DownloadableProfile:read from parcel failed");
        delete downloadableProfile;
        downloadableProfile = nullptr;
    }
    return downloadableProfile;
}
} // namespace OHOS
} // namespace Telephony
