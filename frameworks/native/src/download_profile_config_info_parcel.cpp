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

#include "download_profile_config_info_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool DownloadProfileConfigInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(portIndex_) ||
        !parcel.ReadBool(isSwitchAfterDownload_) ||
        !parcel.ReadBool(isForceDeactivateSim_) ||
        !parcel.ReadBool(isPprAllowed_)) {
        return false;
    }
    return true;
}

bool DownloadProfileConfigInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(portIndex_) ||
        !parcel.WriteBool(isSwitchAfterDownload_) ||
        !parcel.WriteBool(isForceDeactivateSim_) ||
        !parcel.WriteBool(isPprAllowed_)) {
        return false;
    }
    return true;
}

DownloadProfileConfigInfo *DownloadProfileConfigInfo::Unmarshalling(Parcel &parcel)
{
    DownloadProfileConfigInfo *info = new (std::nothrow) DownloadProfileConfigInfo();
    if (info == nullptr) {
        return nullptr;
    }
    if (!info->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("DownloadProfileConfigInfo:read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // namespace OHOS
} // namespace Telephony
