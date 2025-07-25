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

#ifndef OHOS_GET_DOWNLOADABLE_PROFILES_RESULT_PARCEL_H
#define OHOS_GET_DOWNLOADABLE_PROFILES_RESULT_PARCEL_H

#include <parcel.h>
#include <vector>

#include "downloadable_profile_parcel.h"
#include "esim_state_type.h"

namespace OHOS {
namespace Telephony {
/**
 *  @brief Series data of downloadable configuration files.
 */
struct GetDownloadableProfilesResult : public Parcelable {
    EsimResultCode result_;
    std::vector<DownloadableProfile> downloadableProfiles_{};

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static GetDownloadableProfilesResult *Unmarshalling(Parcel &parcel);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_GET_DOWNLOADABLE_PROFILES_RESULT_PARCEL_H
