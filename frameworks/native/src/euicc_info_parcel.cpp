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

#include "euicc_info_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool EuiccInfo::ReadFromParcel(Parcel &parcel)
{
    return parcel.ReadString16(osVersion_) && parcel.ReadString16(response_);
}

bool EuiccInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString16(osVersion_) && parcel.WriteString16(response_);
}

EuiccInfo *EuiccInfo::Unmarshalling(Parcel &parcel)
{
    EuiccInfo *info = new (std::nothrow) EuiccInfo();
    if (info == nullptr) {
        return nullptr;
    }
    if (!info->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("Euiccinfo:read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // namespace OHOS
} // namespace Telephony
