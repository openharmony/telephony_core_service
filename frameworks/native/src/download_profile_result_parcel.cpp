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

#include "download_profile_result_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool DownloadProfileResult::ReadFromParcel(Parcel &parcel)
{
    int32_t resultValue;
    int32_t resolvableErrorsValue;
    if (!parcel.ReadInt32(resultValue) ||
        !parcel.ReadInt32(resolvableErrorsValue) ||
        !parcel.ReadUint32(cardId_)) {
        return false;
    }
    result_ = static_cast<ResultCode>(resultValue);
    resolvableErrors_ = static_cast<SolvableErrors>(resolvableErrorsValue);
    return true;
}

bool DownloadProfileResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(result_)) ||
        !parcel.WriteInt32(static_cast<int32_t>(resolvableErrors_)) ||
        !parcel.WriteUint32(cardId_)) {
        return false;
    }
    return true;
}

DownloadProfileResult *DownloadProfileResult::Unmarshalling(Parcel &parcel)
{
    DownloadProfileResult *downloadProfileResult = new (std::nothrow) DownloadProfileResult();
    if (downloadProfileResult == nullptr) {
        return nullptr;
    }
    if (!downloadProfileResult->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("DownloadProfileResult:read from parcel failed");
        delete downloadProfileResult;
        downloadProfileResult = nullptr;
    }
    return downloadProfileResult;
}
} // namespace OHOS
} // namespace Telephony
