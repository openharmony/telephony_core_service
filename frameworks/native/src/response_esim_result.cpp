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

#include "response_esim_result.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool ResponseEsimResult::ReadFromParcel(Parcel &parcel)
{
    int32_t resultValue;
    if (!parcel.ReadInt32(resultValue) || !parcel.ReadString16(response_)) {
        return false;
    }
    resultCode_ = static_cast<EsimResultCode>(resultValue);
    return true;
}

bool ResponseEsimResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(resultCode_)) ||
        !parcel.WriteString16(response_)) {
        return false;
    }
    return true;
}

ResponseEsimResult *ResponseEsimResult::Unmarshalling(Parcel &parcel)
{
    ResponseEsimResult *responseEsimResult = new (std::nothrow) ResponseEsimResult();
    if (responseEsimResult == nullptr) {
        return nullptr;
    }
    if (!responseEsimResult->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("ResponseEsimResult:read from parcel failed");
        delete responseEsimResult;
        responseEsimResult = nullptr;
    }
    return responseEsimResult;
}
} // namespace OHOS
} // namespace Telephony
