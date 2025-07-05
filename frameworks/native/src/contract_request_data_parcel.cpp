/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "contract_request_data_parcel.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool ContractRequestData::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString16(publicKey_) ||
        !parcel.ReadString16(nonce_) ||
        !parcel.ReadString16(pkid_)) {
        return false;
    }
    return true;
}

bool ContractRequestData::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(publicKey_) ||
        !parcel.WriteString16(nonce_) ||
        !parcel.WriteString16(pkid_)) {
        return false;
    }
    return true;
}

ContractRequestData *ContractRequestData::Unmarshalling(Parcel &parcel)
{
    ContractRequestData *contractRequestData = new (std::nothrow) ContractRequestData();
    if (contractRequestData == nullptr) {
        return nullptr;
    }
    if (!contractRequestData->ReadFromParcel(parcel)) {
        TELEPHONY_LOGE("ContractRequestData:read from parcel failed");
        delete contractRequestData;
        contractRequestData = nullptr;
    }
    return contractRequestData;
}
} // namespace OHOS
} // namespace Telephony
