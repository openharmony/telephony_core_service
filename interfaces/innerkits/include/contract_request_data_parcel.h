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

#ifndef OHOS_CONTRACT_REQUEST_DATA_PARCEL_H
#define OHOS_CONTRACT_REQUEST_DATA_PARCEL_H

#include <parcel.h>
#include <string>
#include <vector>

#include "esim_state_type.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Contract request data
 */
struct ContractRequestData : public Parcelable {
    std::u16string publicKey = u"";
    std::u16string nonce = u"";
    std::u16string pkid = u"";

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static ContractRequestData *Unmarshalling(Parcel &parcel);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_CONTRACT_REQUEST_DATA_PARCEL_H
