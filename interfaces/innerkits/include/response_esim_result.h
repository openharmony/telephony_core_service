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

#ifndef OHOS_RESPONSE_ESIM_RESULT_H
#define OHOS_RESPONSE_ESIM_RESULT_H

#include <parcel.h>
#include <string>

#include "esim_state_type.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Result of a operation.
 */
struct ResponseEsimResult : public Parcelable {
    ResultCode resultCode_;
    std::u16string response_ = u"";
    int32_t sw1_ = 0;
    int32_t sw2_ = 0;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static ResponseEsimResult *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Result of a operation.
 */
struct ResponseEsimInnerResult {
    int32_t resultCode_;
    std::u16string response_ = u"";
    int32_t sw1_ = 0;
    int32_t sw2_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_RESPONSE_ESIM_RESULT_H
