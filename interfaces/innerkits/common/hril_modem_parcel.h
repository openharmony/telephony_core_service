/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_RIL_COMMON_PARCEL_H
#define OHOS_RIL_COMMON_PARCEL_H

#include <memory>
#include <string>
#include "parcel.h"
#include "string_ex.h"
#include "hril_types.h"

namespace OHOS {
#define READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(type, parcel, data) \
    do {                                                         \
        if (!(parcel).Read##type(data)) {                        \
            return false;                                        \
        }                                                        \
    } while (0)

#define WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(type, parcel, data) \
    do {                                                          \
        if (!(parcel).Write##type(data)) {                        \
            return false;                                         \
        }                                                         \
    } while (0)

struct UniInfo : public Parcelable {
    int32_t serial;
    int32_t gsmIndex; /* Index of Global System for Mobile Communications */
    bool flag;
    int32_t arg1;
    int32_t arg2;
    std::string strTmp;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<UniInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};
} // namespace OHOS
#endif // OHOS_RIL_COMMON_PARCEL_H
