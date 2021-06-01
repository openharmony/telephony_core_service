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
#ifndef OHOS_RIL_NETWORK_PARCEL_H
#define OHOS_RIL_NETWORK_PARCEL_H

#include <memory>
#include <string>
#include "parcel.h"
#include "string_ex.h"
#include "hril_types.h"

namespace OHOS {
struct OperatorInfoResult : public Parcelable {
    std::string longName;
    std::string shortName;
    std::string numeric;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<OperatorInfoResult> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

/* Voice registration status results */
struct CsRegStatusInfo : public Parcelable {
    int32_t regStatus; /* The corresponding valid registration states are NOT_REG_MT_NOT_SEARCHING_OP,
                        * "REG_HOME, NOT_REG_MT_SEARCHING_OP, REG_DENIED,  UNKNOWN, REG_ROAMING". */
    int32_t radioTechnology; /* Available voice radio technology, RMS defined by radio technology */

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<CsRegStatusInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct PsRegStatusResultInfo : public Parcelable {
    int32_t regStatus; /* valid when are is ITE UNKNOWN REG = REG, otherwise it defined in RegStatus */
    int32_t radioTechnology;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<PsRegStatusResultInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};
} // namespace OHOS
#endif // OHOS_RIL_NETWORK_PARCEL_H