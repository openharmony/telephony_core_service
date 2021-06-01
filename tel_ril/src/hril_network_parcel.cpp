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

#include "hril_network_parcel.h"
#include <memory>
#include <string>
#include "hdf_log.h"
#include "hril_modem_parcel.h"

namespace OHOS {
std::shared_ptr<OperatorInfoResult> OperatorInfoResult::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<OperatorInfoResult> param = std::make_shared<OperatorInfoResult>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool OperatorInfoResult::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, longName);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, shortName);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, numeric);
    return true;
}

bool OperatorInfoResult::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, longName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, shortName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, numeric);
    return true;
}

bool CsRegStatusInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, regStatus);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, radioTechnology);
    return true;
}

bool CsRegStatusInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, regStatus);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, radioTechnology);
    return true;
}

std::shared_ptr<CsRegStatusInfo> CsRegStatusInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<CsRegStatusInfo> param = std::make_shared<CsRegStatusInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool PsRegStatusResultInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, regStatus);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, radioTechnology);
    return true;
}

bool PsRegStatusResultInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, regStatus);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, radioTechnology);
    return true;
}

std::shared_ptr<PsRegStatusResultInfo> PsRegStatusResultInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<PsRegStatusResultInfo> param = std::make_shared<PsRegStatusResultInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}
} // namespace OHOS