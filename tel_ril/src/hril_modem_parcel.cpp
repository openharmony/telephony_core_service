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

#include "hril_modem_parcel.h"

namespace OHOS {
bool UniInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, gsmIndex);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, flag);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, arg1);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, arg2);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, strTmp);
    return true;
}

bool UniInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, gsmIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, flag);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, arg1);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, arg2);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, strTmp);
    return true;
}

std::shared_ptr<UniInfo> UniInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<UniInfo> param = std::make_shared<UniInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}
} // namespace OHOS