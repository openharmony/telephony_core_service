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
#include "hril_call_parcel.h"
#include <pthread.h>
#include <cstdarg>
#include <memory>
#include <string>
#include <vector>
#include <securec.h>
#include "osal_mem.h"
#include "hril_modem_parcel.h"

namespace OHOS {
std::shared_ptr<DialInfo> DialInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<DialInfo> param = std::make_shared<DialInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool DialInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, address);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, clir);

    return true;
}

bool DialInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, address);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, clir);

    return true;
}

bool CallInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, state);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, index);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, typeOfAddress);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isEmpty);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isMT);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isVoice);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, remoteNumber);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, numberRemind);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, remoteName);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, nameRemind);

    return true;
}

bool CallInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, state);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, index);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, typeOfAddress);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isEmpty);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isMT);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isVoice);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, remoteNumber);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, numberRemind);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, remoteName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, nameRemind);

    return true;
}

std::shared_ptr<CallInfo> CallInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<CallInfo> param = std::make_shared<CallInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool CallInfoList::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, callSize);
    calls.resize(callSize);
    for (int32_t i = 0; i < callSize; i++) {
        calls[i].ReadFromParcel(parcel);
    }
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, flag);
    return true;
}

bool CallInfoList::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, callSize);
    for (int32_t i = 0; i < callSize; i++) {
        calls[i].Marshalling(parcel);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, flag);
    return true;
}

std::shared_ptr<CallInfoList> CallInfoList::UnMarshalling(Parcel &parcel)
{
    return nullptr;
}

bool UusData::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uusDcs);
    return true;
}

bool UusData::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uusDcs);
    return true;
}

std::shared_ptr<UusData> UusData::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<UusData> param = std::make_shared<UusData>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

void UusData::Dump(std::string, int32_t) {}
} // namespace OHOS