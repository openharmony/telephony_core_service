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
#include "hril_data_parcel.h"
#include "hril_modem_parcel.h"

namespace OHOS {
bool SetupDataCallResultInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, flag);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, state);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, retryTime);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, cid);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, active);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, type);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, netPortName);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, address);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, dns);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, gateway);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, mtu);
    return true;
}

bool SetupDataCallResultInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, flag);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, state);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, retryTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, cid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, active);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, type);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, netPortName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, address);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, dns);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, gateway);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, mtu);
    return true;
}

std::shared_ptr<SetupDataCallResultInfo> SetupDataCallResultInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<SetupDataCallResultInfo> param = std::make_shared<SetupDataCallResultInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool DataCallResultList::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    dcList.resize(size);
    for (int32_t i = 0; i < size; i++) {
        dcList[i].ReadFromParcel(parcel);
    }
    return true;
}

bool DataCallResultList::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    for (int32_t i = 0; i < size; i++) {
        dcList[i].Marshalling(parcel);
    }
    return true;
}

std::shared_ptr<DataCallResultList> DataCallResultList::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<DataCallResultList> param = std::make_shared<DataCallResultList>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool DataProfileDataInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, profileId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, apn);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, protocol);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, roamingProtocol);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, verType);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, userName);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, password);
    return true;
}

bool DataProfileDataInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, profileId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, apn);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, protocol);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, roamingProtocol);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, verType);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, userName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, password);
    return true;
}

std::shared_ptr<DataProfileDataInfo> DataProfileDataInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<DataProfileDataInfo> param = std::make_shared<DataProfileDataInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool DataProfilesInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, profilesSize);
    profiles.resize(profilesSize);
    for (int32_t i = 0; i < profilesSize; i++) {
        profiles[i].ReadFromParcel(parcel);
    }
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isRoaming);
    return true;
}

bool DataProfilesInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, profilesSize);
    for (int32_t i = 0; i < profilesSize; i++) {
        profiles[i].Marshalling(parcel);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isRoaming);
    return true;
}

std::shared_ptr<DataProfilesInfo> DataProfilesInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<DataProfilesInfo> param = std::make_shared<DataProfilesInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool DataCallInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, radioTechnology);
    dataProfileInfo.ReadFromParcel(parcel);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, modemCognitive);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, roamingAllowed);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isRoaming);
    return true;
}

bool DataCallInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, radioTechnology);
    dataProfileInfo.Marshalling(parcel);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, modemCognitive);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, roamingAllowed);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isRoaming);
    return true;
}

std::shared_ptr<DataCallInfo> DataCallInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<DataCallInfo> param = std::make_shared<DataCallInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}
} // namespace OHOS