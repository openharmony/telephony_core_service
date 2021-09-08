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

#include "network_information.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
void NetworkInformation::SetOperateInformation(const std::string &operatorLongName,
    const std::string &operatorShortName, const std::string &operatorNumeric, int32_t state, int32_t rat)
{
    operatorLongName_ = operatorLongName;
    operatorShortName_ = operatorShortName;
    operatorNumeric_ = operatorNumeric;
    networkPlmnState_ = static_cast<NetworkPlmnState>(state);
    rat_ = static_cast<NetworkRat>(rat);
}

int32_t NetworkInformation::GetNetworkState() const
{
    return networkPlmnState_;
}

std::string NetworkInformation::GetOperatorShortName() const
{
    return operatorShortName_;
}

std::string NetworkInformation::GetOperatorLongName() const
{
    return operatorLongName_;
}

std::string NetworkInformation::GetOperatorNumeric() const
{
    return operatorNumeric_;
}

int32_t NetworkInformation::GetRadioTech() const
{
    return rat_;
}

bool NetworkInformation::ReadFromParcel(Parcel &parcel)
{
    operatorLongName_ = Str16ToStr8(parcel.ReadString16());
    operatorShortName_ = Str16ToStr8(parcel.ReadString16());
    operatorNumeric_ = Str16ToStr8(parcel.ReadString16());

    int32_t plmnState;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, plmnState);
    networkPlmnState_ = static_cast<NetworkPlmnState>(plmnState);

    int32_t rat;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, rat);
    rat_ = static_cast<NetworkRat>(rat);
    return true;
}

bool NetworkInformation::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(operatorLongName_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(operatorShortName_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(operatorNumeric_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(networkPlmnState_));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(rat_));
    return true;
}

NetworkInformation *NetworkInformation::Unmarshalling(Parcel &parcel)
{
    NetworkInformation *networkInfo = new (std::nothrow) NetworkInformation();
    if (networkInfo == nullptr) {
        return nullptr;
    }
    if (!networkInfo->ReadFromParcel(parcel)) {
        delete networkInfo;
        networkInfo = nullptr;
    }
    return networkInfo;
}
} // namespace Telephony
} // namespace OHOS