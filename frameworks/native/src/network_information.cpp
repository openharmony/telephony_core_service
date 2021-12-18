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
    return static_cast<int32_t>(networkPlmnState_);
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
    return static_cast<int32_t>(rat_);
}

bool NetworkInformation::ReadFromParcel(Parcel &parcel)
{
    operatorLongName_ = Str16ToStr8(parcel.ReadString16());
    operatorShortName_ = Str16ToStr8(parcel.ReadString16());
    operatorNumeric_ = Str16ToStr8(parcel.ReadString16());

    int32_t plmnState;
    if (!parcel.ReadInt32(plmnState)) {
        return false;
    }
    networkPlmnState_ = static_cast<NetworkPlmnState>(plmnState);

    int32_t rat;
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    rat_ = static_cast<NetworkRat>(rat);
    return true;
}

bool NetworkInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(operatorLongName_))) {
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(operatorShortName_))) {
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(operatorNumeric_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(networkPlmnState_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(rat_))) {
        return false;
    }
    return true;
}

NetworkInformation *NetworkInformation::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<NetworkInformation> networkInfo = std::make_unique<NetworkInformation>();
    if (networkInfo == nullptr) {
        return nullptr;
    }
    if (!networkInfo->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return networkInfo.release();
}
} // namespace Telephony
} // namespace OHOS
