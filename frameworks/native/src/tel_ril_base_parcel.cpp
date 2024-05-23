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

#include "tel_ril_base_parcel.h"

namespace OHOS {
namespace Telephony {
namespace BaseParcel {
bool Read(Parcel &parcel, int8_t &value)
{
    return parcel.ReadInt8(value);
}

bool Read(Parcel &parcel, uint8_t &value)
{
    return parcel.ReadUint8(value);
}

bool Read(Parcel &parcel, int32_t &value)
{
    return parcel.ReadInt32(value);
}

bool Read(Parcel &parcel, uint32_t &value)
{
    return parcel.ReadUint32(value);
}

bool Read(Parcel &parcel, int64_t &value)
{
    return parcel.ReadInt64(value);
}

bool Read(Parcel &parcel, uint64_t &value)
{
    return parcel.ReadUint64(value);
}

bool Read(Parcel &parcel, bool &value)
{
    return parcel.ReadBool(value);
}

bool Read(Parcel &parcel, std::string &value)
{
    return parcel.ReadString(value);
}

bool Write(Parcel &parcel, const int8_t &value)
{
    return parcel.WriteInt8(value);
}

bool Write(Parcel &parcel, const uint8_t &value)
{
    return parcel.WriteUint8(value);
}

bool Write(Parcel &parcel, const int32_t &value)
{
    return parcel.WriteInt32(value);
}

bool Write(Parcel &parcel, const uint32_t &value)
{
    return parcel.WriteUint32(value);
}

bool Write(Parcel &parcel, const int64_t &value)
{
    return parcel.WriteInt64(value);
}

bool Write(Parcel &parcel, const uint64_t &value)
{
    return parcel.WriteUint64(value);
}

bool Write(Parcel &parcel, const bool &value)
{
    return parcel.WriteBool(value);
}

bool Write(Parcel &parcel, const std::string &value)
{
    return parcel.WriteString(value);
}
} // BaseParcel

bool TelRilBaseParcel::ReadBaseUint8(Parcel &parcel, uint8_t &value)
{
    return parcel.ReadUint8(value);
}

bool TelRilBaseParcel::ReadBaseInt32(Parcel &parcel, int32_t &value)
{
    return parcel.ReadInt32(value);
}

bool TelRilBaseParcel::ReadBaseInt64(Parcel &parcel, int64_t &value)
{
    return parcel.ReadInt64(value);
}

bool TelRilBaseParcel::ReadBaseBool(Parcel &parcel, bool &value)
{
    return parcel.ReadBool(value);
}

bool TelRilBaseParcel::ReadBaseString(Parcel &parcel, std::string &value)
{
    return parcel.ReadString(value);
}

bool TelRilBaseParcel::WriteBaseUint8(Parcel &parcel, uint8_t value) const
{
    return parcel.WriteUint8(value);
}

bool TelRilBaseParcel::WriteBaseInt32(Parcel &parcel, int32_t value) const
{
    return parcel.WriteInt32(value);
}

bool TelRilBaseParcel::WriteBaseInt64(Parcel &parcel, int64_t value) const
{
    return parcel.WriteInt64(value);
}

bool TelRilBaseParcel::WriteBaseBool(Parcel &parcel, bool value) const
{
    return parcel.WriteBool(value);
}

bool TelRilBaseParcel::WriteBaseString(Parcel &parcel, std::string value) const
{
    return parcel.WriteString(value);
}

std::stringstream &TelRilBaseParcel::StringStream(void) const
{
    thread_local std::stringstream ss;
    ss.str("");
    return ss;
}

std::string &TelRilBaseParcel::String(void) const
{
    thread_local std::string out = "";
    out = "";
    return out;
}

const char *TelRilBaseParcel::ToString(void) const
{
    std::string &str = String();
    str = "[omitted by default...]";
    return str.c_str();
}
} // namespace Telephony
} // namespace OHOS