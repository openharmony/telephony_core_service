/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "operator_config_types.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
bool OperatorConfig::Marshalling(Parcel &parcel) const
{
    if (!MarshallingU16StringMap(parcel)) {
        return false;
    }
    if (!MarshallingBoolMap(parcel)) {
        return false;
    }
    if (!MarshallingStringMap(parcel)) {
        return false;
    }
    if (!MarshallingStringArrayMap(parcel)) {
        return false;
    }
    if (!MarshallingIntMap(parcel)) {
        return false;
    }
    if (!MarshallingIntArrayMap(parcel)) {
        return false;
    }
    if (!MarshallingLongMap(parcel)) {
        return false;
    }
    if (!MarshallingLongArrayMap(parcel)) {
        return false;
    }
    return true;
};

bool OperatorConfig::MarshallingU16StringMap(Parcel &parcel) const
{
    if (!parcel.WriteInt32(configValue.size())) {
        return false;
    }
    auto valueIt = configValue.begin();
    while (valueIt != configValue.end()) {
        if (!parcel.WriteString16(valueIt->first)) {
            return false;
        }
        if (!parcel.WriteString16(valueIt->second)) {
            return false;
        }
        valueIt++;
    }
    return true;
}

bool OperatorConfig::MarshallingStringMap(Parcel &parcel) const
{
    if (!parcel.WriteInt32(stringValue.size())) {
        return false;
    }
    auto valueIt = stringValue.begin();
    while (valueIt != stringValue.end()) {
        if (!parcel.WriteString(valueIt->first)) {
            return false;
        }
        if (!parcel.WriteString(valueIt->second)) {
            return false;
        }
        valueIt++;
    }
    return true;
}

bool OperatorConfig::MarshallingBoolMap(Parcel &parcel) const
{
    if (!parcel.WriteInt32(boolValue.size())) {
        return false;
    }
    auto valueIt = boolValue.begin();
    while (valueIt != boolValue.end()) {
        if (!parcel.WriteString(valueIt->first)) {
            return false;
        }
        if (!parcel.WriteBool(valueIt->second)) {
            return false;
        }
        valueIt++;
    }
    return true;
}

bool OperatorConfig::MarshallingIntMap(Parcel &parcel) const
{
    if (!parcel.WriteInt32(intValue.size())) {
        return false;
    }
    auto valueIt = intValue.begin();
    while (valueIt != intValue.end()) {
        if (!parcel.WriteString(valueIt->first)) {
            return false;
        }
        if (!parcel.WriteInt32(valueIt->second)) {
            return false;
        }
        valueIt++;
    }
    return true;
}

bool OperatorConfig::MarshallingLongMap(Parcel &parcel) const
{
    if (!parcel.WriteInt32(longValue.size())) {
        return false;
    }
    auto valueIt = longValue.begin();
    while (valueIt != longValue.end()) {
        if (!parcel.WriteString(valueIt->first)) {
            return false;
        }
        if (!parcel.WriteInt64(valueIt->second)) {
            return false;
        }
        valueIt++;
    }
    return true;
}

bool OperatorConfig::MarshallingStringArrayMap(Parcel &parcel) const
{
    if (!parcel.WriteInt32(stringArrayValue.size())) {
        return false;
    }
    auto valueIt = stringArrayValue.begin();
    while (valueIt != stringArrayValue.end()) {
        if (!parcel.WriteString(valueIt->first)) {
            return false;
        }
        if (!parcel.WriteStringVector(valueIt->second)) {
            return false;
        }
        valueIt++;
    }
    return true;
}

bool OperatorConfig::MarshallingIntArrayMap(Parcel &parcel) const
{
    if (!parcel.WriteInt32(intArrayValue.size())) {
        return false;
    }
    auto valueIt = intArrayValue.begin();
    while (valueIt != intArrayValue.end()) {
        if (!parcel.WriteString(valueIt->first)) {
            return false;
        }
        if (!parcel.WriteInt32Vector(valueIt->second)) {
            return false;
        }
        valueIt++;
    }
    return true;
}

bool OperatorConfig::MarshallingLongArrayMap(Parcel &parcel) const
{
    if (!parcel.WriteInt32(longArrayValue.size())) {
        return false;
    }
    auto valueIt = longArrayValue.begin();
    while (valueIt != longArrayValue.end()) {
        if (!parcel.WriteString(valueIt->first)) {
            return false;
        }
        if (!parcel.WriteInt64Vector(valueIt->second)) {
            return false;
        }
        valueIt++;
    }
    return true;
}

std::shared_ptr<OperatorConfig> OperatorConfig::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<OperatorConfig> param = std::make_shared<OperatorConfig>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
};

bool OperatorConfig::ReadFromParcel(Parcel &parcel)
{
    if (!ReadFromU16StringMap(parcel)) {
        return false;
    }
    if (!ReadFromBoolMap(parcel)) {
        return false;
    }
    if (!ReadFromStringMap(parcel)) {
        return false;
    }
    if (!ReadFromStringArrayMap(parcel)) {
        return false;
    }
    if (!ReadFromIntMap(parcel)) {
        return false;
    }
    if (!ReadFromIntArrayMap(parcel)) {
        return false;
    }
    if (!ReadFromLongMap(parcel)) {
        return false;
    }
    if (!ReadFromLongArrayMap(parcel)) {
        return false;
    }
    return true;
};

bool OperatorConfig::ReadFromU16StringMap(Parcel &parcel)
{
    configValue.clear();
    int32_t valueSize = parcel.ReadInt32();
    if (valueSize > MAX_CONFIG_SIZE) {
        return false;
    }
    int32_t k = 0;
    while (k < valueSize) {
        std::u16string first = parcel.ReadString16();
        std::u16string second = parcel.ReadString16();
        configValue.emplace(std::pair<std::u16string, std::u16string>(first, second));
        k++;
    }
    return true;
}

bool OperatorConfig::ReadFromStringMap(Parcel &parcel)
{
    stringValue.clear();
    int32_t valueSize = parcel.ReadInt32();
    if (valueSize > MAX_CONFIG_SIZE) {
        return false;
    }
    int32_t k = 0;
    while (k < valueSize) {
        std::string first = parcel.ReadString();
        std::string second = parcel.ReadString();
        stringValue.emplace(std::pair<std::string, std::string>(first, second));
        k++;
    }
    return true;
}

bool OperatorConfig::ReadFromIntMap(Parcel &parcel)
{
    intValue.clear();
    int32_t valueSize = parcel.ReadInt32();
    if (valueSize > MAX_CONFIG_SIZE) {
        return false;
    }
    int32_t k = 0;
    while (k < valueSize) {
        std::string first = parcel.ReadString();
        int32_t second = parcel.ReadInt32();
        intValue[first] = second;
        k++;
    }
    return true;
}

bool OperatorConfig::ReadFromBoolMap(Parcel &parcel)
{
    boolValue.clear();
    int32_t valueSize = parcel.ReadInt32();
    if (valueSize > MAX_CONFIG_SIZE) {
        return false;
    }
    int32_t k = 0;
    while (k < valueSize) {
        std::string first = parcel.ReadString();
        bool second = parcel.ReadBool();
        boolValue[first] = second;
        k++;
    }
    return true;
}
bool OperatorConfig::ReadFromLongMap(Parcel &parcel)
{
    longValue.clear();
    int32_t valueSize = parcel.ReadInt32();
    if (valueSize > MAX_CONFIG_SIZE) {
        return false;
    }
    int32_t k = 0;
    while (k < valueSize) {
        std::string first = parcel.ReadString();
        int64_t second = parcel.ReadInt64();
        longValue[first] = second;
        k++;
    }
    return true;
}
bool OperatorConfig::ReadFromStringArrayMap(Parcel &parcel)
{
    stringArrayValue.clear();
    int32_t valueSize = parcel.ReadInt32();
    if (valueSize > MAX_CONFIG_SIZE) {
        return false;
    }
    int32_t k = 0;
    while (k < valueSize) {
        std::string first = parcel.ReadString();
        std::vector<std::string> vec;
        parcel.ReadStringVector(&vec);
        stringArrayValue[first] = vec;
        k++;
    }
    return true;
}
bool OperatorConfig::ReadFromIntArrayMap(Parcel &parcel)
{
    intArrayValue.clear();
    int32_t valueSize = parcel.ReadInt32();
    if (valueSize > MAX_CONFIG_SIZE) {
        return false;
    }
    int32_t k = 0;
    while (k < valueSize) {
        std::string first = parcel.ReadString();
        std::vector<int32_t> vec;
        parcel.ReadInt32Vector(&vec);
        intArrayValue[first] = vec;
        k++;
    }
    return true;
}
bool OperatorConfig::ReadFromLongArrayMap(Parcel &parcel)
{
    longArrayValue.clear();
    int32_t valueSize = parcel.ReadInt32();
    if (valueSize > MAX_CONFIG_SIZE) {
        return false;
    }
    int32_t k = 0;
    while (k < valueSize) {
        std::string first = parcel.ReadString();
        std::vector<int64_t> vec;
        parcel.ReadInt64Vector(&vec);
        longArrayValue[first] = vec;
        k++;
    }
    return true;
}
} // namespace Telephony
} // namespace OHOS
