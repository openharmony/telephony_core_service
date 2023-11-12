/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License") {}
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
#include "vcard_raw_data.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

void VCardRawData::SetByte(const std::string &byte)
{
    bytes_ = byte;
}

void VCardRawData::SetName(const std::string &name)
{
    name_ = name;
}

void VCardRawData::SetRawValue(const std::string &rawValue)
{
    rawValue_ = rawValue;
}

void VCardRawData::SetValues(const std::vector<std::string> &values)
{
    values_ = values;
}

void VCardRawData::AppendValues(const std::vector<std::string> &values)
{
    values_.insert(values_.end(), values.begin(), values.end());
}

void VCardRawData::AppendGroup(const std::string &group)
{
    groups_.push_back(group);
}

void VCardRawData::AppendParameter(const std::string &param, const std::string &value)
{
    auto it = parasMap_.find(param);
    if (it != parasMap_.end()) {
        it->second.push_back(value);
    } else {
        parasMap_[param] = { value };
    }
}

std::vector<std::string> VCardRawData::GetParameters(const std::string &key)
{
    auto it = parasMap_.find(key);
    if (it != parasMap_.end()) {
        return it->second;
    }
    std::vector<std::string> emptyVector;
    return emptyVector;
}

std::string VCardRawData::GetName()
{
    return name_;
}

std::string VCardRawData::GetRawValue()
{
    return rawValue_;
}

std::string VCardRawData::GetByte()
{
    return bytes_;
}

std::vector<std::string> VCardRawData::GetValue()
{
    return values_;
}

std::vector<std::string> VCardRawData::GetGroup()
{
    return groups_;
}

std::map<std::string, std::vector<std::string>> VCardRawData::GetParasMap()
{
    return parasMap_;
}

} // namespace Telephony
} // namespace OHOS
