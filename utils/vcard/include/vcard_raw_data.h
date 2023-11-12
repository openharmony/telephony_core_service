/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_VCARD_RAW_DATA_H
#define OHOS_VCARD_RAW_DATA_H
#include <map>
#include <string>

namespace OHOS {
namespace Telephony {
class VCardRawData {
public:
    void SetName(const std::string &name);
    void SetRawValue(const std::string &rawValue);
    void SetValues(const std::vector<std::string> &values);
    void SetByte(const std::string &byte);
    void AppendValues(const std::vector<std::string> &values);
    void AppendGroup(const std::string &group);
    void AppendParameter(const std::string &param, const std::string &value);
    std::string GetName();
    std::string GetRawValue();
    std::string GetByte();
    std::vector<std::string> GetValue();
    std::vector<std::string> GetGroup();
    std::map<std::string, std::vector<std::string>> GetParasMap();
    std::vector<std::string> GetParameters(const std::string &key);

private:
    std::string name_;
    std::string rawValue_;
    std::string bytes_;
    std::vector<std::string> values_;
    std::vector<std::string> groups_;
    std::map<std::string, std::vector<std::string>> parasMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_RAW_DATA_H