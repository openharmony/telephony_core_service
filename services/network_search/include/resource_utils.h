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

#ifndef RESOURCE_UTILS_H
#define RESOURCE_UTILS_H

#include <string>
#include <vector>
#include <memory>
#include <any>
#include <mutex>

#include "resource_manager.h"

namespace OHOS {
namespace Telephony {
class ResourceUtils {
public:
    static const std::string IS_NOTIFY_USER_RESTRICTIED_CHANGE;
    static const std::string IS_CS_CAPABLE;
    static const std::string IS_SWITCH_PHONE_REG_CHANGE;
    static const std::string SPN_FORMATS;
    static const std::string EMERGENCY_CALLS_ONLY;
    static const std::string OUT_OF_SERIVCE;

    static ResourceUtils &Get();
    bool Init(std::string path);
    void ShowAllValue();
    ~ResourceUtils() = default;

    template<typename T>
    bool GetValueByName(std::string name, T &value);

private:
    ResourceUtils();
    void SaveAllValue();
    bool GetStringByName(std::string name, std::string &value);
    bool GetIntegerByName(std::string name, int &value);
    bool GetBooleanByName(std::string name, bool &value);
    bool GetStringArrayByName(std::string name, std::vector<std::string> &value);
    bool GetIntArrayByName(std::string name, std::vector<int32_t> &value);

private:
    std::unique_ptr<Global::Resource::ResourceManager> resourceManager_ = nullptr;
    bool beSourceAdd_ = false;
    std::map<std::string, std::any> mapResourceValues_;
    std::mutex mutex_;

    enum class ResourceType {
        ResourceTypeUnkown,
        ResourceTypeString,
        ResourceTypeInteger,
        ResourceTypeBoolean,
        ResourceTypeArrayString,
        ResourceTypeArrayInteger
    };

    static const std::map<std::string, ResourceType> mapResourceNameType_;
    static const std::string RESOURCE_HAP_BUNDLE_NAME;
    static const std::string RESOURCE_INDEX_PATH;
};

template<typename T>
bool ResourceUtils::GetValueByName(std::string name, T &value)
{
    if (mapResourceValues_.find(name) == mapResourceValues_.end()) {
        return false;
    }
    value = std::any_cast<T>(mapResourceValues_[name]);
    return true;
};
} // namespace Telephony
} // namespace OHOS

#endif