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
    static const std::string CONFIG_USER_NOTIFICATION_OF_RESTRICTIED_MOBILE_ACCESS;
    static const std::string CONFIG_CDMA_INTERNATIONAL_ROAMING_INDICATORS;
    static const std::string CONFIG_VOICE_CAPABLE;
    static const std::string CONFIG_SWITCH_PHONE_ON_VOICE_REG_STATE_CHANGE;
    static const std::string CONFIG_CDMA_HOME_SYSTEM;
    static const std::string WFC_SPN_FORMATS;
    static const std::string ROAMING_TEXT_SEARCHING;
    static const std::string CONFIG_LTE_ERI_FOR_NETWORK_NAME;
    static const std::string CONFIG_OPERATOR_CONSIDEREDNON_ROAMING;
    static const std::string CONFIG_SAME_NAME_DOPERATOR_CONSIDERED_ROAMING;
    static const std::string EMERGENCY_CALLS_ONLY;
    static const std::string LOCKSCREEN_CARRIER_DEFAULT;

    ResourceUtils();
    ~ResourceUtils() = default;

    bool Init(std::string path);

    template<typename T>
    bool GetValueByName(std::string name, T &value)
    {
        if (mapResourceValues_.find(name) == mapResourceValues_.end()) {
            return false;
        }
        value = std::any_cast<T>(mapResourceValues_[name]);
        return true;
    }

    void ShowAllValue();

private:
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
};
} // namespace Telephony
} // namespace OHOS

#endif