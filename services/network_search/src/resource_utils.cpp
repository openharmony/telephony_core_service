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

#include "resource_utils.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const std::string ResourceUtils::RESOURCE_HAP_BUNDLE_NAME = "ohos.global.systemres";
const std::string ResourceUtils::RESOURCE_INDEX_PATH = "/data/accounts/account_0/applications/" +
    ResourceUtils::RESOURCE_HAP_BUNDLE_NAME + "/" + ResourceUtils::RESOURCE_HAP_BUNDLE_NAME +
    "/assets/entry/resources.index";

const std::string ResourceUtils::IS_NOTIFY_USER_RESTRICTIED_CHANGE = "is_notify_user_restrictied_change";
const std::string ResourceUtils::IS_CS_CAPABLE = "is_cs_capable";
const std::string ResourceUtils::IS_SWITCH_PHONE_REG_CHANGE = "is_switch_phone_reg_change";
const std::string ResourceUtils::SPN_FORMATS = "spn_formats";
const std::string ResourceUtils::EMERGENCY_CALLS_ONLY = "emergency_calls_only";
const std::string ResourceUtils::OUT_OF_SERIVCE = "out_of_serivce";

const std::map<std::string, ResourceUtils::ResourceType> ResourceUtils::mapResourceNameType_ = {
    {ResourceUtils::IS_NOTIFY_USER_RESTRICTIED_CHANGE, ResourceUtils::ResourceType::ResourceTypeBoolean},
    {ResourceUtils::IS_CS_CAPABLE, ResourceUtils::ResourceType::ResourceTypeBoolean},
    {ResourceUtils::IS_SWITCH_PHONE_REG_CHANGE, ResourceUtils::ResourceType::ResourceTypeBoolean},
    {ResourceUtils::SPN_FORMATS, ResourceUtils::ResourceType::ResourceTypeArrayString},
    {ResourceUtils::EMERGENCY_CALLS_ONLY, ResourceUtils::ResourceType::ResourceTypeString},
    {ResourceUtils::OUT_OF_SERIVCE, ResourceUtils::ResourceType::ResourceTypeString},
};

ResourceUtils &ResourceUtils::Get()
{
    static ResourceUtils utils_;
    if (!utils_.Init(RESOURCE_INDEX_PATH)) {
        TELEPHONY_LOGE("ResourceUtils::Get init failed.");
    }
    return utils_;
}

ResourceUtils::ResourceUtils()
{
    resourceManager_ =
        std::unique_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager());
}

bool ResourceUtils::Init(std::string path)
{
    std::lock_guard<std::mutex> locker(mutex_);
    if (beSourceAdd_) {
        return true;
    }
    if (resourceManager_ == nullptr) {
        TELEPHONY_LOGE("ResourceUtils Init failed , resourceManager is null.  %{public}s", path.c_str());
        beSourceAdd_ = false;
        return false;
    }
    beSourceAdd_ = resourceManager_->AddResource(path.c_str());
    TELEPHONY_LOGI(
        "ResourceUtils add resource %{public}s %{public}d", path.c_str(), static_cast<int32_t>(beSourceAdd_));
    if (beSourceAdd_) {
        SaveAllValue();
    }
    return beSourceAdd_;
}

void ResourceUtils::SaveAllValue()
{
    std::string strValue;
    int32_t intValue = 0;
    bool boolValue = false;
    std::vector<std::string> strVector;
    std::vector<int32_t> intVector;
    for (auto iter : mapResourceNameType_) {
        switch (iter.second) {
            case ResourceType::ResourceTypeString:
                if (GetStringByName(iter.first.c_str(), strValue)) {
                    mapResourceValues_[iter.first] = strValue;
                }
                break;
            case ResourceType::ResourceTypeInteger:
                if (GetIntegerByName(iter.first.c_str(), intValue)) {
                    mapResourceValues_[iter.first] = intValue;
                }
                break;
            case ResourceType::ResourceTypeBoolean:
                if (GetBooleanByName(iter.first.c_str(), boolValue)) {
                    mapResourceValues_[iter.first] = boolValue;
                }
                break;
            case ResourceType::ResourceTypeArrayString:
                if (GetStringArrayByName(iter.first.c_str(), strVector)) {
                    mapResourceValues_[iter.first] = strVector;
                }
                break;
            case ResourceType::ResourceTypeArrayInteger:
                if (GetIntArrayByName(iter.first.c_str(), intVector)) {
                    mapResourceValues_[iter.first] = intVector;
                }
                break;
            default:
                break;
        }
    }
}

bool ResourceUtils::GetStringByName(std::string name, std::string &value)
{
    Global::Resource::RState state = resourceManager_->GetStringByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

bool ResourceUtils::GetIntegerByName(std::string name, int &value)
{
    Global::Resource::RState state = resourceManager_->GetIntegerByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

bool ResourceUtils::GetBooleanByName(std::string name, bool &value)
{
    Global::Resource::RState state = resourceManager_->GetBooleanByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

bool ResourceUtils::GetStringArrayByName(std::string name, std::vector<std::string> &value)
{
    value.clear();
    Global::Resource::RState state = resourceManager_->GetStringArrayByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

bool ResourceUtils::GetIntArrayByName(std::string name, std::vector<int32_t> &value)
{
    value.clear();
    Global::Resource::RState state = resourceManager_->GetIntArrayByName(name.c_str(), value);
    if (state == Global::Resource::RState::SUCCESS) {
        return true;
    } else {
        TELEPHONY_LOGE("failed to get resource by name %{public}s", name.c_str());
        return false;
    }
}

void ResourceUtils::ShowAllValue()
{
    for (auto iter : mapResourceNameType_) {
        switch (iter.second) {
            case ResourceType::ResourceTypeString:
                TELEPHONY_LOGI("resource[%{public}s]:\"%{public}s\"", iter.first.c_str(),
                    std::any_cast<std::string>(mapResourceValues_[iter.first]).c_str());
                break;
            case ResourceType::ResourceTypeInteger:
                TELEPHONY_LOGI("resource[%{public}s]:\"%{public}d\"", iter.first.c_str(),
                    std::any_cast<int32_t>(mapResourceValues_[iter.first]));
                break;
            case ResourceType::ResourceTypeBoolean:
                TELEPHONY_LOGI("resource[%{public}s]:\"%{public}s\"", iter.first.c_str(),
                    std::any_cast<bool>(mapResourceValues_[iter.first]) ? "true" : "false");
                break;
            case ResourceType::ResourceTypeArrayString: {
                std::vector<std::string> &vecString =
                    std::any_cast<std::vector<std::string> &>(mapResourceValues_[iter.first]);
                for (unsigned int i = 0; i < vecString.size(); i++) {
                    TELEPHONY_LOGI("resource[%{public}s][%{public}d]:\"%{public}s\"", iter.first.c_str(), i,
                        vecString[i].c_str());
                }
                break;
            }
            case ResourceType::ResourceTypeArrayInteger: {
                std::vector<int32_t> &vecInt =
                    std::any_cast<std::vector<int32_t> &>(mapResourceValues_[iter.first]);
                for (unsigned int i = 0; i < vecInt.size(); i++) {
                    TELEPHONY_LOGI(
                        "resource[%{public}s][%{public}d]:\"%{public}d\"", iter.first.c_str(), i, vecInt[i]);
                }
                break;
            }
            default:
                break;
        }
    }
}
} // namespace Telephony
} // namespace OHOS
