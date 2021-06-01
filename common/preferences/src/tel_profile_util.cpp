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
#include "tel_profile_util.h"
#include "preferences_helper.h"

namespace OHOS {
namespace TelephonyCommon {
TelProfileUtil::TelProfileUtil() {}
TelProfileUtil::~TelProfileUtil() {}

std::shared_ptr<NativePreferences::Preferences> TelProfileUtil::GetProfiles(const std::string &path, int &errCode)
{
    return NativePreferences::PreferencesHelper::GetPreferences(path, errCode);
}

int TelProfileUtil::DeleteProfiles()
{
    return NativePreferences::PreferencesHelper::DeletePreferences(path_);
}

int TelProfileUtil::SaveString(const std::string &key, const std::string &value)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->PutString(key, value);
}

std::string TelProfileUtil::ObtainString(const std::string &key, const std::string &defValue)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return error_;
    }
    return ptr->GetString(key, defValue);
}

int TelProfileUtil::SaveInt(const std::string &key, int value)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->PutInt(key, value);
}

int TelProfileUtil::ObtainInt(const std::string &key, int defValue)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->GetInt(key, defValue);
}

int TelProfileUtil::SaveBool(const std::string &key, bool value)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->PutBool(key, value);
}

int TelProfileUtil::ObtainBool(const std::string &key, int defValue)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->GetBool(key, defValue);
}

int TelProfileUtil::SaveLong(const std::string &key, int64_t value)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->PutLong(key, value);
}

int64_t TelProfileUtil::ObtainLong(const std::string &key, int64_t defValue)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->GetLong(key, defValue);
}

int TelProfileUtil::SaveFloat(const std::string &key, float value)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->PutFloat(key, value);
}

float TelProfileUtil::ObtainFloat(const std::string &key, float defValue)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->GetFloat(key, defValue);
}

bool TelProfileUtil::IsExistKey(const std::string &key)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->HasKey(key);
}

int TelProfileUtil::RemoveKey(const std::string &key)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->Delete(key);
}

int TelProfileUtil::RemoveAll()
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->Clear();
}

void TelProfileUtil::Refresh()
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr != nullptr) {
        ptr->Flush();
    }
}

int TelProfileUtil::RefreshSync()
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr == nullptr) {
        return NativePreferences::E_ERROR;
    }
    return ptr->FlushSync();
}

void TelProfileUtil::RegisterObserver(std::shared_ptr<NativePreferences::PreferencesObserver> preferencesObserver)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr != nullptr) {
        ptr->RegisterObserver(preferencesObserver);
    }
}

void TelProfileUtil::UnRegisterObserver(std::shared_ptr<NativePreferences::PreferencesObserver> preferencesObserver)
{
    std::shared_ptr<NativePreferences::Preferences> ptr = GetProfiles(path_, errCode_);
    if (ptr != nullptr) {
        ptr->UnRegisterObserver(preferencesObserver);
    }
}
} // namespace TelephonyCommon
} // namespace OHOS