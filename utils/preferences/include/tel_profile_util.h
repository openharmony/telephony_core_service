/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef DATA_STORAGE_PREFERENCES_UTILS_H
#define DATA_STORAGE_PREFERENCES_UTILS_H

#include <string>
#include <vector>

#include "singleton.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_observer.h"

namespace OHOS {
namespace Telephony {
class TelProfileUtil {
    DECLARE_DELAYED_SINGLETON(TelProfileUtil);

public:
    int SaveString(const std::string &key, const std::string &value);
    std::string ObtainString(const std::string &key, const std::string &defValue);
    int SaveInt(const std::string &key, int value);
    int ObtainInt(const std::string &key, int defValue);
    int SaveBool(const std::string &key, bool value);
    bool ObtainBool(const std::string &key, bool defValue);
    int SaveLong(const std::string &key, int64_t value);
    int64_t ObtainLong(const std::string &key, int64_t defValue);
    int SaveFloat(const std::string &key, float value);
    float ObtainFloat(const std::string &key, float defValue);
    bool IsExistKey(const std::string &key);
    int RemoveKey(const std::string &key);
    int RemoveAll();
    void Refresh();
    int RefreshSync();
    int DeleteProfiles();

private:
    std::shared_ptr<NativePreferences::Preferences> GetProfiles(const std::string &path, int &errCode);

private:
    std::string path_ = "/data/service/el1/public/telephony/telephonyProperties.xml";
    int errCode_ = NativePreferences::E_OK;
    const std::string error_ = "error";
};
} // namespace Telephony
} // namespace OHOS
#endif // DATA_STORAGE_PREFERENCES_UTILS_H