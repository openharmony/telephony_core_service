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

#include "telephony_common_utils.h"

#include <cstdint>
#include <regex>
#include <string>

#include "ipc_skeleton.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"

namespace OHOS {
namespace Telephony {
constexpr uint32_t INPUT_VALUE_LENGTH = 10;
constexpr uint8_t HEX_TYPE = 16;
std::string GetBundleName()
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    std::string bundleName = "";
    TelephonyPermission::GetBundleNameByUid(uid, bundleName);
    if (bundleName.empty()) {
        bundleName.append(std::to_string(uid));
        bundleName.append(std::to_string(IPCSkeleton::GetCallingPid()));
    }
    return bundleName;
}

bool IsValidDecValue(const std::string &inputValue)
{
    if (inputValue.length() > INPUT_VALUE_LENGTH) {
        TELEPHONY_LOGE("The value entered is out of range, value:%{public}s", inputValue.c_str());
        return false;
    }
    bool isValueNumber = regex_match(inputValue, std::regex("(-[\\d+]+)|(\\d+)"));
    if (isValueNumber) {
        int64_t numberValue = std::stoll(inputValue);
        if ((numberValue >= INT32_MIN) && (numberValue <= INT32_MAX)) {
            return true;
        }
    }
    TELEPHONY_LOGI("InputValue is not a decimal number");
    return false;
}

bool IsValidHexValue(const std::string &inputValue)
{
    if (inputValue.length() > INPUT_VALUE_LENGTH) {
        TELEPHONY_LOGE("The value entered is out of range, value:%{public}s", inputValue.c_str());
        return false;
    }
    bool isValueNumber = regex_match(inputValue, std::regex("0[xX][0-9a-fA-F]+"));
    if (isValueNumber) {
        int64_t numberValue = std::stoll(inputValue, nullptr, HEX_TYPE);
        if ((numberValue >= INT32_MIN) && (numberValue <= INT32_MAX)) {
            return true;
        }
    }
    TELEPHONY_LOGI("InputValue is not a hexadecimal number");
    return false;
}

int32_t GetTokenID()
{
    return static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
}
} // namespace Telephony
} // namespace OHOS