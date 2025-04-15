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

#ifndef TELEPHONY_COMMON_UTILS_H
#define TELEPHONY_COMMON_UTILS_H

#include <string>

namespace OHOS {
namespace Telephony {
constexpr uint8_t DEC_TYPE = 10;
constexpr uint8_t HEX_TYPE = 16;
/**
 * @brief Indicates if the input value is a decimal number.
 *
 * @param str
 * @param value
 * @param base
 * @return Return {@code true} If the input str is a valid basedecimal number, return {@code false} otherwise.
 */
bool ConvertStrToInt(const std::string &str, int &value, uint8_t base);

/**
 * @brief Indicates if the input value is a decimal number.
 *
 * @param str
 * @param value
 * @param base
 * @return Return {@code true} If the input str is a valid basedecimal number, return {@code false} otherwise.
 */
bool ConvertStrToLong(const std::string &str, int64_t &value, uint8_t base);

/**
 * @brief Get bundle name by the calling uid.
 *
 * @return Return bundle name of the caller.
 */
std::string GetBundleName();

/**
 * @brief Indicates if the input value is a decimal number.
 *
 * @param inputValue
 * @return Return {@code true} if the input value is a decimal number, return {@code false} otherwise.
 */
bool IsValidDecValue(const std::string &inputValue);

/**
 * @brief Indicates if the input value is a hexadecimal number.
 *
 * @param inputValue
 * @return Return {@code true} if the input value is a hexadecimal number, return {@code false} otherwise.
 */
bool IsValidHexValue(const std::string &inputValue);

/**
 * @brief Get calling token id.
 *
 * @return Return token id of the caller.
 */
int32_t GetTokenID();
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_COMMON_UTILS_H