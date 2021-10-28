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

#ifndef OHOS_SIM_CHAR_DECODE_H
#define OHOS_SIM_CHAR_DECODE_H

#include <cstring>
#include <stdlib.h>
#include <string>
#include <map>
#include <iostream>
#include <iomanip>
#include <type_traits>
#include <memory>
#include "securec.h"

#include "sim_constant.h"
#include "telephony_log_wrapper.h"

#define TABLE_LENGTH 128

namespace OHOS {
namespace Telephony {
static const int MAX_CHINESE_NAME = 6;
static const int MAX_ENGLISH_NAME = 13;
static const int EMPTY = 0;
static const int CHINESE_FLAG = 0x80;
static const int CHAR_LENGTH = 2;
static const int CHAR16_LENGTH = 4;
static const int CHAR32_LENGTH = 8;
static const int ENCODE_CHAR_LENGTH = 100;
static const int BYTE_BIT = 8;
static const int BYTE_LESS = 7;

class SimCharDecode {
public:
    SimCharDecode();
    ~SimCharDecode();
    static bool IsChineseString(const std::string &str);
    template<typename tStringType, typename tTraits = typename tStringType::traits_type>
    static std::string CharCodeToSequence(const tStringType &str, bool chinese)
    {
        using char_type = typename tTraits::char_type;
        static_assert(std::is_same<char_type, char>::value || std::is_same<char_type, char16_t>::value ||
                std::is_same<char_type, char32_t>::value,
            "error");
        using unsigned_char_type = typename std::make_unsigned<char_type>::type;
        using unsigned_int_type = typename std::make_unsigned<typename tTraits::int_type>::type;
        int w = std::is_same<char, char_type>::value ? CHAR_LENGTH :
            (std::is_same<char16_t, char_type>::value ? CHAR16_LENGTH : CHAR32_LENGTH);
        char tempChar[ENCODE_CHAR_LENGTH] = {0};
        int contentLen = sizeof(tempChar);
        int flagLen = 0;
        int maxNumber = 0;
        if (memset_s(tempChar, contentLen, 0x00, contentLen) != EOK) {
            TELEPHONY_LOGE("DebugTpdu memset_s error");
            return "";
        }
        if (chinese) {
            char flag[] = "80";
            if (strcat_s(tempChar, contentLen, flag) != EOK) {
                TELEPHONY_LOGE("DebugTpdu strcat_s error");
                return "";
            }
            flagLen = strlen(flag) * sizeof(char);
            maxNumber = MAX_CHINESE_NAME;
        } else {
            maxNumber = MAX_ENGLISH_NAME;
        }
        int i = 0;
        uint8_t step = w;
        for (auto c : str) {
            auto value = static_cast<unsigned_int_type>(static_cast<unsigned_char_type>(c));
            const int len = contentLen - (i * step) - flagLen;
            if (snprintf_s(tempChar + flagLen + (i * step), len - 1, len - 1,
                (step == CHAR16_LENGTH) ? "%04X" : "%02X", value) < 0) {
                TELEPHONY_LOGE("DebugTpdu snprintf_s error");
                return "";
            }
            i++;
            if (i >= maxNumber) {
                break;
            }
        }
        std::cout << tempChar << std::endl;
        std::string result(tempChar);
        return result;
    }

private:
    static void EnableCountrySpecificEncodings();
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_SIM_CHAR_DECODE_H