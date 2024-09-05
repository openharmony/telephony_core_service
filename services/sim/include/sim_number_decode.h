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

#ifndef OHOS_SIM_NUMBER_DECODE_H
#define OHOS_SIM_NUMBER_DECODE_H

#include <vector>
#include <regex>
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t NEW_WIDTH = 2;
const int MAX_NUMBER_CHAR = 20;
enum SectionPosition { POS_START = 1, POS_BRACE = 2, POS_BRACKET = 3, POS_PARENTHESIS = 4, POS_END = 5 };
enum CommonConstant { MIN_LENGTH = 2, SHIFT_FLAG = 4, CHAR_START = 0xa, HALF_BYTE = 0xf, BYTE_HIGH = 0xf0 };

class SimNumberDecode final {
public:
    const static int32_t BCD_TYPE_ADN = 1;
    const static int32_t BCD_TYPE_CALLER = 2;

    static bool NumberConvertToBCD(const std::string &number, std::vector<uint8_t> &bcdCodes,
        const bool includeLen = false, const int bcdExtType = BCD_TYPE_ADN);

    static bool BCDConvertToString(const std::vector<uint8_t>::const_iterator &codeBeg,
        const std::vector<uint8_t>::const_iterator &codeEnd, std::string &number,
        const int bcdExtType = BCD_TYPE_ADN);

    static std::string BCDConvertToString(const std::shared_ptr<unsigned char> bytesData, int offset, int length,
        int bcdExtType = BCD_TYPE_ADN);

    static std::string ExtensionBCDConvertToString(const std::shared_ptr<unsigned char> bytesData, int offset,
        int length, int bcdExtType = BCD_TYPE_ADN);

    static bool IsValidNumberString(const std::string &number);

private:
    static bool BCDSectionConvertToString(const std::vector<uint8_t>::const_iterator &codeBeg,
        const std::vector<uint8_t>::const_iterator &codeEnd, std::string &number, const int bcdExtType);

    static bool CharToBCD(const char c, uint8_t &result, const int bcdExtType);

    static bool BcdToChar(const uint8_t bcdCode, char &result, const int bcdExtType);

    static const std::string *chooseExtendedByType(const int bcdExtType);

    static constexpr uint8_t FLAG_INTERNATIONAL = 0x91;
    static constexpr uint8_t FLAG_UNKNOWN = 0x81;
    inline const static std::string BCD_ADN_EXTENTION = "*#,N;";
    inline const static std::string BCD_CALLER_EXTENTION = "*#abc";
    inline constexpr static int INC_ONE = 1;
    inline constexpr static size_t EVEN = 2;
    inline constexpr static int INIT_VAL = 0;
    inline constexpr static int FOUR_BIT = 4;
    inline constexpr static uint8_t HI_FOUR = 0xf0;
    inline constexpr static uint8_t LO_FOUR = 0x0f;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_NUMBER_DECODE_H