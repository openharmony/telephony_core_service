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

#include <cstring>
#include <string>
#include <iostream>
#include <string>
#include <regex>
#include "telephony_log_wrapper.h"

#define BCD_EXTENDED_TYPE_EF_ADN 1
#define BCD_EXTENDED_TYPE_CALLED_PARTY 2
#define TOA_INTERNATIONAL 0x91
#define TOA_UNKNOWN 0x81
#define BCD_EF_ADN_EXTENDED "*#,N;"
#define BCD_CALLED_PARTY_EXTENDED "*#abc"

namespace OHOS {
namespace Telephony {
enum SectionPosition { POS_START = 1, POS_BRACE = 2, POS_BRACKET = 3, POS_PARENTHESIS = 4, POS_END = 5 };
enum CommonConstant { MIN_LENGTH = 2, SHIFT_FLAG = 4, CHAR_START = 0xa, HALF_BYTE = 0xf, BYTE_HIGH = 0xf0 };
class SimNumberDecode {
public:
    SimNumberDecode();
    ~SimNumberDecode();
    static std::shared_ptr<unsigned char> NumberConvertToBCD(const std::string &number, int &bcdLength);
    static std::shared_ptr<unsigned char> NumberConvertToBCD(
        const std::string &number, int bcdExtType, int &bcdLength);
    static std::string BCDConvertToString(const std::shared_ptr<unsigned char> bytesData, int offset, int length);
    static std::string BCDConvertToString(
        const std::shared_ptr<unsigned char> bytesData, int offset, int length, int bcdExtType);
    static std::string BCDSectionConvertToString(
        const std::shared_ptr<unsigned char> bytes, int offset, int length);
    static std::string BCDSectionConvertToString(
        const std::shared_ptr<unsigned char> bytes, int offset, int length, int bcdExtType);

private:
    static std::shared_ptr<unsigned char> NumberConvertToBCDHelper(
        const std::string &number, bool includeLength, int bcdExtType, int &bcdLength);
    static int CharToBCD(char c, int bcdExtType);
    static void InternalBCDSectionConvertToString(
        std::string &sb, std::shared_ptr<unsigned char> bytesData, int offset, int length, int bcdExtType);
    static char BcdToChar(unsigned char b, int bcdExtType);
    static void ParseSpecialNumbers(std::string &number);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_NUMBER_DECODE_H