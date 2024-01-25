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

#ifndef OHOS_SIM_UTILS_H
#define OHOS_SIM_UTILS_H

#include <stdlib.h>
#include <string>

#include "event_handler.h"
#include "event_runner.h"
#include "string_ex.h"
#include "telephony_log_wrapper.h"
#include "sim_char_decode.h"

namespace OHOS {
namespace Telephony {
static const int DECIMAL_MAX = 10;
static const int HALF_LEN = 2;
static const int HALF_BYTE_LEN = 4;
static const int LAC_RANGE_LEN = 6;
static const int ZERO_DATA = 0x00;
static const int SEVENF_DATA = 0x7F;
static const int F0_DATA = 0x80;
static const int FF_DATA = 0xFF;
static const int UCS_FLAG = 0x81;
static const int UCS_WIDE_FLAG = 0x82;
static const int HEX_HUNDRE = 0x100;
static const int UCS_OFFSET = 3;
static const int UCS_WIDE_OFFSET = 4;
// Full Name IEI from TS 24.008
static const int LONG_NAME_FLAG = 0x43;
// Short Name IEI from TS 24.008
static const int SHORT_NAME_FLAG = 0x45;
static const int CHAR_GSM_7BIT = 7;
static const int UCS_BASE_POS = 2;
static const int START_POS = 3;
static const int END_POS = 4;
static const int POS_NOT_BLANK = 1;
static char HEX_CHARS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
// TS 24.008 Section 10.5.3.5a Network Name
enum {
    NETWORK_NAME_IEI,
    NETWORK_NAME_LENGTH,
    NETWORK_NAME_CODING_SCHEME,
    NETWORK_NAME_TEXT_STRING
};
// TS 31.102 Section 4.2.59.
enum {
    BCD_PLMN_MCC2,
    BCD_PLMN_MCC1,
    BCD_PLMN_MNC3,
    BCD_PLMN_MCC3,
    BCD_PLMN_MNC2,
    BCD_PLMN_MNC1,
    MCCMNC_LEN
};

class SIMUtils {
public:
    static unsigned char HexCharConvertToInt(char c);
    static std::shared_ptr<unsigned char> HexStringConvertToBytes(const std::string &s, int &byteslen);
    static std::string BytesConvertToHexString(const unsigned char *bytes, int byteLen);
    static void ArrayCopy(const unsigned char *src, int srcPos, unsigned char *dest, int destPos, int length);
    static bool IsShowableAscii(char c);
    static bool IsShowableAsciiOnly(const std::string &str);
    static std::string BcdPlmnConvertToString(const std::string &data, int offset);
    static std::string DiallingNumberStringFieldConvertToString(
        std::shared_ptr<unsigned char> array, int offset, int length, int offPos);
    static std::shared_ptr<char16_t> CharsConvertToChar16(
        const unsigned char *charBytes, int charBytesLen, int &outChar16Len, bool bigEndian);
    static std::string Trim(std::string& str);
    static std::string Gsm7bitConvertToString(const unsigned char *bytes, int byteLen);

private:
    static std::u16string UcsConvertToString(unsigned char *data, int length, int offset);
    static std::u16string UcsWideConvertToString(unsigned char *data, int length, int offset);
    static std::string Decode8BitConvertToString(unsigned char *data, int length, int offset);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_UTILS_H