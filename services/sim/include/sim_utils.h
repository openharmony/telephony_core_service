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
static wchar_t LANGUAGE_TABLE[] = {
    L'@', L'\u00a3', L'$', L'\u00a5', L'\u00e8', L'\u00e9', L'\u00f9', L'\u00ec', L'\u00f2', L'\u00c7',
    L'\n', L'\u00d8', L'\u00f8', L'\r', L'\u00c5', L'\u00e5', L'\u0394', L'_', L'\u03a6', L'\u0393',
    L'\u039b', L'\u03a9', L'\u03a0', L'\u03a8', L'\u03a3', L'\u0398', L'\u039e', L'\uffff', L'\u00c6',
    L'\u00e6', L'\u00df', L'\u00c9', L' ', L'!', L'"', L'#', L'\u00a4', L'%', L'&', L'\'', L'(',
    L')', L'*', L'+', L',', L'-', L'.', L'/', L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9', L':',
    L';', L'<', L'=', L'>', L'?', L'\u00a1', L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I',
    L'J', L'K', L'L', L'M', L'N', L'O', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z',
    L'\u00c4', L'\u00d6', L'\u00d1', L'\u00dc', L'\u00a7', L'\u00bf', L'a', L'b', L'c', L'd', L'e',
    L'f', L'g', L'h', L'i', L'j', L'k', L'l', L'm', L'n', L'o', L'p', L'q', L'r', L's', L't', L'u',
    L'v', L'w', L'x', L'y', L'z', L'\u00e4', L'\u00f6', L'\u00f1', L'\u00fc', L'\u00e0'
};
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