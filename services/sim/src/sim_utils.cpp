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

#include <sstream>
#include "sim_utils.h"

#include "str_convert.h"

using namespace std;

namespace OHOS {
namespace Telephony {

static const uint8_t WORD_LEN = 2;

unsigned char SIMUtils::HexCharConvertToInt(char c)
{
    if (c >= '0' && c <= '9') {
        return (c - '0');
    } else if (c >= 'A' && c <= 'F') {
        return (c - 'A' + DECIMAL_MAX);
    } else if (c >= 'a' && c <= 'f') {
        return (c - 'a' + DECIMAL_MAX);
    }
    return 0;
}

std::shared_ptr<unsigned char> SIMUtils::HexStringConvertToBytes(const std::string &s, int &byteslen)
{
    if (s.empty()) {
        return nullptr;
    }
    int id = 0;
    int sz = static_cast<int>(s.length());
    if (sz % HALF_LEN != 0) {
        return nullptr;
    }
    int outlen = sz / HALF_LEN;
    byteslen = outlen;
    if (outlen == 0) {
        return nullptr;
    }
    unsigned char *cache = (unsigned char *)calloc(outlen + 1, sizeof(unsigned char));
    if (cache == nullptr) {
        return nullptr;
    }
    (void)memset_s(cache, (outlen + 1) * sizeof(unsigned char), 0, (outlen + 1) * sizeof(unsigned char));
    std::shared_ptr<unsigned char> ptr(cache, [](unsigned char *ptr) { free(ptr); });
    unsigned char *ret = ptr.get();
    for (int i = 0; i < sz; i += HALF_LEN) {
        id = i / HALF_LEN;
        ret[id] = (unsigned char)((HexCharConvertToInt(s.at(i)) << HALF_BYTE_LEN) | HexCharConvertToInt(s.at(i + 1)));
    }
    return ptr;
}

std::string SIMUtils::BytesConvertToHexString(const unsigned char *bytes, int byteLen)
{
    if (bytes == nullptr) {
        return "";
    }
    std::string str = "";
    for (int i = 0; i < byteLen; i++) {
        int b = 0;
        b = 0x0f & (bytes[i] >> HALF_BYTE_LEN);
        str.push_back(HEX_CHARS[b]);
        b = 0x0f & bytes[i];
        str.push_back(HEX_CHARS[b]);
    }
    return str;
}

void SIMUtils::ArrayCopy(const unsigned char *src, int srcPos, unsigned char *dest, int destPos, int length)
{
    src += srcPos;
    dest += destPos;
    for (int i = 0; i < length; i++) {
        dest[i] = src[i];
    }
}

bool SIMUtils::IsShowableAscii(char c)
{
    char asciiFirst = 0x20;
    char asciiLast = 0x7E;
    return (asciiFirst <= c && c <= asciiLast) || c == '\r' || c == '\n';
}

bool SIMUtils::IsShowableAsciiOnly(const std::string &str)
{
    int len = static_cast<int>(str.length());
    for (int i = 0; i < len; i++) {
        if (!IsShowableAscii(str.at(i))) {
            return false;
        }
    }
    return true;
}

std::shared_ptr<char16_t> SIMUtils::CharsConvertToChar16(
    const unsigned char *charBytes, int charBytesLen, int &outChar16Len, bool bigEndian)
{
    if (charBytes == nullptr || charBytesLen == 0) {
        return nullptr;
    }

    int id = 0;
    if (charBytesLen % HALF_LEN != 0) {
        return nullptr;
    }

    int outLen = charBytesLen / HALF_LEN;
    outChar16Len = outLen;
    if (outChar16Len == 0) {
        return nullptr;
    }
    char16_t *cache = (char16_t *)calloc(outLen + 1, sizeof(char16_t));
    if (cache == nullptr) {
        return nullptr;
    }
    (void)memset_s(cache, (outLen + 1) * sizeof(char16_t), 0, (outLen + 1) * sizeof(char16_t));
    std::shared_ptr<char16_t> ptr(cache, [](char16_t *ptr) { free(ptr); });
    char16_t *ret = ptr.get();
    for (int i = 0; i < charBytesLen; i += HALF_LEN) {
        id = i / HALF_LEN;
        char16_t high = charBytes[i];
        char16_t low = charBytes[i + 1];
        if (bigEndian) {
            ret[id] = (char16_t)((high << BYTE_LENGTH) | low);
        } else {
            ret[id] = (char16_t)((low << BYTE_LENGTH) | high);
        }
    }
    return ptr;
}

std::string SIMUtils::BcdPlmnConvertToString(const std::string &data, int offset)
{
    std::string plmn = "";
    if (static_cast<int>(data.size()) >= (offset + MCCMNC_LEN) && data.at(offset) != 'F') {
        plmn.push_back(data[offset + BCD_PLMN_MCC1]);
        plmn.push_back(data[offset + BCD_PLMN_MCC2]);
        plmn.push_back(data[offset + BCD_PLMN_MCC3]);
        plmn.push_back(data[offset + BCD_PLMN_MNC1]);
        plmn.push_back(data[offset + BCD_PLMN_MNC2]);
        if (data.at(offset + BCD_PLMN_MNC3) != 'F') {
            plmn.push_back(data[offset + BCD_PLMN_MNC3]);
        }
    }
    return plmn;
}

std::string SIMUtils::Gsm7bitConvertToString(const unsigned char *bytes, int byteLen)
{
    std::wstring wide_str = L"";
    int i = 0;
    int n = 0;
    int pos = 0;
    int left = 0;
    uint8_t high = 0;
    uint8_t low = 0;
    uint8_t gsmVal = 0;
    left = BYTE_LENGTH;
    n = (byteLen * BYTE_LENGTH) / CHAR_GSM_7BIT;
    TELEPHONY_LOGI("Gsm7bitConvertToString byteLen:%{public}d", byteLen);
    for (i = 0; i < n; i++) {
        if (left == BYTE_LENGTH) {
            gsmVal = bytes[pos] & (~(0xFF << (CHAR_GSM_7BIT)));
            left -= CHAR_GSM_7BIT;
        } else if (left == CHAR_GSM_7BIT) {
            gsmVal = (bytes[pos] & (0xFF << (BYTE_LENGTH - left))) >> (BYTE_LENGTH - left);
            left = BYTE_LENGTH;
            pos++;
        } else {
            low = (bytes[pos] & (unsigned char)(0xFF << (BYTE_LENGTH - left))) >> (BYTE_LENGTH - left);
            high = (bytes[pos + 1] & (unsigned char)(~(0xFF << (CHAR_GSM_7BIT - left)))) << left;
            gsmVal = low | high;
            left = BYTE_LENGTH - (CHAR_GSM_7BIT - left);
            pos++;
        }
        int gsmValIndex = static_cast<int>(gsmVal);
        if (gsmValIndex < 0 || gsmValIndex >= 129) { // 129 is gsm val index max
            continue;
        }
        wchar_t c = LANGUAGE_TABLE[gsmValIndex];
        wide_str += c;
    }
    if (byteLen > 0 && byteLen % CHAR_GSM_7BIT == 0) {
        wide_str = static_cast<int>(bytes[byteLen - 1]) > 1 ? wide_str : wide_str.substr(0, n);
    } else {
        wide_str = wide_str.substr(0, n);
    }
    TELEPHONY_LOGI("Gsm7bitConvertToString str:%{public}s", ToUtf8(wide_str).c_str());
    return ToUtf8(wide_str);
}

std::string SIMUtils::Cphs7bitConvertToString(const std::string &rawData)
{
    if (rawData.empty()) {
        return "";
    }
    const char *bytes = rawData.c_str();
    std::wstring wide_str = L"";
    int high = 0;
    int low = 0;
    int gsmVal = 0;
    int byteLen = strlen(bytes);
    bool escTag = false;
    wchar_t c;
    for (int i = 0; i < byteLen; i++) {
        low = (int)HexCharConvertToInt(bytes[i]);
        if (i + 1 < byteLen) {
            high = (int)HexCharConvertToInt(bytes[i + 1]);
        } else {
            break;
        }
        gsmVal = low * 16 + high; // 16 is the hex val max
        i++;
        if (gsmVal < 0 || gsmVal >= 129) { // 129 is gsm val index max
            continue;
        }
        if (!escTag && gsmVal == 0x1B) { // 1B is the ESC tag refer to GSM 03.38;
            escTag = true;
            continue;
        } else if (escTag && gsmVal == 0x1B) { // Two escape chars in a row We treat this as a space
                                               // See Note 1 in table 6.2.1 of TS 23.038 v7.00
            escTag = false;
            c = ' ';
            wide_str += c;
            continue;
        }
        if (escTag == true) {
            if (LANGUAGE_EXT_TABLE_MAP.find(gsmVal) != LANGUAGE_EXT_TABLE_MAP.end()) {
                c = LANGUAGE_EXT_TABLE_MAP.at(gsmVal);
                wide_str += c;
            } else {
                c = LANGUAGE_TABLE[gsmVal];
                wide_str += c;
            }
            escTag = false;
        } else {
            c = LANGUAGE_TABLE[gsmVal];
            wide_str += c;
        }
    }
    TELEPHONY_LOGI("Cphs7bitConvertToString str:%{public}s", ToUtf8(wide_str).c_str());
    return ToUtf8(wide_str);
}

std::string SIMUtils::HexVecToHexStr(const std::vector<uint8_t> &arr)
{
    std::stringstream ss;
    for (auto it = arr.begin(); it != arr.end(); it++) {
        ss << std::setiosflags(std::ios::uppercase) << std::hex << std::setw(WORD_LEN) << std::setfill('0') << int(*it);
    }
    return ss.str();
}

std::string SIMUtils::DiallingNumberStringFieldConvertToString(
    std::shared_ptr<unsigned char> array, int offset, int length, int offPos)
{
    if (offset >= length || offset < 0 || array == nullptr) {
        return "";
    }
    unsigned char *data = array.get();
    std::u16string hs = u"";
    TELEPHONY_LOGI("DiallingNumberStringFieldToString: start 16be decode");
    if (data[offset] == static_cast<unsigned char>(CHINESE_FLAG)) {
        int ucslen = (length - 1) / HALF_LEN;
        int outlen = 0;
        std::shared_ptr<char16_t> cs = CharsConvertToChar16(data + 1, ucslen * HALF_LEN, outlen, true);
        hs = std::u16string(cs.get(), 0, outlen);
    }
    if (length >= START_POS && data[offset] == static_cast<unsigned char>(UCS_FLAG)) {
        hs = UcsConvertToString(data, length, offset);
    }
    if (length >= END_POS && data[offset] == static_cast<unsigned char>(UCS_WIDE_FLAG)) {
        hs = UcsWideConvertToString(data, length, offset);
    }
    if (!hs.empty()) {
        int ucslen = static_cast<int>(hs.length());
        wchar_t c = L'\uFFFF';
        while (ucslen > 0 && hs.at(ucslen - 1) == c) {
            ucslen--;
        }
        std::u16string rtl = hs.substr(0, ucslen);
        std::string uz = Str16ToStr8(hs);
        std::string ns = Str16ToStr8(rtl);
        return ns;
    }
    std::string tempData = SIMUtils::BytesConvertToHexString(data, length);
    return Cphs7bitConvertToString(tempData);
}

std::u16string SIMUtils::UcsConvertToString(unsigned char *data, int length, int offset)
{
    if (data == nullptr || length <= offset + 1) {
        return u"";
    }
    int len = data[offset + 1] & BYTE_VALUE;
    if (len > length - START_POS) {
        len = length - START_POS;
    }
    if (len <= 0) {
        return u"";
    }
    unsigned char* dataUsc = new unsigned char[len * HALF_LEN]{ FF_DATA };
    int index = 0;
    int base = 0;
    int dataOffset = UCS_OFFSET;
    while (index < len * HALF_LEN && offset + dataOffset < length) {
        if ((data[offset + dataOffset] & F0_DATA) > 0) {
            base = (data[offset + UCS_BASE_POS] & BYTE_VALUE) << BYTE_LESS;
        } else {
            base = ZERO_DATA;
        }
        int dataDouble = base + (data[offset + dataOffset] & SEVENF_DATA);
        dataUsc[index] = dataDouble / HEX_HUNDRE;
        dataUsc[index + 1] = dataDouble % HEX_HUNDRE;
        dataOffset++;
        index = index + HALF_LEN;
    }
    int outlen = 0;
    std::shared_ptr<char16_t> cs = CharsConvertToChar16(dataUsc, len * HALF_LEN, outlen, true);
    delete[] dataUsc;
    dataUsc = nullptr;
    if (cs == nullptr) {
        TELEPHONY_LOGE("cs is nullptr");
        return u"";
    }
    return std::u16string(cs.get(), 0, outlen);
}

std::u16string SIMUtils::UcsWideConvertToString(unsigned char *data, int length, int offset)
{
    if (data == nullptr || length <= offset + 1) {
        return u"";
    }
    int len = data[offset + 1] & BYTE_VALUE;
    if (len > length - END_POS) {
        len = length - END_POS;
    }
    if (len <= 0) {
        return u"";
    }
    int base = (data[offset + UCS_BASE_POS] << BYTE_BIT) + data[offset + UCS_BASE_POS + 1];
    unsigned char* dataUsc = new unsigned char[len * HALF_LEN]{ FF_DATA };
    int dataOffset = UCS_WIDE_OFFSET;
    int index = 0;
    while (index < len * HALF_LEN && offset + dataOffset < length) {
        if ((data[offset + dataOffset] & F0_DATA) > 0) {
            int dataDouble = base + (data[offset + dataOffset] & SEVENF_DATA);
            dataUsc[index] = dataDouble / HEX_HUNDRE;
            dataUsc[index + 1] = dataDouble % HEX_HUNDRE;
        } else {
            dataUsc[index] = ZERO_DATA;
            dataUsc[index + 1] = data[offset + dataOffset];
        }
        index = index + HALF_LEN;
        dataOffset++;
    }
    int outlen = 0;
    std::shared_ptr<char16_t> cs = CharsConvertToChar16(dataUsc, len * HALF_LEN, outlen, true);
    delete[] dataUsc;
    dataUsc = nullptr;
    if (cs == nullptr) {
        TELEPHONY_LOGE("cs is nullptr");
        return u"";
    }
    return std::u16string(cs.get(), 0, outlen);
}

std::string SIMUtils::Decode8BitConvertToString(unsigned char *data, int length, int offset)
{
    if (data == nullptr || length <= offset + 1 || offset < 0) {
        return "";
    }
    int i = 0;
    for (i = offset; i < length; i++) {
        int c = data[i] & BYTE_VALUE;
        if (c == BYTE_VALUE) {
            break;
        }
    }
    i -= offset;
    std::string str(reinterpret_cast<char *>(data), offset, i);
    TELEPHONY_LOGI("Decode8BitConvertToString str:%{public}s", str.c_str());
    return str;
}

std::string SIMUtils::Trim(std::string &str)
{
    string::size_type pos = str.find_last_not_of(' ');
    if (pos != string::npos) {
        str.erase(pos + POS_NOT_BLANK);
        pos = str.find_first_not_of(' ');
        if (pos != string::npos) {
            str.erase(0, pos);
        }
    } else {
        str.erase(str.begin(), str.end());
    }
    return str;
}
} // namespace Telephony
} // namespace OHOS
