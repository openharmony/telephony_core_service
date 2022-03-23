/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed ConvertTo in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sim_utils.h"

using namespace std;

namespace OHOS {
namespace Telephony {
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
    int sz = s.length();
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
        ret[id] =
            (unsigned char)((HexCharConvertToInt(s.at(i)) << HALF_BYTE_LEN) | HexCharConvertToInt(s.at(i + 1)));
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
    int asciiFirst = 0x20;
    int asciiLast = 0x7E;
    return (asciiFirst <= c && c <= asciiLast) || c == '\r' || c == '\n';
}

bool SIMUtils::IsShowableAsciiOnly(const std::string &str)
{
    int len = str.length();
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
    (void)data;
    (void)offset;
    return "";
}

std::string SIMUtils::DiallingNumberStringFieldConvertToString(
    std::shared_ptr<unsigned char> array, int offset, int length, int offPos)
{
    if (length <= 0 || array == nullptr) {
        return "";
    }
    unsigned char *data = array.get();

    if (data[offset] == (unsigned char)CHINESE_FLAG) {
        TELEPHONY_LOGI("DiallingNumberStringFieldToString: start 16be decode");
        int ucslen = (length - 1) / HALF_LEN;
        int outlen = 0;
        std::shared_ptr<char16_t> cs = CharsConvertToChar16(data + 1, ucslen * HALF_LEN, outlen, true);
        std::string ns = "";
        std::u16string hs(cs.get(), 0, outlen);
        std::u16string rtl = u"";
        if (!hs.empty()) {
            ucslen = hs.length();
            wchar_t c = L'\uFFFF';
            while (ucslen > 0 && hs.at(ucslen - 1) == c) {
                ucslen--;
            }
            rtl = hs.substr(0, ucslen);
            std::string uz = Str16ToStr8(hs);
            ns = Str16ToStr8(rtl);
            TELEPHONY_LOGI("16be result %{public}s, %{public}s", uz.c_str(), ns.c_str());
            return ns;
        }
    } else {
        int i = 0;
        for (i = offset; i < offset + length; i++) {
            int c = data[i] & BYTE_VALUE;
            if (c == BYTE_VALUE) {
                break;
            }
        }
        i -= offset;
        std::string str((char *)data, offset, i);
        TELEPHONY_LOGI("8bit decode result");
        if (!str.empty()) {
            return str;
        }
    }
    return UcsCodeConvertToString(array, offset, length, offPos);
}

std::string SIMUtils::UcsCodeConvertToString(
    std::shared_ptr<unsigned char> array, int offset, int length, int offPos)
{
    bool isucs2 = false;
    char base = '\0';
    int len = 0;
    unsigned char *data = array.get();
    if (length >= START_POS && data[offset] == (unsigned char)UCS_FLAG) {
        len = data[offset + 1] & BYTE_VALUE;
        if (len > length - START_POS) {
            len = length - START_POS;
        }
        base = (char)((data[offset + HALF_LEN] & BYTE_VALUE) << BYTE_LESS);
        offset += START_POS;
        isucs2 = true;
    } else if (length >= END_POS && data[offset] == (unsigned char)UCS_WIDE_FLAG) {
        len = data[offset + 1] & BYTE_VALUE;
        if (len > length - END_POS)
            len = length - END_POS;

        base =
            (char)(((data[offset + HALF_LEN] & BYTE_VALUE) << BYTE_BIT) | (data[offset + START_POS] & BYTE_VALUE));
        offset += END_POS;
        isucs2 = true;
    }

    if (isucs2) {
        std::string retuc = "";
        while (len > 0) {
            if (data[offset] < 0) {
                retuc.push_back((char)(base + (data[offset] & 0x7F)));
                offset++;
                len--;
            }
            int count = 0;
            int id = offset + count;
            while ((count < len) && (data[id] >= 0)) {
                count++;
                id = offset + count;
            }
            TELEPHONY_LOGI("start 8bit decode");
            offset += count;
            len -= count;
        }
        TELEPHONY_LOGI("isucs2 decode result %{public}s", retuc.c_str());
        return retuc;
    }

    std::string defaultCharset = "";
    TELEPHONY_LOGI("UcsCodeConvertToString finished");
    return defaultCharset;
}

std::string SIMUtils::Trim(std::string& str)
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
