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
    unsigned char *cache = (unsigned char *)calloc(outlen, sizeof(unsigned char));
    if (cache == nullptr) {
        return nullptr;
    }
    std::shared_ptr<unsigned char> ptr(cache);
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

std::string SIMUtils::BcdPlmnConvertToString(const std::string &data, int offset)
{
    (void)data;
    (void)offset;
    return "";
}
} // namespace Telephony
} // namespace OHOS