/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef ASN1_UTIL_H
#define ASN1_UTIL_H

#include <cstdbool>
#include <cstdint>
#include <list>
#include <vector>
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class Asn1Utils {
public:
    static bool IsConstructedTag(uint32_t tag);
    static uint32_t CalculateEncodedBytesNumForLength(uint32_t length);
    static uint32_t ByteCountForUint(uint32_t value);
    static void BchToString(const std::vector<uint8_t> &src, std::string &destStr);
    static void BcdToBytes(const std::string &bcd, std::vector<uint8_t> &bytes);
    static std::string BytesToHexStr(const std::vector<uint8_t> &bytes);
    static std::vector<uint8_t> HexStrToBytes(const std::string &hexStr);
    static uint32_t UintToBytes(const uint32_t value, std::vector<uint8_t> &bytes);
    static uint32_t IntToBytes(int32_t value, std::vector<uint8_t> &dest);
    static std::string BytesToString(const std::vector<uint8_t> &src);
    static std::string HexStrToString(const std::string &hexStr);
    static std::vector<uint8_t> StringToBytes(const std::string &src);
    static bool BytesToInt(const std::vector<uint8_t> &src, uint32_t offset, uint32_t length, int32_t &valInt);
    static uint8_t CountTrailingZeros(const uint8_t value);
    static uint32_t ReverseInt(uint32_t value);
    static uint32_t ByteToHexStr(uint8_t src, std::string &dest);

private:
    static std::string SwapHexCharPair(const std::string &hexStr);
    static std::string StrToHexStr(const std::string& str);
    static uint32_t ByteCountForInt(uint32_t value, bool isSigned);
};
} // namespace Telephony
} // namespace OHOS
#endif // ASN1_UTIL_H_
