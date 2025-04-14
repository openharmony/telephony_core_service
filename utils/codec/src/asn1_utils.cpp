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

#include "asn1_utils.h"
#include <cctype>
#include <cstdio>
#include <securec.h>
#include <sstream>
#include "asn1_constants.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
namespace {
const uint32_t HEX_STR_MAX_LENGTH = 4;
const uint32_t HEX_DATA_LEN = 16;
const uint32_t OFFSET_ONE_BIT = 1;
const uint32_t OFFSET_TWO_BIT = 2;
const uint32_t OFFSET_FOUR_BIT = 4;
const uint32_t OFFSET_THREE_BYTE = 24;
const uint32_t ONE_BYTE_LENGTH = 1;
const uint32_t TWO_BYTE_LENGTH = 2;
const uint32_t THREE_BYTE_LENGTH = 3;
const uint32_t FOUR_BYTE_LENGTH = 4;
const uint8_t ZERO_VALUE_OCCPUPIED_BIT_COUNT = 8;
const uint32_t NONZERO_OCCUPIED_BITS = 7;
// For exchanging adjacent bit pairs
const uint32_t MASK_PAIRS = 0x55555555;
// For swap adjacent 4-bit blocks
const uint32_t MASK_NIBBLES = 0x33333333;
// For swap adjacent bytes
const uint32_t MASK_BYTES = 0x0f0f0f0f;
// For exchange high and low 16 bits
const uint32_t MASK_HALFWORDS = 0xff00;

const uint32_t MASK_BYTES_ONE_BYTE = 0x0F;
const uint32_t MASK_NIBBLES_ONE_BYTE = 0x33;
const uint32_t MASK_PAIRS_ONE_BYTE = 0x55;
}

bool Asn1Utils::IsConstructedTag(uint32_t tag)
{
    std::vector<uint8_t> tagBytes;
    uint32_t bytesLen = UintToBytes(tag, tagBytes);
    if (bytesLen == 0 || tagBytes.empty()) {
        TELEPHONY_LOGE("failed to transform uint data to bytes.");
        return false;
    }
    return (static_cast<uint8_t>(tagBytes[0]) & BIT6_MASK) != 0;
}

uint32_t Asn1Utils::CalculateEncodedBytesNumForLength(uint32_t length)
{
    // default length is 1 byte
    uint32_t len = 1;
    if (length > MAX_INT8) {
        len += ByteCountForUint(length);
    }
    return len;
}

uint32_t Asn1Utils::ByteCountForUint(uint32_t value)
{
    return ByteCountForInt(value, false);
}

uint32_t Asn1Utils::ByteCountForInt(uint32_t value, bool isSigned)
{
    if (isSigned) {
        if (value <= MAX_INT8) {
            return ONE_BYTE_LENGTH;
        }
        if (value <= MAX_INT16) {
            return TWO_BYTE_LENGTH;
        }
        if (value <= MAX_INT24) {
            return THREE_BYTE_LENGTH;
        }
    } else {
        if (value <= MAX_UINT8) {
            return ONE_BYTE_LENGTH;
        }
        if (value <= MAX_UINT16) {
            return TWO_BYTE_LENGTH;
        }
        if (value <= MAX_UINT24) {
            return THREE_BYTE_LENGTH;
        }
    }
    return FOUR_BYTE_LENGTH;
}

// convert bytes array to string
void Asn1Utils::BchToString(const std::vector<uint8_t> &src, std::string &destStr)
{
    std::string hexStr = BytesToHexStr(src);
    destStr = SwapHexCharPair(hexStr);
}

void Asn1Utils::BcdToBytes(const std::string &bcd, std::vector<uint8_t> &bytes)
{
    std::string hexStr = SwapHexCharPair(bcd);
    bytes = HexStrToBytes(hexStr);
}

std::string Asn1Utils::BytesToHexStr(const std::vector<uint8_t> &bytes)
{
    if (bytes.size() > MAX_BPP_LENGTH) {
        TELEPHONY_LOGE("bytes length(%{public}lu) is more than max byte.", bytes.size());
        return "";
    }
    std::ostringstream oss;
    for (size_t i = 0; i < bytes.size(); i++) {
        oss << std::hex << std::uppercase << std::setw(BYTE_TO_HEX_LEN) << std::setfill('0') << (bytes[i] & MAX_UINT8);
    }
    return oss.str();
}

uint32_t Asn1Utils::ByteToHexStr(uint8_t src, std::string &dest)
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setw(BYTE_TO_HEX_LEN) << std::setfill('0') << (src & MAX_UINT8);
    dest = oss.str();
    return static_cast<uint32_t>(dest.size());
}

std::vector<uint8_t> Asn1Utils::HexStrToBytes(const std::string& hexStr)
{
    std::vector<uint8_t> ret = {};
    if (hexStr.length() > (MAX_BPP_LENGTH * BYTE_TO_HEX_LEN)) {
        TELEPHONY_LOGE("hexStr length(%{public}lu) is more than max byte.", hexStr.length());
        return ret;
    }

    if ((hexStr.length() % BYTE_TO_HEX_LEN) != 0) {
        return ret;
    }

    for (size_t i = 0; i < hexStr.length(); i += BYTE_TO_HEX_LEN) {
        uint8_t byte = static_cast<uint8_t>(strtol((hexStr.substr(i, BYTE_TO_HEX_LEN)).c_str(),
            nullptr, HEX_DATA_LEN));
        ret.push_back(byte);
    }
    return ret;
}

bool Asn1Utils::BytesToInt(const std::vector<uint8_t> &src, uint32_t offset, uint32_t length, int32_t &valInt)
{
    if (length > HEX_STR_MAX_LENGTH || (offset + length) > src.size()) {
        TELEPHONY_LOGE("src length is more than four byte.");
        return false;
    }
    std::vector<uint8_t> subByteStream(src.begin() + offset, src.begin() + offset + length);
    std::string hexStr = BytesToHexStr(subByteStream);
    valInt = static_cast<int32_t>(strtol(hexStr.c_str(), nullptr, HEX_DATA_LEN));
    return true;
}

uint32_t Asn1Utils::UintToBytes(const uint32_t value, std::vector<uint8_t> &bytes)
{
    uint32_t len = ByteCountForInt(value, false);
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setw(len * BYTE_TO_HEX_LEN) << std::setfill('0') << value;
    std::string hexStr = oss.str();
    bytes = HexStrToBytes(hexStr);
    return len;
}

uint32_t Asn1Utils::IntToBytes(int32_t value, std::vector<uint8_t> &dest)
{
    uint32_t len = ByteCountForInt(static_cast<uint32_t>(value), true);
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setw(len * BYTE_TO_HEX_LEN) << std::setfill('0') << value;
    std::string hexStr = oss.str();
    dest = HexStrToBytes(hexStr);
    return len;
}

std::string Asn1Utils::BytesToString(const std::vector<uint8_t> &src)
{
    std::string hexStr = BytesToHexStr(src);
    std::string dest = HexStrToString(hexStr);
    return dest;
}

std::string Asn1Utils::StrToHexStr(const std::string& str)
{
    std::string inputStr = str;
    std::vector<uint8_t> bytes = {};
    for (size_t i = 0; i < inputStr.length(); i++) {
        bytes.push_back(static_cast<uint8_t>(inputStr[i]));
    }
    std::string result = BytesToHexStr(bytes);
    return result;
}

std::string Asn1Utils::HexStrToString(const std::string& hexStr)
{
    std::string inputHexStr = hexStr;
    std::vector<uint8_t> bytes = HexStrToBytes(inputHexStr);
    std::string result("");
    for (size_t i = 0; i < bytes.size(); i++) {
        result += (static_cast<char>(bytes[i]));
    }
    return result;
}

std::vector<uint8_t> Asn1Utils::StringToBytes(const std::string &src)
{
    std::string hexStr = StrToHexStr(src);
    std::vector<uint8_t> dest = HexStrToBytes(hexStr);
    return dest;
}

uint32_t Asn1Utils::ReverseInt(uint32_t value)
{
    uint32_t valueTemp = value;
    // Exchanging adjacent bit pairs
    valueTemp = ((valueTemp & MASK_PAIRS) << OFFSET_ONE_BIT) | ((valueTemp >> OFFSET_ONE_BIT) & MASK_PAIRS);
    // Swap adjacent 4-bit blocks
    valueTemp = ((valueTemp & MASK_NIBBLES) << OFFSET_TWO_BIT) | ((valueTemp >> OFFSET_TWO_BIT) & MASK_NIBBLES);
    // Swap adjacent bytes
    valueTemp = ((valueTemp & MASK_BYTES) << OFFSET_FOUR_BIT) | ((valueTemp >> OFFSET_FOUR_BIT) & MASK_BYTES);
    // Exchange high and low 16 bits
    valueTemp = (valueTemp << OFFSET_THREE_BYTE) | ((valueTemp & MASK_HALFWORDS) << OFFSET_EIGHT_BIT) |
        ((valueTemp >> OFFSET_EIGHT_BIT) & MASK_HALFWORDS) | (valueTemp >> OFFSET_THREE_BYTE);
    return valueTemp;
}

uint8_t Asn1Utils::CountTrailingZeros(const uint8_t value)
{
    if (value == 0) {
        return ZERO_VALUE_OCCPUPIED_BIT_COUNT;
    }

    uint32_t valueTemp = ((static_cast<uint32_t>(value)) & MAX_UINT8);
    // The number of bits occupied by non-zero values
    uint8_t nonZeroBitCount = static_cast<uint8_t>(NONZERO_OCCUPIED_BITS);
    if ((valueTemp & static_cast<uint32_t>(MASK_BYTES_ONE_BYTE)) != 0) {
        nonZeroBitCount -= static_cast<uint8_t>(OFFSET_FOUR_BIT);
    }
    if ((valueTemp & static_cast<uint32_t>(MASK_NIBBLES_ONE_BYTE)) != 0) {
        nonZeroBitCount -= static_cast<uint8_t>(OFFSET_TWO_BIT);
    }
    if ((valueTemp & static_cast<uint32_t>(MASK_PAIRS_ONE_BYTE)) != 0) {
        nonZeroBitCount -= static_cast<uint8_t>(OFFSET_ONE_BIT);
    }
    return nonZeroBitCount;
}

// convert bytes array to string
std::string Asn1Utils::SwapHexCharPair(const std::string &hexStr)
{
    std::string result = "";
    if (hexStr.length() > (MAX_UINT8 * BYTE_TO_HEX_LEN)) {
        return result;
    }

    std::string tmphexStr = hexStr;
    if (tmphexStr.length() % BYTE_TO_HEX_LEN != 0) {
        tmphexStr += "0";
    }
    for (size_t i = 0; i < tmphexStr.length(); i += BYTE_TO_HEX_LEN) {
        result += tmphexStr.substr(i + ONE_BYTE_LENGTH, ONE_BYTE_LENGTH);
        result += tmphexStr.substr(i, ONE_BYTE_LENGTH);
    }
    return result;
}
} // namespace Telephony
}
