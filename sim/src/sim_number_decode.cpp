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

#include "sim_number_decode.h"

using namespace std;

namespace OHOS {
namespace Telephony {
SimNumberDecode::SimNumberDecode() {}

SimNumberDecode::~SimNumberDecode() {}

std::shared_ptr<unsigned char> SimNumberDecode::NumberConvertToBCD(const std::string &number, int &bcdLength)
{
    return NumberConvertToBCD(number, BCD_EXTENDED_TYPE_EF_ADN, bcdLength);
}

std::shared_ptr<unsigned char> SimNumberDecode::NumberConvertToBCD(
    const std::string &number, int bcdExtType, int &bcdLength)
{
    return NumberConvertToBCDHelper(number, false, bcdExtType, bcdLength);
}

std::shared_ptr<unsigned char> SimNumberDecode::NumberConvertToBCDHelper(
    const std::string &number, bool includeLength, int bcdExtType, int &bcdLength)
{
    int numberLenReal = number.length();
    int numberLenEffective = numberLenReal;
    int charPos = number.find('+');
    bool hasPlus = (charPos != -1);
    if (hasPlus) {
        numberLenEffective--;
    }

    if (numberLenEffective == 0) {
        return nullptr;
    }

    int resultLen = (numberLenEffective + 1) / MIN_LENGTH;
    int extraBytes = 1;
    if (includeLength) {
        extraBytes++;
    }
    resultLen += extraBytes;
    unsigned char *cache = (unsigned char *)calloc(resultLen, sizeof(unsigned char));
    if (cache == nullptr) {
        return nullptr;
    }
    std::shared_ptr<unsigned char> resultData(cache);
    unsigned char *result = resultData.get();

    uint32_t digitCount = 0;
    for (int i = 0; i < numberLenReal; i++) {
        char c = number.at(i);
        if (c == '+') {
            continue;
        }
        int shift = ((digitCount & 0x01) == 1) ? SHIFT_FLAG : 0;
        result[extraBytes + (digitCount >> 1)] |= (unsigned char)((CharToBCD(c, bcdExtType) & 0x0F) << shift);
        digitCount++;
    }

    if ((digitCount & 0x01) == 1) {
        result[extraBytes + (digitCount >> 1)] |= BYTE_HIGH;
    }

    int offset = 0;
    if (includeLength) {
        result[offset++] = (unsigned char)(resultLen - 1);
    }
    TELEPHONY_LOGD("NumberConvertToBCDHelper %{public}d %{public}d %{public}d %{public}s", resultLen,
        numberLenReal, digitCount, result);
    bcdLength = resultLen;
    result[offset] = (unsigned char)(hasPlus ? TOA_INTERNATIONAL : TOA_UNKNOWN);
    return resultData;
}

int SimNumberDecode::CharToBCD(char c, int bcdExtType)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    std::string extended = "";
    int charPos = 0;
    if (BCD_EXTENDED_TYPE_EF_ADN == bcdExtType) {
        extended = BCD_EF_ADN_EXTENDED;
    } else if (BCD_EXTENDED_TYPE_CALLED_PARTY == bcdExtType) {
        extended = BCD_CALLED_PARTY_EXTENDED;
    }
    charPos = extended.find(c);
    if (extended.empty() || (charPos == -1)) {
        TELEPHONY_LOGE("invalid char for BCD %{public}d", c);
        return 0;
    }
    return (CHAR_START + charPos);
}

std::string SimNumberDecode::BCDConvertToString(
    const std::shared_ptr<unsigned char> bytesData, int offset, int length)
{
    return BCDConvertToString(bytesData, offset, length, BCD_EXTENDED_TYPE_EF_ADN);
}

std::string SimNumberDecode::BCDConvertToString(
    const std::shared_ptr<unsigned char> bytesData, int offset, int length, int bcdExtType)
{
    bool prependPlus = false;
    std::string ret = "";
    unsigned char *bytes = bytesData.get();

    if (length < MIN_LENGTH) {
        return "";
    }

    if ((bytes[offset] & BYTE_HIGH) == (TOA_INTERNATIONAL & BYTE_HIGH)) {
        prependPlus = true;
    }

    InternalBCDSectionConvertToString(ret, bytesData, offset + 1, length - 1, bcdExtType);

    if (prependPlus && ret.length() == 0) {
        return "";
    }

    if (prependPlus) {
        ParseSpecialNumbers(ret);
    }
    return ret;
}

void SimNumberDecode::ParseSpecialNumbers(std::string &number)
{
    std::string pattern = "(^[#*])(.*)([#*])(.*)(#)$";
    std::regex express(pattern);
    std::match_results<std::string::iterator> results;
    if (std::regex_match(number.begin(), number.end(), results, express)) {
        std::vector<std::string> vcStr;
        std::match_results<std::string::iterator>::const_iterator iter;
        for (iter = results.begin(); iter != results.end(); iter++) {
            vcStr.push_back(iter->str());
        }
        if (vcStr.empty()) {
            number = "";
            number.append(vcStr.at(POS_START));
            number.append(vcStr.at(POS_BRACKET));
            number.append(vcStr.at(POS_PARENTHESIS));
            number.append(vcStr.at(POS_END));
            number.append("+");
        } else {
            number = "";
            number.append(vcStr.at(POS_START));
            number.append(vcStr.at(POS_BRACE));
            number.append(vcStr.at(POS_BRACKET));
            number.append("+");
            number.append(vcStr.at(POS_PARENTHESIS));
            number.append(vcStr.at(POS_END));
        }
    } else {
        std::string pattern = "(^[#*])(.*)([#*])(.*)";
        std::regex express(pattern);
        std::match_results<std::string::iterator> results;
        if (std::regex_match(number.begin(), number.end(), results, express)) {
            std::vector<std::string> vcStr;
            std::match_results<std::string::iterator>::const_iterator iter;
            for (iter = results.begin(); iter != results.end(); iter++) {
                vcStr.push_back(iter->str());
            }
            number = "";
            number.append(vcStr.at(POS_START));
            number.append(vcStr.at(POS_BRACE));
            number.append(vcStr.at(POS_BRACKET));
            number.append("+");
            number.append(vcStr.at(POS_PARENTHESIS));
        } else {
            std::string retTemp = number;
            number = "";
            number.push_back('+');
            number.append(retTemp);
        }
    }
}

std::string SimNumberDecode::BCDSectionConvertToString(
    const std::shared_ptr<unsigned char> bytes, int offset, int length)
{
    return BCDSectionConvertToString(bytes, offset, length, BCD_EXTENDED_TYPE_EF_ADN);
}

std::string SimNumberDecode::BCDSectionConvertToString(
    const std::shared_ptr<unsigned char> bytes, int offset, int length, int bcdExtType)
{
    std::string ret = "";
    InternalBCDSectionConvertToString(ret, bytes, offset, length, bcdExtType);
    return ret;
}

void SimNumberDecode::InternalBCDSectionConvertToString(
    std::string &sb, std::shared_ptr<unsigned char> bytesData, int offset, int length, int bcdExtType)
{
    unsigned char *bytes = bytesData.get();
    unsigned char b = 0;
    char c = '\0';
    for (int i = offset; i < length + offset; i++) {
        c = BcdToChar((unsigned char)(bytes[i] & HALF_BYTE), bcdExtType);
        if (c == 0) {
            return;
        }
        sb.push_back(c);
        b = (unsigned char)((bytes[i] >> SHIFT_FLAG) & HALF_BYTE);
        if (b == HALF_BYTE && i + 1 == length + offset) {
            break;
        }
        c = BcdToChar(b, bcdExtType);
        if (c == 0) {
            return;
        }
        sb.push_back(c);
    }
}

char SimNumberDecode::BcdToChar(unsigned char b, int bcdExtType)
{
    if (b < CHAR_START) {
        return (char)('0' + b);
    }

    std::string extended = "";
    if (BCD_EXTENDED_TYPE_EF_ADN == bcdExtType) {
        extended = BCD_EF_ADN_EXTENDED;
    } else if (BCD_EXTENDED_TYPE_CALLED_PARTY == bcdExtType) {
        extended = BCD_CALLED_PARTY_EXTENDED;
    }
    if (extended == "" || (b - CHAR_START >= extended.length())) {
        return 0;
    }
    return extended.at(b - CHAR_START);
}
} // namespace Telephony
} // namespace OHOS
