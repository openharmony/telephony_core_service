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
#include <set>
#include <sstream>
#include <iomanip>

using namespace std;

namespace OHOS {
namespace Telephony {
static std::string HexToStr(const std::vector<uint8_t> &arr)
{
    std::stringstream ss;
    for (const auto &v : arr) {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << v;
    }
    return ss.str();
}

inline static bool isNumber(const char num)
{
    return (num >= '0' && num <= '9');
}

inline static bool isPlusNumber(const char num)
{
    return isNumber(num) || (num == '+');
}

inline static bool isSharpStar(const char num)
{
    return num == '#' || num == '*';
}

inline static bool isValidNumberChar(const char num)
{
    return isPlusNumber(num) || isSharpStar(num);
}

bool SimNumberDecode::IsValidNumberString(const std::string &number)
{
    for (const auto &num : number) {
        if (!isValidNumberChar(num)) {
            return false;
        }
    }
    return true;
}

std::shared_ptr<unsigned char> SimNumberDecode::NumberConvertToBCD(
    const std::string &number, int bcdExtType, int &bcdLength)
{
    TELEPHONY_LOGI("SimNumberDecode::NumberConvertToBCD begin_A with number,bcdExtType:%{public}d", bcdExtType);
    std::vector<uint8_t> result;
    if (!NumberConvertToBCD(number, result, false, bcdExtType)) {
        TELEPHONY_LOGE("SimNumberDecode::NumberConvertToBCD for number and bcdLength:%{public}d", bcdLength);
        bcdLength = INIT_VAL;
        return nullptr;
    }
    bcdLength = result.size();
    if (bcdLength <= 0) {
        TELEPHONY_LOGE("invalid length :%{public}d", bcdLength);
        return nullptr;
    }
    uint8_t *res = (unsigned char *)calloc(bcdLength, sizeof(unsigned char));
    if (!res) {
        TELEPHONY_LOGE("calloc(%{public}d, %{public}zu) fail!", bcdLength, sizeof(uint8_t));
        return nullptr;
    }
    for (const auto &v : result) {
        *res = v;
        ++res;
    }
    TELEPHONY_LOGI("SimNumberDecode::NumberConvertToBCD success end_A with result");
    return std::shared_ptr<unsigned char>(res);
}

const std::string *SimNumberDecode::chooseExtendedByType(const int bcdExtType)
{
    if (bcdExtType == BCD_TYPE_ADN) {
        return &BCD_ADN_EXTENTION;
    } else if (bcdExtType == BCD_TYPE_CALLER) {
        return &BCD_CALLER_EXTENTION;
    }
    return nullptr;
}

bool SimNumberDecode::CharToBCD(const char c, uint8_t &result, const int bcdExtType)
{
    TELEPHONY_LOGI(
        "SimNumberDecode::CharToBCD begin with:char'%{public}c' and bcdExtType:'%{public}d'", c, bcdExtType);
    if (c >= '0' && c <= '9') {
        result = c - '0';
        TELEPHONY_LOGI("SimNumberDecode::CharToBCD end with:result '%{public}d'", result);
        return true;
    }
    const std::string *extendedPtr = chooseExtendedByType(bcdExtType);
    if (!extendedPtr) {
        TELEPHONY_LOGE("Unknow bcdExtType:[%{public}d]", bcdExtType);
        return false;
    }
    const std::string &extended = *extendedPtr;
    const size_t chrIdx = extended.find(c);
    if (chrIdx == std::string::npos) {
        TELEPHONY_LOGE("invalid char for BCD %{public}d", c);
        return false;
    }
    result = static_cast<uint8_t>(chrIdx + CHAR_START);
    TELEPHONY_LOGI("SimNumberDecode::CharToBCD end with:result '%{public}d'", result);
    return true;
}

bool SimNumberDecode::BcdToChar(const uint8_t bcdCode, char &result, const int bcdExtType)
{
    TELEPHONY_LOGI("SimNumberDecode::BcdToChar begin with:bcdCode'%{public}d' and bcdExtType:'%{public}d'",
        bcdCode, bcdExtType);
    const int32_t surplus = static_cast<int32_t>(bcdCode) - CHAR_START;
    if (surplus < INIT_VAL) {
        result = '0' + bcdCode;
        return true;
    }
    const std::string *extendedPtr = chooseExtendedByType(bcdExtType);
    if (!extendedPtr) {
        TELEPHONY_LOGE("Unknow bcdExtType:[%{public}d]", bcdExtType);
        return false;
    }
    if (surplus >= extendedPtr->size()) {
        TELEPHONY_LOGE("Unknow bcdCode:[%{public}d]", bcdCode);
        return false;
    }
    result = extendedPtr->at(surplus);
    TELEPHONY_LOGI("SimNumberDecode::BcdToChar success end with result:'%{public}c'", result);
    return true;
}

bool SimNumberDecode::NumberConvertToBCD(
    const std::string &number, std::vector<uint8_t> &bcdCodes, const bool includeLen, const int bcdExtType)
{
    TELEPHONY_LOGI(
        "SimNumberDecode::NumberConvertToBCD begin_B with "
        "number,isCludeLen:%{public}d,bcdExtType:%{public}d",
        includeLen, bcdExtType);
    const bool hasPlus = (number.find('+') != std::string::npos);
    uint8_t length = number.length();
    if (hasPlus) {
        --length;
    }
    if (includeLen) {
        bcdCodes.push_back(length);
    }
    bcdCodes.push_back(hasPlus ? FLAG_INTERNATIONAL : FLAG_UNKNOWN);

    size_t count = INIT_VAL;
    for (const auto &num : number) {
        if (num == '+') {
            continue;
        }
        uint8_t code = INIT_VAL;
        if (!CharToBCD(num, code, bcdExtType)) {
            TELEPHONY_LOGI("occur error in CharToBCD(num:'%{public}d',bcdExtType:'%{public}d')", num, bcdExtType);
            return false;
        }
        if (count % EVEN == 1) {
            bcdCodes.back() |= (code << FOUR_BIT);
        } else {
            bcdCodes.push_back(code);
        }
        ++count;
    }
    if (count % EVEN == 1) {
        bcdCodes.back() |= HI_FOUR;
    }
    TELEPHONY_LOGI(
        "SimNumberDecode::NumberConvertToBCD success end_B with result:'%{publci}s'", HexToStr(bcdCodes).c_str());
    return true;
}

std::string SimNumberDecode::BCDConvertToString(
    const std::shared_ptr<unsigned char> bytesData, int offset, int length, int bcdExtType)
{
    uint8_t *arr = bytesData.get();
    if (!arr) {
        TELEPHONY_LOGE("BCDConvertToString fail because bytesData is nullptr!!");
        return "";
    }
    std::vector<uint8_t> bcdCode;
    for (int i = INIT_VAL; i < length; ++i) {
        bcdCode.push_back(arr[offset + i]);
    }
    std::string res;
    if (!BCDConvertToString(bcdCode.begin(), bcdCode.end(), res, bcdExtType)) {
        TELEPHONY_LOGE("occur error in BCDConvertToString for '%{public}s by bcdExtType:%{public}d",
            HexToStr(bcdCode).c_str(), bcdExtType);
        return "";
    }
    return res;
}

bool SimNumberDecode::BCDSectionConvertToString(const std::vector<uint8_t>::const_iterator &codeBeg,
    const std::vector<uint8_t>::const_iterator &codeEnd, std::string &number, const int bcdExtType)
{
    TELEPHONY_LOGI(
        "SimNumberDecode::BCDSectionConvertToString begin with codes:'%{public}s' and bcdExtType:'%{public}d'",
        HexToStr(std::vector<uint8_t>(codeBeg, codeEnd)).c_str(), bcdExtType);
    for (std::vector<uint8_t>::const_iterator it = codeBeg; it != codeEnd; ++it) {
        uint8_t loFourBit = (*it & LO_FOUR);
        char c = INIT_VAL;
        if (!BcdToChar(loFourBit, c, bcdExtType)) {
            TELEPHONY_LOGE(
                "occur error in BcdToChar(bcd:'%{public}d',bcdExtType:'%{public}d')", loFourBit, bcdExtType);
            return false;
        }
        number.push_back(c);
        uint8_t hiFourBit = (*it >> SHIFT_FLAG) & HALF_BYTE;
        if (hiFourBit == HALF_BYTE && (it + INC_ONE) == codeEnd) {
            break;
        }
        if (!BcdToChar(hiFourBit, c, bcdExtType)) {
            TELEPHONY_LOGE(
                "occur error in BcdToChar(bcd:'%{public}d',bcdExtType:'%{public}d')", loFourBit, bcdExtType);
            return false;
        }
        number.push_back(c);
    }
    return true;
}

bool SimNumberDecode::BCDConvertToString(const std::vector<uint8_t>::const_iterator &codeBeg,
    const std::vector<uint8_t>::const_iterator &codeEnd, std::string &number, const int bcdExtType)
{
    TELEPHONY_LOGI("SimNumberDecode::BCDConvertToString begin with codes:'%{public}s' and bcdExtType:'%{public}d'",
        HexToStr(std::vector<uint8_t>(codeBeg, codeEnd)).c_str(), bcdExtType);
    std::vector<uint8_t>::const_iterator it = codeBeg;
    const bool prependPlus = (*it == FLAG_INTERNATIONAL);
    ++it;
    if (!BCDSectionConvertToString(it, codeEnd, number, bcdExtType)) {
        TELEPHONY_LOGE(
            "occur error to BCDSectionConvertToString by codes:'%{public}s' and bcdExtType:'%{public}d'",
            HexToStr(std::vector<uint8_t>(it, codeEnd)).c_str(), bcdExtType);
        return false;
    }
    if (!prependPlus) {
        return true;
    }
    if (number.empty() || !IsValidNumberString(number)) {
        TELEPHONY_LOGE("occur error at number after parse!! number");
        return false;
    }

    std::string::const_iterator numIt = number.begin();
    /* not start with [#*] just prepend '+' */
    if (!isSharpStar(number.front())) {
        number.insert(number.begin(), '+');
        return true;
    }
    ++numIt;
    /* started with two [#*] ends with # ,just append a +  */
    if (isSharpStar(*numIt) && (number.back() == '#')) {
        number.push_back('+');
        return true;
    }
    while ((numIt != number.end()) && isPlusNumber(*numIt)) {
        numIt++;
    }
    /*  start with [#*] ;assume the data after last;insert head of data a + */
    if ((numIt != number.end()) && (numIt + INC_ONE != number.end()) && isSharpStar(*numIt)) {
        number.insert(numIt + INC_ONE, '+');
    }
    return true;
}
} // namespace Telephony
} // namespace OHOS
