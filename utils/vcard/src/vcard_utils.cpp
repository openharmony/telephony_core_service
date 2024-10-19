/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "vcard_utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <sstream>

#include "glib.h"
#include "map"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_configuration.h"
#include "vcard_constant.h"

namespace OHOS {
namespace Telephony {
namespace {
std::map<ImType, std::string> imLabelIdToType = { { ImType::IM_AIM, VCARD_TYPE_X_AIM },
    { ImType::IM_MSN, VCARD_TYPE_X_MSN }, { ImType::IM_YAHOO, VCARD_TYPE_X_YAHOO },
    { ImType::IM_ICQ, VCARD_TYPE_X_ICQ }, { ImType::IM_JABBER, VCARD_TYPE_X_JABBER },
    { ImType::IM_SKYPE, VCARD_TYPE_X_SKYPE_USERNAME }, { ImType::IM_QQ, VCARD_TYPE_X_QQ } };
std::map<PhoneVcType, std::string> phoneLabelIdToType = { { PhoneVcType::NUM_HOME, VCARD_PARAM_TYPE_HOME },
    { PhoneVcType::NUM_MOBILE, VCARD_PARAM_TYPE_CELL }, { PhoneVcType::NUM_WORK, VCARD_PARAM_TYPE_WORK },
    { PhoneVcType::NUM_PAGER, VCARD_PARAM_TYPE_PAGER }, { PhoneVcType::NUM_OTHER, VCARD_PARAM_TYPE_VOICE },
    { PhoneVcType::NUM_CALLBACK, VCARD_PARAM_PHONE_EXTRA_TYPE_CALLBACK },
    { PhoneVcType::NUM_CAR, VCARD_PARAM_TYPE_CAR }, { PhoneVcType::NUM_COMPANY_MAIN, VCARD_PARAM_TYPE_WORK },
    { PhoneVcType::NUM_ISDN, VCARD_PARAM_TYPE_ISDN }, { PhoneVcType::NUM_OTHER_FAX, VCARD_PARAM_TYPE_FAX },
    { PhoneVcType::NUM_RADIO, VCARD_PARAM_PHONE_EXTRA_TYPE_RADIO }, { PhoneVcType::NUM_TELEX, VCARD_PARAM_TYPE_TLX },
    { PhoneVcType::NUM_TTY_TDD, VCARD_PARAM_PHONE_EXTRA_TYPE_TTY_TDD },
    { PhoneVcType::NUM_ASSISTANT, VCARD_PARAM_PHONE_EXTRA_TYPE_ASSISTANT },
    { PhoneVcType::NUM_MMS, VCARD_PARAM_TYPE_MSG } };
std::map<std::string, PhoneVcType> typeToPhoneTypeMap = { { VCARD_PARAM_TYPE_CAR, PhoneVcType::NUM_CAR },
    { VCARD_PARAM_TYPE_PAGER, PhoneVcType::NUM_PAGER }, { VCARD_PARAM_TYPE_ISDN, PhoneVcType::NUM_ISDN },
    { VCARD_PARAM_TYPE_HOME, PhoneVcType::NUM_HOME }, { VCARD_PARAM_TYPE_WORK, PhoneVcType::NUM_WORK },
    { VCARD_PARAM_TYPE_CELL, PhoneVcType::NUM_MOBILE },
    { VCARD_PARAM_PHONE_EXTRA_TYPE_CALLBACK, PhoneVcType::NUM_CALLBACK },
    { VCARD_PARAM_PHONE_EXTRA_TYPE_RADIO, PhoneVcType::NUM_RADIO },
    { VCARD_PARAM_PHONE_EXTRA_TYPE_TTY_TDD, PhoneVcType::NUM_TTY_TDD },
    { VCARD_PARAM_PHONE_EXTRA_TYPE_ASSISTANT, PhoneVcType::NUM_ASSISTANT },
    { VCARD_PARAM_TYPE_VOICE, PhoneVcType::NUM_OTHER } };
} // namespace

std::string VCardUtils::EncodeBase64(const std::string &input)
{
    gchar *encodedData = g_base64_encode(reinterpret_cast<const guchar *>(input.c_str()), input.length());
    std::string result(encodedData);
    g_free(encodedData);
    return result;
}

std::string VCardUtils::DecodeBase64(const std::string &input)
{
    gsize outputLength;
    guchar *decodedData = g_base64_decode(input.c_str(), &outputLength);
    std::string result(reinterpret_cast<char *>(decodedData), outputLength);
    g_free(decodedData);
    return result;
}

bool VCardUtils::EqualsIgnoreCase(const std::string &str1, const std::string &str2)
{
    std::string copy1 = str1;
    std::string copy2 = str2;

    std::transform(copy1.begin(), copy1.end(), copy1.begin(), ::tolower);
    std::transform(copy2.begin(), copy2.end(), copy2.begin(), ::tolower);

    return copy1 == copy2;
}

std::vector<std::string> VCardUtils::Split(const std::string &input, const std::string &delimiter)
{
    std::vector<std::string> result;
    std::size_t pos = 0;
    std::size_t delimiterPos;

    while ((delimiterPos = input.find(delimiter, pos)) != std::string::npos) {
        std::string token = input.substr(pos, delimiterPos - pos);
        result.push_back(token);
        pos = delimiterPos + delimiter.size();
    }

    if (pos < input.size()) {
        std::string token = input.substr(pos);
        result.push_back(token);
    }

    return result;
}

std::string VCardUtils::Trim(std::string &str)
{
    std::string::size_type pos1 = str.find_first_not_of(" \t\n\r\f\v");
    std::string::size_type pos2 = str.find_last_not_of(" \t\n\r\f\v");
    if (pos1 != std::string::npos && pos2 != std::string::npos) {
        str = str.substr(pos1, pos2 - pos1 + 1);
    } else {
        str.clear();
    }

    return str;
}

std::string VCardUtils::ToUpper(const std::string &str)
{
    std::string temp = str;
    for (char &c : temp) {
        c = std::toupper(c);
    }
    return temp;
}

bool VCardUtils::StartWith(const std::string &str, const std::string &prefix)
{
    if (str.length() < prefix.length()) {
        return false;
    }
    return str.substr(0, prefix.length()) == prefix;
}

bool VCardUtils::EndWith(const std::string &fullString, const std::string &ending)
{
    if (fullString.length() < ending.length()) {
        return false;
    }

    std::string extractedEnding = fullString.substr(fullString.length() - ending.length());

    return extractedEnding == ending;
}

std::string VCardUtils::ConvertCharset(
    const std::string &input, const std::string &fromCharset, const std::string &toCharset, int32_t &errorCode)
{
    GIConv converter = g_iconv_open(toCharset.c_str(), fromCharset.c_str());
    if (converter == nullptr) {
        TELEPHONY_LOGE("ConvertCharset open fail");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return "";
    }

    size_t inBytes = input.size();
    size_t outBytes = inBytes * 4; // Allocate enough space for the worst-case scenario
    char *inBuf = const_cast<char *>(input.c_str());
    char *outBuf = new char[outBytes];
    char *outBufPtr = outBuf;

    if (g_iconv(converter, &inBuf, &inBytes, &outBufPtr, &outBytes) == (size_t)(-1)) {
        TELEPHONY_LOGE("ConvertCharset open fail");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        delete[] outBuf;
        g_iconv_close(converter);
        return "";
    }

    std::string output(outBuf, outBufPtr - outBuf);
    delete[] outBuf;
    g_iconv_close(converter);
    return output;
}

std::string VCardUtils::CreateFileName()
{
    std::time_t now = std::time(nullptr);
    std::tm *timeinfo = std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(timeinfo, VCARD_TIME_FORMAT);
    std::string fileName = oss.str() + ".vcf";
    return fileName;
}

void VCardUtils::SaveFile(const std::string &fileStr, const std::string &path)
{
    std::ofstream file(path, std::ios::trunc);
    if (file.is_open()) {
        std::stringstream ss(fileStr);
        std::string line;

        while (std::getline(ss, line)) {
            file << line << std::endl;
        }
        file.close();
    }
}

bool VCardUtils::IsWrapPrintableAscii(std::vector<std::string> strs)
{
    for (auto str : strs) {
        for (char ch : str) {
            if (!(IsPrintableAscii(ch) || ch == '\r' || ch == '\n')) {
                return false;
            }
        }
    }
    return true;
}

bool VCardUtils::IsPrintableAscii(std::vector<std::string> strs)
{
    for (auto it : strs) {
        if (!IsPrintableAscii(it)) {
            return false;
        }
    }
    return true;
}

bool VCardUtils::IsPrintableAscii(const std::string &str)
{
    for (char ch : str) {
        if (!IsPrintableAscii(ch)) {
            return false;
        }
    }
    return true;
}

bool VCardUtils::IsPrintableAscii(char ch)
{
    return std::isprint(static_cast<unsigned char>(ch));
}

bool VCardUtils::IsNum(const std::string &str)
{
    if (str.empty()) {
        return false;
    }
    for (char ch : str) {
        if (!std::isdigit(ch)) {
            return false;
        }
    }
    return true;
}

std::string VCardUtils::GetTypeFromImLabelId(std::string labelId)
{
    if (!IsNum(labelId)) {
        return "";
    }
    int32_t num = std::stoi(labelId);
    auto it = imLabelIdToType.find(static_cast<ImType>(num));
    if (it != imLabelIdToType.end()) {
        return it->second;
    }
    return "";
}

int32_t VCardUtils::GetLabelIdFromImType(std::string type)
{
    if (type.empty()) {
        return static_cast<int32_t>(ImType::INVALID_LABEL_ID);
    }
    if (type == VCARD_TYPE_X_AIM) {
        return static_cast<int32_t>(ImType::IM_AIM);
    } else if (type == VCARD_TYPE_X_MSN) {
        return static_cast<int32_t>(ImType::IM_MSN);
    } else if (type == VCARD_TYPE_X_YAHOO) {
        return static_cast<int32_t>(ImType::IM_YAHOO);
    } else if (type == VCARD_TYPE_X_ICQ) {
        return static_cast<int32_t>(ImType::IM_ICQ);
    } else if (type == VCARD_TYPE_X_JABBER) {
        return static_cast<int32_t>(ImType::IM_JABBER);
    } else if (type == VCARD_TYPE_X_QQ) {
        return static_cast<int32_t>(ImType::IM_QQ);
    } else {
        return static_cast<int32_t>(ImType::CUSTOM_LABEL);
    }
}

std::vector<std::string> VCardUtils::GetTypeFromPhoneLabelId(std::string labelId)
{
    std::vector<std::string> paramTypes = {};
    if (!IsNum(labelId) || labelId.size() > INT_64_LENTGH) {
        return paramTypes;
    }
    int64_t num = std::stoll(labelId);
    auto phoneType = static_cast<PhoneVcType>(num);
    auto it = phoneLabelIdToType.find(phoneType);
    if (it != phoneLabelIdToType.end()) {
        paramTypes.push_back(it->second);
        return paramTypes;
    }
    switch (phoneType) {
        case PhoneVcType::NUM_FAX_HOME: {
            paramTypes.push_back(VCARD_PARAM_TYPE_HOME);
            paramTypes.push_back(VCARD_PARAM_TYPE_FAX);
            return paramTypes;
        }
        case PhoneVcType::NUM_FAX_WORK: {
            paramTypes.push_back(VCARD_PARAM_TYPE_WORK);
            paramTypes.push_back(VCARD_PARAM_TYPE_FAX);
            return paramTypes;
        }
        case PhoneVcType::NUM_WORK_MOBILE: {
            paramTypes.push_back(VCARD_PARAM_TYPE_WORK);
            paramTypes.push_back(VCARD_PARAM_TYPE_CELL);
            return paramTypes;
        }
        case PhoneVcType::NUM_WORK_PAGER: {
            paramTypes.push_back(VCARD_PARAM_TYPE_WORK);
            paramTypes.push_back(VCARD_PARAM_TYPE_PAGER);
            return paramTypes;
        }
        default:
            break;
    }
    return paramTypes;
}

std::string VCardUtils::TrimListToString(const std::vector<std::string> &strs)
{
    int32_t size = static_cast<int32_t>(strs.size());
    std::string result;
    if (size > 1) {
        std::string init = "";
        result = std::accumulate(strs.begin(), strs.end(), init,
            [](std::string &str, const std::string &element) { return str + element + ";"; });
    } else if (size == 1) {
        return strs[0];
    } else {
        return "";
    }
    return result;
}

std::string VCardUtils::HandleCh(char nextCh, std::string vcardType)
{
    std::string unescapedString = "";
    if (vcardType == VERSION_40) {
        if (nextCh == 'n' || nextCh == 'N') {
            unescapedString = "\n";
        } else {
            unescapedString = nextCh;
        }
    } else if (vcardType == VERSION_30) {
        if (nextCh == 'n' || nextCh == 'N') {
            unescapedString = "\n";
        } else {
            unescapedString = nextCh;
        }
    } else {
        if (nextCh == '\\' || nextCh == ';' || nextCh == ':' || nextCh == ',') {
            unescapedString = nextCh;
        } else {
            unescapedString = "";
        }
    }
    return unescapedString;
}

std::vector<std::string> VCardUtils::ConstructListFromValue(const std::string &value, std::string vcardType)
{
    std::vector<std::string> result;
    std::string builder;
    int32_t length = static_cast<int32_t>(value.length());
    for (int32_t i = 0; i < length; i++) {
        char ch = value[i];
        if (ch == '\\' && i < length - 1) {
            char nextCh = value[i + 1];
            std::string unescapedString = HandleCh(nextCh, vcardType);
            if (!unescapedString.empty()) {
                builder += unescapedString;
                i++;
            } else {
                builder += ch;
            }
        } else if (ch == ';') {
            result.push_back(builder);
        } else {
            builder += ch;
        }
    }
    result.push_back(builder);
    return result;
}

void VCardUtils::HandleTypeAndLabel(int32_t &type, std::string &label, std::string number, std::string labelCandidate)
{
    std::map<std::string, PhoneVcType>::iterator iter = typeToPhoneTypeMap.find(labelCandidate);
    if (iter != typeToPhoneTypeMap.end()) {
        PhoneVcType phoneType = iter->second;
        int32_t typeCandidate = static_cast<int32_t>(phoneType);

        std::size_t indexOfAt = -1;
        std::size_t found = number.find("@");
        if (found != std::string::npos) {
            indexOfAt = found;
        }

        if ((typeCandidate == static_cast<int32_t>(PhoneVcType::NUM_PAGER) && 0 < indexOfAt &&
                indexOfAt < number.length() - 1) ||
            type < 0 || type == static_cast<int32_t>(PhoneVcType::CUSTOM_LABEL) ||
            type == static_cast<int32_t>(PhoneVcType::NUM_OTHER)) {
            type = typeCandidate;
        }
    } else if (type < 0) {
        type = static_cast<int32_t>(PhoneVcType::CUSTOM_LABEL);
        label = labelCandidate;
    }
}

void VCardUtils::GetPhoneTypeFromStrings(
    const std::vector<std::string> &types, std::string number, std::tuple<int32_t, std::string> &result)
{
    int32_t type = -1;
    std::string label;
    bool isFax = false;
    bool hasPref = false;

    for (std::string typeStringOrg : types) {
        std::string typeStringUpperCase = ToUpper(typeStringOrg);
        if (typeStringUpperCase == VCARD_PARAM_TYPE_PREF) {
            hasPref = true;
        } else if (typeStringUpperCase == VCARD_PARAM_TYPE_FAX) {
            isFax = true;
        } else {
            std::string labelCandidate;
            if (StartWith(typeStringUpperCase, "X-") && type < 0) {
                labelCandidate = typeStringOrg.substr(VALUE_INDEX_TWO);
            } else {
                labelCandidate = typeStringOrg;
                label = labelCandidate;
            }
            if (labelCandidate.length() == 0) {
                continue;
            }
            HandleTypeAndLabel(type, label, number, labelCandidate);
        }
    }

    if (type < 0) {
        if (hasPref) {
            type = static_cast<int32_t>(PhoneVcType::NUM_MAIN);
        } else {
            type = static_cast<int32_t>(PhoneVcType::NUM_HOME);
        }
    }

    if (isFax) {
        if (type == static_cast<int32_t>(PhoneVcType::NUM_MOBILE)) {
            type = static_cast<int32_t>(PhoneVcType::NUM_FAX_HOME);
        } else if (type == static_cast<int32_t>(PhoneVcType::NUM_WORK)) {
            type = static_cast<int32_t>(PhoneVcType::NUM_FAX_WORK);
        } else if (type == static_cast<int32_t>(PhoneVcType::NUM_OTHER)) {
            type = static_cast<int32_t>(PhoneVcType::NUM_OTHER_FAX);
        }
    }

    if (type == static_cast<int32_t>(PhoneVcType::CUSTOM_LABEL)) {
        std::get<0>(result) = -1;
        std::get<1>(result) = label;
    } else {
        std::get<0>(result) = type;
        std::get<1>(result) = "-1";
    }
}

int32_t VCardUtils::VcardtypeToInt(const std::string &vcardType)
{
    if (vcardType == VERSION_21) {
        return VERSION_21_NUM;
    } else if (vcardType == VERSION_30) {
        return VERSION_30_NUM;
    } else if (vcardType == VERSION_40) {
        return VERSION_40_NUM;
    }
    return -1;
}

std::string VCardUtils::FormatNumber(std::string source)
{
    return source;
}

int32_t VCardUtils::GetPhoneNumberFormat(const int32_t vcardType)
{
    if (VCardConfiguration::IsJapaneseDevice(vcardType)) {
        return VCARD_PHONE_NUM_FORMAT_JAPAN;
    } else {
        return VCARD_PHONE_NUM_FORMAT_NANP;
    }
}

std::string VCardUtils::GetImageType(std::string bytes)
{
    if (bytes.empty()) {
        return "";
    }
    int32_t length = static_cast<int32_t>(bytes.length());
    int32_t gifTypeLength = VALUE_LEN_THREE;
    if (length >= gifTypeLength && bytes[VALUE_INDEX_ZERO] == 'G' && bytes[1] == 'I' && bytes[VALUE_INDEX_TWO] == 'F') {
        return "GIF";
    }
    int32_t pngTypeLength = VALUE_LEN_FOUR;
    if (length >= pngTypeLength && bytes[VALUE_INDEX_ZERO] == static_cast<char>(0x89) &&
        bytes[VALUE_INDEX_ONE] == 'P' && bytes[VALUE_INDEX_TWO] == 'N' && bytes[VALUE_INDEX_THREE] == 'G') {
        return "PNG";
    }
    int32_t jpgTypeLength = VALUE_LEN_TWO;
    if (length >= jpgTypeLength && bytes[VALUE_INDEX_ZERO] == static_cast<char>(0xff) &&
        bytes[VALUE_INDEX_ONE] == static_cast<char>(0xd8)) {
        return "JPEG";
    }
    return "";
}

bool VCardUtils::IsAllEmpty(std::vector<std::string> values)
{
    for (auto value : values) {
        if (!value.empty()) {
            return false;
        }
    }
    return true;
}

} // namespace Telephony
} // namespace OHOS
