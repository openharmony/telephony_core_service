/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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
#include "vcard_decoder_v30.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_constant.h"
#include "vcard_file_utils.h"
#include "vcard_utils.h"

namespace OHOS {
namespace Telephony {

bool VCardDecoderV30::ReadBegin()
{
    return VCardDecoderV21::ReadBegin();
}

std::string VCardDecoderV30::GetLine()
{
    std::string line = "";
    if (!preLine_.empty()) {
        line = preLine_;
        preLine_ = "";
        return line;
    }
    fileUtils_.ReadLine(line);
    return line;
}

std::string VCardDecoderV30::PeekLine()
{
    if (!preLine_.empty()) {
        return preLine_;
    }
    std::string line = "";
    fileUtils_.PeekLine(line);
    return line;
}

std::string VCardDecoderV30::GetNonEmptyLine()
{
    std::string line;
    std::string ret = "";
    while (fileUtils_.ReadLine(line)) {
        if (line.empty()) {
            continue;
        }
        if (line[0] == ' ' || line[0] == '\t') {
            if (!preLine_.empty()) {
                ret += preLine_;
                preLine_ = "";
            }
            ret += line.substr(1);
            continue;
        }
        if (!ret.empty() || !preLine_.empty()) {
            break;
        }
        preLine_ = line;
    }
    if (ret.empty()) {
        ret = preLine_;
    }
    preLine_ = line;
    return ret;
}

void VCardDecoderV30::DealParams(const std::string &params, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    VCardDecoderV21::DealParams(params, rawData, errorCode);
    if (errorCode == TELEPHONY_SUCCESS) {
        return;
    }
    auto strs = VCardUtils::Split(params, "=");
    if (static_cast<int32_t>(strs.size()) == SIZE_TWO) {
        std::string name = VCardUtils::ToUpper(VCardUtils::Trim(strs[0]));
        std::string value = VCardUtils::Trim(strs[1]);
        DealAnyParam(name, value, rawData, errorCode);
        errorCode = TELEPHONY_SUCCESS;
        return;
    }
    errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
}

std::string VCardDecoderV30::EncodeParamValue(const std::string &value)
{
    int32_t errorCode = TELEPHONY_SUCCESS;
    return VCardUtils::ConvertCharset(value, "", DEFAULT_IMPORT_CHARSET, errorCode);
}

void VCardDecoderV30::DealAnyParam(
    const std::string &param, const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    DealParmV30(param, paramValue, rawData, errorCode);
}

void VCardDecoderV30::DealNoNameParam(
    const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    DealTypeParam(paramValue, rawData, errorCode);
}

void VCardDecoderV30::DealTypeParam(
    const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    DealParmV30(VCARD_PARAM_TYPE, paramValue, rawData, errorCode);
}

void VCardDecoderV30::DealAgent(std::shared_ptr<VCardRawData> rawData, int32_t &errorCode) {}

std::string VCardDecoderV30::UnescapeText(const std::string &from)
{
    std::string result;
    for (size_t i = 0; i < from.length(); i++) {
        auto ch = from[i];
        if (ch == '\\' && i < from.length() - 1) {
            char nextCh = from[++i];
            if (nextCh == 'n' || nextCh == 'N') {
                result.append("\n");
                continue;
            }
            result += nextCh;
            continue;
        }
        result += ch;
    }
    return result;
}

std::string VCardDecoderV30::UnescapeChar(char ch)
{
    if (ch == 'n' || ch == 'N') {
        return "\n";
    }
    return std::string(1, ch);
}

void VCardDecoderV30::DealParmV30(
    const std::string &param, const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    auto quoted = false;
    std::string value = "";
    for (size_t i = 0; i < paramValue.length(); i++) {
        auto ch = paramValue[i];
        if (ch == '"') {
            if (quoted) {
                rawData->AppendParameter(param, EncodeParamValue(value));
                value.clear();
                quoted = false;
                continue;
            }
            quoted = true;
            continue;
        }
        if (ch == ',' && !quoted) {
            if (value.empty()) {
                continue;
            }
            rawData->AppendParameter(param, EncodeParamValue(value));
            value.clear();
            continue;
        }
        value += ch;
    }
    if (quoted) {
        TELEPHONY_LOGI("non quote at end");
    }
    if (value.empty()) {
        TELEPHONY_LOGI("value is empty");
        return;
    }
    rawData->AppendParameter(param, EncodeParamValue(value));
}

std::string VCardDecoderV30::GetVersion()
{
    return VERSION_30;
}

std::string VCardDecoderV30::GetBase64(const std::string &value, int32_t &errorCode)
{
    return value;
}

std::vector<std::string> VCardDecoderV30::GetSupportType()
{
    return { VCARD_TYPE_BEGIN, VCARD_TYPE_END, VCARD_TYPE_LOGO, VCARD_TYPE_PHOTO, "LABEL", VCARD_TYPE_FN, "TITLE",
        "SOUND", VCARD_TYPE_VERSION, VCARD_TYPE_TEL, VCARD_TYPE_EMAIL, "TZ", "GEO", VCARD_TYPE_NOTE, VCARD_TYPE_URL,
        VCARD_TYPE_BDAY, "ROLE", "REV", "UID", "KEY", "MAILER", "NAME", "PROFILE", "SOURCE", VCARD_TYPE_NICKNAME,
        "CLASS", "SORT-STRING", "CATEGORIES", "PRODID", "IMPP" };
}
} // namespace Telephony
} // namespace OHOS
