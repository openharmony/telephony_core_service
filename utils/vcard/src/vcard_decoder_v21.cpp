/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "vcard_decoder_v21.h"

#include <algorithm>
#include <cctype>
#include <codecvt>
#include <locale>
#include <sstream>
#include <vector>

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_constant.h"
#include "vcard_file_utils.h"
#include "vcard_utils.h"

namespace OHOS {
namespace Telephony {
std::mutex rawDataMutex_;
namespace {
constexpr int32_t STATUS_GROUP_OR_TYPE_NAME = 1;
constexpr int32_t STATUS_PARAMS = 2;
constexpr int32_t STATUS_PARAMS_IN_DQUOTE = 3;
} // namespace

void VCardDecoderV21::AddVCardDecodeListener(std::shared_ptr<VCardDecodeListener> listener)
{
    if (listener == nullptr) {
        TELEPHONY_LOGE("listener is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(rawDataMutex_);
    listeners_.push_back(listener);
}

void VCardDecoderV21::NotifyStarted()
{
    for (auto it : listeners_) {
        if (it == nullptr) {
            continue;
        }
        it->OnStarted();
    }
}

void VCardDecoderV21::NotifyEnded()
{
    for (auto it : listeners_) {
        if (it == nullptr) {
            continue;
        }
        it->OnEnded();
    }
}
void VCardDecoderV21::NotifyOneContactStarted()
{
    for (auto it : listeners_) {
        if (it == nullptr) {
            continue;
        }
        it->OnOneContactStarted();
    }
}

void VCardDecoderV21::NotifyOneContactEnded()
{
    for (auto it : listeners_) {
        if (it == nullptr) {
            continue;
        }
        it->OnOneContactEnded();
    }
}

void VCardDecoderV21::NotifyRawDataCreated(std::shared_ptr<VCardRawData> rawData)
{
    for (auto it : listeners_) {
        if (it == nullptr) {
            continue;
        }
        it->OnRawDataCreated(rawData);
    }
}

void VCardDecoderV21::Decode(int32_t &errorCode)
{
    NotifyStarted();
    while (!IsEnd() && DecodeOne(errorCode)) {
        if (errorCode != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("Failed to decode");
        }
    }
    NotifyEnded();
}

bool VCardDecoderV21::DecodeOne(int32_t &errorCode)
{
    errorCode = TELEPHONY_SUCCESS;
    currentCharset_ = DEFAULT_CHARSET;
    currentEncoding_ = DEFAULT_ENCODING;
    NotifyOneContactStarted();
    if (!ReadBegin()) {
        TELEPHONY_LOGE("Failed to decode");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        fileUtils_.Close();
        return false;
    }
    ParseItems(errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Failed to parse item");
        return false;
    }
    NotifyOneContactEnded();
    fileUtils_.SkipEmptyLines();
    return true;
}

bool VCardDecoderV21::ReadBegin()
{
    std::string line;
    while (fileUtils_.ReadLine(line)) {
        line = VCardUtils::Trim(line);
        if (line.length() > 0) {
            break;
        }
    }
    if (line == "") {
        TELEPHONY_LOGE("empty file");
        return false;
    }
    std::vector<std::string> strArr = VCardUtils::Split(line, ":");
    int32_t expectSize = 2;
    if (static_cast<int32_t>(strArr.size()) == expectSize &&
        VCardUtils::EqualsIgnoreCase(VCardUtils::Trim(strArr[0]), VCARD_TYPE_BEGIN) &&
        VCardUtils::EqualsIgnoreCase(VCardUtils::Trim(strArr[1]), DATA_VCARD)) {
        return true;
    }
    return false;
}

void VCardDecoderV21::ParseItems(int32_t &errorCode)
{
    while (ParseItem(errorCode)) {
        if (errorCode != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("Failed to parse item");
            return;
        }
    }
}

bool VCardDecoderV21::ParseItem(int32_t &errorCode)
{
    currentEncoding_ = DEFAULT_ENCODING;
    std::string line = GetNonEmptyLine();
    if (line == "") {
        TELEPHONY_LOGI("File is finish");
        return false;
    }
    std::lock_guard<std::mutex> lock(rawDataMutex_);
    auto rawData = std::make_shared<VCardRawData>();
    BuildRawData(line, rawData, errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Build raw data failed");
        return false;
    }
    std::string name = VCardUtils::ToUpper(rawData->GetName());
    std::string rawDataValue = rawData->GetRawValue();
    if (name == VCARD_TYPE_END && VCardUtils::EqualsIgnoreCase(rawDataValue, DATA_VCARD)) {
        TELEPHONY_LOGI("Vcard parse end");
        return false;
    }
    if (name == VCARD_TYPE_AGENT) {
        DealAgent(rawData, errorCode);
        return true;
    }
    if (!IsValidName(name)) {
        TELEPHONY_LOGE("Name is invalid");
        return false;
    }
    DealRawDataValue(name, rawData, errorCode);
    return !fileUtils_.IsEnd();
}

void VCardDecoderV21::DealRawDataValue(
    const std::string &name, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    std::string nameUp = VCardUtils::ToUpper(rawData->GetName());
    std::string rawValue = rawData->GetRawValue();
    std::string sourceCharset = DEFAULT_INTERMEDIATE_CHARSET;
    auto charsets = rawData->GetParameters(VCARD_PARAM_CHARSET);
    std::string targetCharset = ((static_cast<int32_t>(charsets.size()) != 0) ? charsets[0] : "");
    if (targetCharset.empty()) {
        targetCharset = DEFAULT_IMPORT_CHARSET;
    }
    if (nameUp == VCARD_TYPE_ADR || nameUp == VCARD_TYPE_ORG || nameUp == VCARD_TYPE_N) {
        DealAdrOrgN(rawValue, rawData, sourceCharset, targetCharset, errorCode);
        return;
    }
    if (currentEncoding_ == VCARD_PARAM_ENCODING_QP ||
        ((nameUp == VCARD_TYPE_FN) && rawData->GetParameters(VCARD_PARAM_ENCODING).empty())) {
        DealEncodingQPOrNoEncodingFN(rawValue, rawData, sourceCharset, targetCharset, errorCode);
        return;
    }
    if (currentEncoding_ == VCARD_PARAM_ENCODING_BASE64 || currentEncoding_ == VCARD_PARAM_ENCODING_B) {
        DealBase64OrB(rawValue, rawData, errorCode);
        return;
    }
    if (!(currentEncoding_ == VCARD_PARAM_ENCODING_7BIT || currentEncoding_ == VCARD_PARAM_ENCODING_8BIT ||
            VCardUtils::StartWith(currentEncoding_, "X-"))) {
        TELEPHONY_LOGI("encoding is no support %{public}s ", currentEncoding_.c_str());
    }
    if (GetVersion() == VERSION_21) {
        DealV21Value(rawValue);
    }
    std::string temp = VCardUtils::ConvertCharset(rawValue, "", targetCharset, errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("GetQuotedPritableValue failed");
        return;
    }
    std::vector<std::string> valueList;
    std::string value = UnescapeText(temp);
    valueList.push_back(value);
    rawData->SetValues(valueList);
    NotifyRawDataCreated(rawData);
}

void VCardDecoderV21::DealV21Value(std::string &rawValue)
{
    std::string str;
    while (true) {
        std::string line = PeekLine();
        if (line.empty() || line[0] != ' ' || VCardUtils::ToUpper(line).find("END:VCARD") != std::string::npos) {
            break;
        }
        GetLine();
        if (str.empty()) {
            str = rawValue;
        }
        str += line.substr(1);
    }
    rawValue = str;
}

std::string VCardDecoderV21::GetVersion()
{
    return VERSION_21;
}

void VCardDecoderV21::DealBase64OrB(
    const std::string &rawValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    std::string base64 = GetBase64(rawValue, errorCode);
    rawData->SetByte(VCardUtils::DecodeBase64(base64));
    NotifyRawDataCreated(rawData);
}

void VCardDecoderV21::DealEncodingQPOrNoEncodingFN(const std::string &rawValue, std::shared_ptr<VCardRawData> rawData,
    const std::string &fromCharSet, const std::string &toCharSet, int32_t &errorCode)
{
    std::string quotedPrintableValue = GetQuotedPritableValue(rawValue, errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("GetQuotedPritableValue failed");
        return;
    }
    std::string encodedValue = ParseQuotedPrintableValue(quotedPrintableValue, fromCharSet, toCharSet, errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("GetQuotedPritableValue failed");
        return;
    }
    rawData->SetRawValue(quotedPrintableValue);
    rawData->AppendValues({ encodedValue });
    NotifyRawDataCreated(rawData);
}

bool VCardDecoderV21::IsValidName(const std::string &name)
{
    if (!(ContainValue(VCardUtils::ToUpper(name), GetSupportType()) || VCardUtils::StartWith(name, "X-"))) {
        unknowParamType_.insert(name);
    }
    return true;
}

std::string VCardDecoderV21::GetLine()
{
    std::string line = "";
    fileUtils_.ReadLine(line);
    return line;
}

std::string VCardDecoderV21::PeekLine()
{
    std::string line = "";
    fileUtils_.PeekLine(line);
    return line;
}

std::string VCardDecoderV21::GetNonEmptyLine()
{
    std::string line = "";
    while (fileUtils_.ReadLine(line)) {
        line = VCardUtils::Trim(line);
        if (!line.empty()) {
            break;
        }
    }
    return line;
}

void VCardDecoderV21::BuildRawData(const std::string &line, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    int32_t length = static_cast<int32_t>(line.length());
    if (length >= 0 && line[0] == '#') {
        TELEPHONY_LOGE("line is invalid");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return;
    }
    int32_t status = STATUS_GROUP_OR_TYPE_NAME;
    int32_t namePos = 0;
    errorCode = TELEPHONY_SUCCESS;
    for (int i = 0; i < length && errorCode == TELEPHONY_SUCCESS; i++) {
        if (status == STATUS_GROUP_OR_TYPE_NAME) {
            DealGroupOrTypeNameStatus(line, rawData, errorCode, status, namePos, i);
            continue;
        }
        if (status == STATUS_PARAMS) {
            DealParamsStatus(line, rawData, errorCode, status, namePos, i);
            continue;
        }
        if (status == STATUS_PARAMS_IN_DQUOTE) {
            status = STATUS_PARAMS;
            continue;
        }
    }
}

void VCardDecoderV21::DealGroupOrTypeNameStatus(const std::string &line, std::shared_ptr<VCardRawData> rawData,
    int32_t &errorCode, int32_t &status, int32_t &namePos, int32_t &index)
{
    if (line[index] == ':') {
        rawData->SetName(line.substr(namePos, index - namePos));
        rawData->SetRawValue(index < static_cast<int32_t>(line.length()) - 1 ? line.substr(index + 1) : "");
        index = static_cast<int32_t>(line.length());
        return;
    }

    if (line[index] == '.') {
        std::string groupName = line.substr(namePos, index - namePos);
        if (groupName.length() == 0) {
            TELEPHONY_LOGI("Empty group");
        } else {
            rawData->AppendGroup(groupName);
        }
        namePos = index + 1;
        return;
    }
    if (line[index] == ';') {
        rawData->SetName(line.substr(namePos, index - namePos));
        namePos = index + 1;
        status = STATUS_PARAMS;
        return;
    }
}

void VCardDecoderV21::DealParamsStatus(const std::string &line, std::shared_ptr<VCardRawData> rawData,
    int32_t &errorCode, int32_t &status, int32_t &namePos, int32_t &index)
{
    if (line[index] == '"') {
        status = STATUS_PARAMS_IN_DQUOTE;
        return;
    }
    if (line[index] == ';') {
        DealParams(line.substr(namePos, index - namePos), rawData, errorCode);
        namePos = index + 1;
        return;
    }

    if (line[index] == ':') {
        DealParams(line.substr(namePos, index - namePos), rawData, errorCode);
        namePos = index + 1;
        rawData->SetRawValue(index < static_cast<int32_t>(line.length()) - 1 ? line.substr(index + 1) : "");
        index = static_cast<int32_t>(line.length());
        return;
    }
}

void VCardDecoderV21::DealParams(const std::string &params, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    auto strs = VCardUtils::Split(params, "=");
    if (static_cast<int32_t>(strs.size()) == SIZE_TWO) {
        std::string name = VCardUtils::ToUpper(VCardUtils::Trim(strs[0]));
        std::string value = VCardUtils::Trim(strs[1]);
        if (name == VCARD_PARAM_TYPE) {
            DealTypeParam(value, rawData, errorCode);
            return;
        }
        if (name == VCARD_PARAM_VALUE) {
            DealValueParam(value, rawData, errorCode);
            return;
        }
        if (name == VCARD_PARAM_ENCODING) {
            DealEncodingParam(VCardUtils::ToUpper(value), rawData, errorCode);
            return;
        }
        if (name == VCARD_PARAM_CHARSET) {
            DealCharsetParam(value, rawData, errorCode);
            return;
        }
        if (name == VCARD_PARAM_LANGUAGE) {
            DealLanguageParam(value, rawData, errorCode);
            return;
        }
        if (VCardUtils::StartWith(name, "X-")) {
            DealAnyParam(name, value, rawData, errorCode);
            return;
        }
        TELEPHONY_LOGE("Param type is not support");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return;
    }
    DealNoNameParam((strs.size() == SIZE_ZERO) ? "" : strs[0], rawData, errorCode);
}

void VCardDecoderV21::DealNoNameParam(
    const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    DealTypeParam(paramValue, rawData, errorCode);
}

void VCardDecoderV21::DealTypeParam(const std::string &type, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    if (!(ContainValue(VCardUtils::ToUpper(type), GetSupportParamType()) || VCardUtils::StartWith(type, "X-"))) {
        unknowParamType_.insert(type);
    }
    rawData->AppendParameter(VCARD_PARAM_TYPE, type);
}

void VCardDecoderV21::DealValueParam(
    const std::string &value, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    if (!(ContainValue(VCardUtils::ToUpper(value), GetSupportParamValue()) || VCardUtils::StartWith(value, "X-"))) {
        unknowParamValue_.insert(value);
    }
    rawData->AppendParameter(VCARD_PARAM_VALUE, value);
}

void VCardDecoderV21::DealEncodingParam(
    const std::string &encoding, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    if (ContainValue(encoding, GetSupportParamEncoding()) || VCardUtils::StartWith(encoding, "X-")) {
        rawData->AppendParameter(VCARD_PARAM_ENCODING, encoding);
        currentEncoding_ = encoding;
        return;
    }
    TELEPHONY_LOGE("Encoding is not support");
    errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
}

void VCardDecoderV21::DealCharsetParam(
    const std::string &charset, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    currentCharset_ = charset;
    rawData->AppendParameter(VCARD_PARAM_CHARSET, charset);
}

void VCardDecoderV21::DealLanguageParam(
    const std::string &language, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    auto strs = VCardUtils::Split(language, "-");
    if (static_cast<int32_t>(strs.size()) != SIZE_TWO) {
        TELEPHONY_LOGE("Language error");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return;
    }
    if (!IsAllAscLetter(strs[0])) {
        TELEPHONY_LOGE("Language error");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return;
    }

    if (!IsAllAscLetter(strs[1])) {
        TELEPHONY_LOGE("Language error");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return;
    }
    rawData->AppendParameter(VCARD_PARAM_LANGUAGE, language);
}

void VCardDecoderV21::DealAnyParam(
    const std::string &param, const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    rawData->AppendParameter(param, paramValue);
}

std::vector<std::string> VCardDecoderV21::GetSupportParamType()
{
    return { "DOM", "INTL", "POSTAL", "PARCEL", "HOME", "WORK", "PREF", "VOICE", "FAX", "MSG", "CELL", "PAGER", "BBS",
        "MODEM", "CAR", "ISDN", "VIDEO", "AOL", "APPLELINK", "ATTMAIL", "CIS", "EWORLD", "INTERNET", "IBMMAIL",
        "MCIMAIL", "POWERSHARE", "PRODIGY", "TLX", "X400", "GIF", "CGM", "WMF", "BMP", "MET", "PMB", "DIB", "PICT",
        "TIFF", "PDF", "PS", "JPEG", "QTIME", "MPEG", "MPEG2", "AVI", "WAVE", "AIFF", "PCM", "X509", "PGP" };
}

std::vector<std::string> VCardDecoderV21::GetSupportParamValue()
{
    return { "INLINE", "URL", "CONTENT-ID", "CID" };
}

std::vector<std::string> VCardDecoderV21::GetSupportType()
{
    return { VCARD_TYPE_BEGIN, VCARD_TYPE_END, VCARD_TYPE_LOGO, VCARD_TYPE_PHOTO, "LABEL", VCARD_TYPE_FN,
        VCARD_TYPE_TITLE, "SOUND", VCARD_TYPE_VERSION, VCARD_TYPE_TEL, VCARD_TYPE_EMAIL, "TZ", "GEO", VCARD_TYPE_NOTE,
        VCARD_TYPE_URL, VCARD_TYPE_BDAY, "ROLE", "REV", "UID", "KEY", "MAILER" };
}

std::vector<std::string> VCardDecoderV21::GetSupportParamEncoding()
{
    return { VCARD_PARAM_ENCODING_7BIT, VCARD_PARAM_ENCODING_8BIT, VCARD_PARAM_ENCODING_QP, VCARD_PARAM_ENCODING_BASE64,
        VCARD_PARAM_ENCODING_B };
}

bool VCardDecoderV21::IsAllAscLetter(const std::string &value)
{
    for (auto ch : value) {
        if (!IsAscChar(ch)) {
            return false;
        }
    }
    return true;
}

bool VCardDecoderV21::ContainValue(const std::string &value, const std::vector<std::string> values)
{
    auto it = std::find(values.begin(), values.end(), value);
    return it != values.end();
}

void VCardDecoderV21::DealAdrOrgN(const std::string &rawValue, std::shared_ptr<VCardRawData> rawData,
    const std::string &fromCharSet, const std::string &toCharSet, int32_t &errorCode)
{
    std::vector<std::string> encodedValues;
    if (currentEncoding_ == VCARD_PARAM_ENCODING_QP) {
        std::string quotedPrintableValue = GetQuotedPritableValue(rawValue, errorCode);
        if (errorCode != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("GetQuotedPritableValue failed");
            return;
        }
        ParseQuotedPrintableValues(quotedPrintableValue, encodedValues, fromCharSet, toCharSet, errorCode);
        if (errorCode != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("ParseQuotedPrintableValues failed");
            return;
        }
        rawData->SetRawValue(quotedPrintableValue);
        rawData->AppendValues(encodedValues);
        NotifyRawDataCreated(rawData);
        return;
    }
    std::string value = VCardUtils::ConvertCharset(GetPoMultiLine(rawValue), "", toCharSet, errorCode);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ConvertCharset failed");
        return;
    }
    rawData->AppendValues(BuildListFromValue(value));
    NotifyRawDataCreated(rawData);
}

void VCardDecoderV21::ParseQuotedPrintableValues(const std::string &rawValue, std::vector<std::string> &encodedValues,
    const std::string &fromCharSet, const std::string &toCharSet, int32_t &errorCode)
{
    auto quotedPrintableList = BuildListFromValue(rawValue);
    for (auto temp : quotedPrintableList) {
        auto value = ParseQuotedPrintableValue(temp, fromCharSet, toCharSet, errorCode);
        if (errorCode != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("GetQuotedPritableValue failed");
            return;
        }
        encodedValues.push_back(value);
    }
}

std::string VCardDecoderV21::GetQuotedPritableValue(const std::string &str, int32_t &errorCode)
{
    std::string target;
    std::string firstStr = str;
    if (!VCardUtils::EndWith(VCardUtils::Trim(firstStr), "=")) {
        target += VCardUtils::Trim(firstStr);
        return target;
    }
    target += VCardUtils::Trim(firstStr) + "\r\n";
    std::string line;
    while (true) {
        line = GetLine();
        if (line.empty()) {
            TELEPHONY_LOGE("QuotedPritableValue error");
            errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
            return "";
        }
        if (!VCardUtils::EndWith(VCardUtils::Trim(line), "=")) {
            target += VCardUtils::Trim(line);
            return target;
        }
        target += VCardUtils::Trim(line) + "\r\n";
    }
}

std::string VCardDecoderV21::ParseQuotedPrintableValue(
    const std::string &from, const std::string &fromCharSet, const std::string &toCharSet, int32_t &errorCode)
{
    std::vector<std::string> lines = VCardUtils::Split(from, "\r\n");
    std::string printableValue;
    for (auto &it : lines) {
        if (VCardUtils::EndWith(it, "=")) {
            printableValue += it.substr(0, static_cast<int32_t>(it.length()) - 1);
            continue;
        }
        printableValue += it;
    }
    std::string encodeValue = DecodeQuotedPrintable(printableValue);
    return VCardUtils::ConvertCharset(encodeValue, "", toCharSet, errorCode);
}

std::string VCardDecoderV21::DecodeQuotedPrintable(const std::string &encodedString)
{
    std::istringstream iss(encodedString);
    std::ostringstream oss;
    char ch;
    while (iss.get(ch)) {
        if (ch == '=') {
            char hex[VALUE_INDEX_THREE] = { 0 };
            iss.get(hex, VALUE_INDEX_THREE);
            int decodedChar = std::stoi(hex, nullptr, DECODE_CHAR_MAX_SIZE);
            oss << static_cast<char>(decodedChar);
        } else {
            oss << ch;
        }
    }
    return oss.str();
}

std::vector<std::string> VCardDecoderV21::BuildListFromValue(const std::string &value)
{
    std::vector<std::string> list;
    std::string temp;
    int32_t length = static_cast<int32_t>(value.length());
    for (int i = 0; i < length; i++) {
        auto ch = value[i];
        if (ch == '\\' && i < length - 1) {
            char nextCh = value[i + 1];
            std::string unescapedStr = UnescapeChar(nextCh);
            if (!unescapedStr.empty()) {
                temp += unescapedStr;
                i++;
                continue;
            }
            temp += ch;
            continue;
        }
        if (ch == ';') {
            list.push_back(temp);
            temp = "";
            continue;
        }
        temp += ch;
    }
    list.push_back(temp);
    return list;
}

void VCardDecoderV21::DealAgent(std::shared_ptr<VCardRawData> rawData, int32_t &errorCode)
{
    if (VCardUtils::ToUpper(rawData->GetRawValue()).find("BEGIN : VCARD") != std::string::npos) {
        TELEPHONY_LOGE("Agent data error");
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return;
    }
    NotifyRawDataCreated(rawData);
}

std::string VCardDecoderV21::GetBase64(const std::string &value, int32_t &errorCode)
{
    std::string str;
    str += value;
    while (true) {
        std::string line = PeekLine();
        if (line.empty()) {
            break;
        }
        std::string nameUp = getUpperName(line);
        if (ContainValue(nameUp, GetSupportType())) {
            TELEPHONY_LOGI("GetBase64 contain vcard type");
            break;
        }
        GetLine();
        str += VCardUtils::Trim(line);
    }
    return str;
}

std::string VCardDecoderV21::UnescapeText(const std::string &from)
{
    return from;
}

std::string VCardDecoderV21::UnescapeChar(char ch)
{
    if (ch == '\\' || ch == ';' || ch == ':' || ch == ',') {
        return std::string(1, ch);
    }
    return "";
}

std::string VCardDecoderV21::GetPoMultiLine(const std::string &from)
{
    std::string str;
    str += from;
    while (true) {
        std::string line = PeekLine();
        if ((line.empty())) {
            break;
        }
        std::string name = getUpperName(line);
        if (!name.empty()) {
            break;
        }
        GetLine();
        str += " " + line;
    }
    return str;
}

std::string VCardDecoderV21::getUpperName(const std::string &line)
{
    auto colonIndex = line.find(":");
    auto semiColonIndex = line.find(";");
    if (colonIndex != std::string::npos || semiColonIndex != std::string::npos) {
        int32_t minIndex = static_cast<int32_t>(colonIndex);
        if (colonIndex == std::string::npos) {
            minIndex = static_cast<int32_t>(semiColonIndex);
        } else if (semiColonIndex != std::string::npos) {
            minIndex = std::min(colonIndex, semiColonIndex);
        }
        return VCardUtils::ToUpper(line.substr(0, minIndex));
    }
    return "";
}

bool VCardDecoderV21::IsAscChar(char ch)
{
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
        return true;
    }
    return false;
}

} // namespace Telephony
} // namespace OHOS
