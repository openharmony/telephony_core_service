/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use & file except in compliance with the License.
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

#include "sim_file_parse.h"
#include "sim_utils.h"
#include "icc_file.h"
#include "tag_service.h"
#include "telephony_common_utils.h"

namespace OHOS {
namespace Telephony {

const int HEXADECIMAL = 16;
const size_t OPL_5G_LENGTH = 10;
const int TAG_SPDI = 0xA3;
const int TAG_SPDI_PLMN_LIST = 0x80;

std::string SimFileParse::ParseSpn(const std::string &rawData, int spnStatus, SimFile &simFile)
{
    int offset = 0;
    int length = 0;
    std::shared_ptr<unsigned char> bytesRaw = SIMUtils::HexStringConvertToBytes(rawData, length);
    std::shared_ptr<unsigned char> bytesNew = nullptr;
    std::string ret = "";
    if (bytesRaw == nullptr) {
        TELEPHONY_LOGE("ParseSpn invalid data: %{public}s", rawData.c_str());
        return "";
    }
    TELEPHONY_LOGI("ParseSpn rawData: %{public}s, %{public}d, %{public}d", rawData.c_str(), spnStatus, length);
    if (spnStatus == simFile.OBTAIN_SPN_GENERAL) {
        offset = 0;
        length -= simFile.INVALID_BYTES_NUM;
        bytesNew = std::shared_ptr<unsigned char>(
            bytesRaw.get() + simFile.INVALID_BYTES_NUM, [bytesRaw](unsigned char *) {}); // first is 0, +1
        ret = SIMUtils::DiallingNumberStringFieldConvertToString(bytesNew, offset, length, simFile.SPN_CHAR_POS);
    } else if ((spnStatus == simFile.OBTAIN_OPERATOR_NAMESTRING)
                || (spnStatus == simFile.OBTAIN_OPERATOR_NAME_SHORTFORM)) {
        TELEPHONY_LOGI("Parse CPHS");
        ret = SIMUtils::Cphs7bitConvertToString(rawData);
    } else {
        return "";
    }
    TELEPHONY_LOGI("SimFile::ParseSpn spn: %{public}s", ret.c_str());
    return ret;
}

void SimFileParse::ParsePnn(const std::vector<std::string> &records, SimFile &simFile)
{
    simFile.pnnFiles_.clear();
    if (records.empty()) {
        TELEPHONY_LOGI("ParsePnn records is empty");
        return;
    }
    for (const auto &dataPnn : records) {
        TELEPHONY_LOGI("ParsePnn: %{public}s", dataPnn.c_str());
        int recordLen = 0;
        std::shared_ptr<unsigned char> data = SIMUtils::HexStringConvertToBytes(dataPnn, recordLen);
        if (data == nullptr) {
            TELEPHONY_LOGD("ParsePnn data is nullptr");
            continue;
        }
        unsigned char *tlv = data.get();
        std::shared_ptr<PlmnNetworkName> file = std::make_shared<PlmnNetworkName>();
        const int tagAndLength = NETWORK_NAME_LENGTH + 1;
        if (recordLen <= tagAndLength) {
            TELEPHONY_LOGD("recordLen <= tagAndLength");
            continue;
        }
        if (recordLen >= (tagAndLength + static_cast<int>(tlv[NETWORK_NAME_LENGTH])) &&
            tlv[NETWORK_NAME_IEI] == (unsigned char)LONG_NAME_FLAG) {
            file->longName =
                SIMUtils::Gsm7bitConvertToString(tlv + NETWORK_NAME_TEXT_STRING, tlv[NETWORK_NAME_LENGTH] - 1);
        }
        const int shortNameOffset = tagAndLength + tlv[NETWORK_NAME_LENGTH];
        if (recordLen > (shortNameOffset + tagAndLength) &&
            recordLen >=
            (shortNameOffset + tagAndLength + static_cast<int>(tlv[shortNameOffset + NETWORK_NAME_LENGTH])) &&
            tlv[shortNameOffset + NETWORK_NAME_IEI] == (unsigned char)SHORT_NAME_FLAG) {
            file->shortName = SIMUtils::Gsm7bitConvertToString(
                tlv + (shortNameOffset + NETWORK_NAME_TEXT_STRING), tlv[shortNameOffset + NETWORK_NAME_LENGTH] - 1);
        }
        TELEPHONY_LOGI("longName: %{public}s, shortName: %{public}s", file->longName.c_str(), file->shortName.c_str());
        simFile.pnnFiles_.push_back(file);
    }
}

void SimFileParse::ParseOpl(const std::vector<std::string> &records, SimFile &simFile)
{
    simFile.oplFiles_.clear();
    if (records.empty()) {
        TELEPHONY_LOGI("ParseOpl records is empty");
        return;
    }
    for (const auto &dataOpl : records) {
        TELEPHONY_LOGD("ParseOpl: %{public}s", dataOpl.c_str());
        if (dataOpl.size() != (BYTE_LENGTH + BYTE_LENGTH)) {
            continue;
        }
        if (!IsValidHexValue(dataOpl)) {
            TELEPHONY_LOGI("InputValue is not a hexadecimal number");
            continue;
        }
        std::string plmn = SIMUtils::BcdPlmnConvertToString(dataOpl, 0);
        if (plmn.empty()) {
            continue;
        }
        std::shared_ptr<OperatorPlmnInfo> file = std::make_shared<OperatorPlmnInfo>();
        file->plmnNumeric = plmn;

        file->lacStart = stoi(dataOpl.substr(MCCMNC_LEN, HALF_BYTE_LEN), 0, HEXADECIMAL);
        file->lacEnd = stoi(dataOpl.substr(MCCMNC_LEN + HALF_BYTE_LEN, HALF_BYTE_LEN), 0, HEXADECIMAL);
        file->pnnRecordId = stoi(dataOpl.substr(MCCMNC_LEN + BYTE_LENGTH, HALF_LEN), 0, HEXADECIMAL);
        TELEPHONY_LOGI("plmnNumeric: %{public}s, lacStart: %{public}d, lacEnd: %{public}d, pnnRecordId: %{public}d",
            file->plmnNumeric.c_str(), file->lacStart, file->lacEnd, file->pnnRecordId);
        simFile.oplFiles_.push_back(file);
    }
}

void SimFileParse::ParseOpl5g(const std::vector<std::string> &records, SimFile &simFile)
{
    simFile.opl5gFiles_.clear();
    if (records.empty()) {
        TELEPHONY_LOGE("ParseOpl5g records is empty");
        return;
    }
    std::regex express("[0-9a-fA-F]+");
    for (const auto &dataOpl : records) {
        TELEPHONY_LOGD("ParseOpl5g: %{public}s", dataOpl.c_str());
        if (dataOpl.size() != (OPL_5G_LENGTH + OPL_5G_LENGTH)) {
            continue;
        }
        if (!regex_match(dataOpl, express)) {
            TELEPHONY_LOGI("InputValue is not a hexadecimal number");
            continue;
        }
        std::string plmn = SIMUtils::BcdPlmnConvertToString(dataOpl, 0);
        if (plmn.empty()) {
            continue;
        }
        std::shared_ptr<OperatorPlmnInfo> file = std::make_shared<OperatorPlmnInfo>();
        file->plmnNumeric = plmn;
        file->lacStart = stoi(dataOpl.substr(MCCMNC_LEN, LAC_RANGE_LEN), 0, HEXADECIMAL);
        file->lacEnd = stoi(dataOpl.substr(MCCMNC_LEN + LAC_RANGE_LEN, LAC_RANGE_LEN), 0, HEXADECIMAL);
        file->pnnRecordId = stoi(dataOpl.substr(MCCMNC_LEN + LAC_RANGE_LEN + LAC_RANGE_LEN, HALF_LEN), 0, HEXADECIMAL);
        TELEPHONY_LOGD("plmnNumeric: %{public}s, lacStart: %{public}d, lacEnd: %{public}d, pnnRecordId: %{public}d",
            file->plmnNumeric.c_str(), file->lacStart, file->lacEnd, file->pnnRecordId);
        simFile.opl5gFiles_.push_back(file);
    }
}

void SimFileParse::ParseEhplmn(std::string data, SimFile &simFile)
{
    simFile.ehplmns_.clear();
    if (data.size() < 6) { // 6 is the length of one record of PLMN
        TELEPHONY_LOGE("ParseEhplmn invalid data");
        return;
    }
    for (size_t i = 0; i + 6 <= data.size(); i += 6) { // EFEHPLMN, 6 is the length of one record of PLMN
        std::string plmnCode = SIMUtils::BcdPlmnConvertToString(data, i);
        if (!plmnCode.empty()) {
            simFile.ehplmns_.insert(plmnCode);
        }
    }
}

void SimFileParse::ParseSpdi(std::string data, SimFile &simFile)
{
    simFile.spdiPlmns_.clear();
    TELEPHONY_LOGI("ParseSpdi start");
    if (data.empty()) {
        TELEPHONY_LOGE("ParseSpdi invalid data");
        return;
    }
    const std::string &rawData = data;
    std::shared_ptr<TagService> recTlv = std::make_shared<TagService>(rawData);
    int tag = 0;
    std::vector<uint8_t> datav;
    while (recTlv->Next()) {
        tag = recTlv->GetTagCode();
        // Skip SPDI tag, if existant
        if (tag == TAG_SPDI) {
            recTlv->GetValue(datav);
            recTlv = std::make_shared<TagService>(datav);
        }
        if (tag == TAG_SPDI_PLMN_LIST) {
            recTlv->GetValue(datav);
        }
    }
    if (datav.empty()) {
        return;
    }
    std::string plmnRawData = SIMUtils::HexVecToHexStr(datav);
    if (plmnRawData.size() < 6) { // 6 is the length of one record of PLMN
        return;
    }
    for (size_t i = 0; i + 6 <= plmnRawData.size(); i += 6) { // EFSPDI, 6 is the length of one record of PLMN
        std::string plmnCode = SIMUtils::BcdPlmnConvertToString(plmnRawData, i);
        if (!plmnCode.empty()) {
            TELEPHONY_LOGD("EF_SPDI PLMN: %{public}s", plmnCode.c_str());
            simFile.spdiPlmns_.insert(plmnCode);
        }
    }
}

} // namespace Telephony
} // namespace OHOS
