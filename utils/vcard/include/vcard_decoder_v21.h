/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_VCARD_DECODER_V21_H
#define OHOS_VCARD_DECODER_V21_H

#include <memory>
#include <mutex>
#include <set>

#include "vcard_decoder.h"
#include "vcard_raw_data.h"

namespace OHOS {
namespace Telephony {
class VCardDecoderV21 : public VCardDecoder {
public:
    virtual void AddVCardDecodeListener(std::shared_ptr<VCardDecodeListener> listener);
    virtual void Decode(int32_t &errorCode);
    virtual bool DecodeOne(int32_t &errorCode);

protected:
    bool ReadBegin();
    void ParseItems(int32_t &errorCode);
    bool ParseItem(int32_t &errorCode);
    void DealRawDataValue(const std::string &name, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual std::string GetVersion();
    bool IsValidName(const std::string &name);
    virtual std::string GetLine();
    virtual std::string PeekLine();
    virtual std::string GetNonEmptyLine();
    void BuildRawData(const std::string &line, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual void DealParams(const std::string &params, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual void DealNoNameParam(
        const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual void DealTypeParam(const std::string &type, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    void DealValueParam(const std::string &value, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    void DealEncodingParam(const std::string &encoding, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    void DealCharsetParam(const std::string &charset, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    void DealLanguageParam(const std::string &language, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual void DealAnyParam(const std::string &param, const std::string &paramValue,
        std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual std::vector<std::string> GetSupportParamType();
    virtual std::vector<std::string> GetSupportParamValue();
    virtual std::vector<std::string> GetSupportType();
    virtual std::vector<std::string> GetSupportParamEncoding();
    void DealAdrOrgN(const std::string &rawValue, std::shared_ptr<VCardRawData> rawData, const std::string &fromCharSet,
        const std::string &toCharSet, int32_t &errorCode);
    void DealAgent(std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual std::string GetBase64(const std::string &value, int32_t &errorCode);
    virtual std::string UnescapeText(const std::string &from);
    virtual std::string UnescapeChar(char ch);

protected:
    std::set<std::string> unknowParamType_;
    std::set<std::string> unknowParamValue_;

private:
    void DealV21Value(std::string &rawValue);
    void DealBase64OrB(const std::string &rawValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    void DealEncodingQPOrNoEncodingFN(const std::string &rawValue, std::shared_ptr<VCardRawData> rawData,
        const std::string &fromCharSet, const std::string &toCharSet, int32_t &errorCode);
    void DealGroupOrTypeNameStatus(const std::string &line, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode,
        int32_t &status, int32_t &namePos, int32_t &index);
    void DealParamsStatus(const std::string &line, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode,
        int32_t &status, int32_t &namePos, int32_t &index);
    bool IsAllAscLetter(const std::string &value);
    bool ContainValue(const std::string &value, const std::vector<std::string> values);
    void ParseQuotedPrintableValues(const std::string &rawValue, std::vector<std::string> &encodedValues,
        const std::string &fromCharSet, const std::string &toCharSet, int32_t &errorCode);
    std::string ParseQuotedPrintableValue(
        const std::string &from, const std::string &fromCharSet, const std::string &toCharSet, int32_t &errorCode);
    std::string GetQuotedPritableValue(const std::string &str, int32_t &errorCode);
    std::string DecodeQuotedPrintable(const std::string &encodedString);
    std::vector<std::string> BuildListFromValue(const std::string &value);
    std::string GetPoMultiLine(const std::string &from);
    std::string getUpperName(const std::string &from);
    bool IsAscChar(char ch);
    void NotifyStarted();
    void NotifyEnded();
    void NotifyOneContactStarted();
    void NotifyOneContactEnded();
    void NotifyRawDataCreated(std::shared_ptr<VCardRawData> rawData);

private:
    std::string currentEncoding_;
    std::string currentCharset_;
    std::vector<std::shared_ptr<VCardDecodeListener>> listeners_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_DECODER_V21_H