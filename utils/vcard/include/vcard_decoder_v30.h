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

#ifndef OHOS_VCARD_DECODER_V30_H
#define OHOS_VCARD_DECODER_V30_H

#include "vcard_decoder_v21.h"

namespace OHOS {
namespace Telephony {
class VCardDecoderV30 : public VCardDecoderV21 {
protected:
    virtual bool ReadBegin();
    virtual std::string GetLine();
    virtual std::string PeekLine();
    virtual std::string GetNonEmptyLine();
    virtual void DealParams(const std::string &params, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual void DealAnyParam(const std::string &param, const std::string &paramValue,
        std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual void DealNoNameParam(
        const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual void DealTypeParam(
        const std::string &paramValue, std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual void DealAgent(std::shared_ptr<VCardRawData> rawData, int32_t &errorCode);
    virtual std::string UnescapeText(const std::string &from);
    virtual std::string UnescapeChar(char ch);
    virtual std::string GetVersion();
    virtual std::string GetBase64(const std::string &value, int32_t &errorCode);
    virtual std::vector<std::string> GetSupportType();

private:
    void DealParmV30(const std::string &param, const std::string &paramValue, std::shared_ptr<VCardRawData> rawData,
        int32_t &errorCode);
    std::string EncodeParamValue(const std::string &paramValue);

private:
    std::string preLine_ = "";
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_DECODER_V30_H