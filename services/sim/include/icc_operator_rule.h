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

#ifndef OHOS_USIM_ACCESS_RULE_H
#define OHOS_USIM_ACCESS_RULE_H

#include <string>
#include <vector>

namespace OHOS {
namespace Telephony {
class IccOperatorRule {
public:
    inline constexpr static std::string_view TAG_ALL_RULE = "FF40";
    inline constexpr static std::string_view TAG_RULE = "E2";
    inline constexpr static std::string_view TAG_CERT_PKG = "E1";
    inline constexpr static std::string_view TAG_CERTIFICATE = "C1";
    inline constexpr static std::string_view TAG_PACKAGE = "CA";
    inline constexpr static std::string_view TAG_LIMITS = "E3";
    inline constexpr static std::string_view TAG_LIMIT = "DB";
    inline constexpr static int32_t TLV_SIMPLE_TAG_ONEBYTE_LEN = 1;
    inline constexpr static int32_t TLV_SIMPLE_TAG_LENGTH_LEN = 1;
    inline constexpr static int32_t TLV_LEN_CHARLEN = 2;
    inline constexpr static int32_t TLV_STAG_CHARLEN = 2;
    inline constexpr static int32_t TLV_ONEBYTE_CHARLEN = 2;
    inline constexpr static int32_t HEX_LEN = 10;
    inline constexpr static int32_t HEX_ = 16;

public:
    static bool CreateFromTLV(const std::string::const_iterator &hexStrBeg,
        const std::string::const_iterator &hexStrEnd, std::vector<IccOperatorRule> &result);
    static bool CreateFromTLV(const std::string &hexStr, std::vector<IccOperatorRule> &result);

public:
    IccOperatorRule();
    virtual ~IccOperatorRule();

    bool Matche(const std::string_view &certHash, const std::string_view &packageName) const;

    void GetPackageName(std::string &result) const;
    void SetPackageName(const std::string &packageName);
    void SetPackageName(std::string &&packageName);
    bool SetPackageNameByHexStr(const std::string &hexStr);

    void GetCertificate(std::string &result) const;
    void SetCertificate(const std::string &certificate);
    void SetCertificate(std::string &&certificate);

    void SetAccessLimit(const std::string &accessLimit);
    void SetAccessLimit(std::string &&accessLimit);

private:
    static bool DecodeTLVTagRule(std::string::const_iterator &hexStrBeg,
        const std::string::const_iterator &hexStrEnd, IccOperatorRule &result, int32_t &len);
    static bool DecodeTLVTagCertPkg(std::string::const_iterator &hexStrBeg,
        const std::string::const_iterator &hexStrEnd, IccOperatorRule &result);
    static bool DecodeTLVTagLimits(std::string::const_iterator &hexStrBeg,
        const std::string::const_iterator &hexStrEnd, IccOperatorRule &result);

private:
    std::string packageName_;
    std::string certificate_;
    std::string accessLimit_;
};
} // namespace Telephony
} // namespace OHOS

#endif
