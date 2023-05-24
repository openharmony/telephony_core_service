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

#include "icc_operator_rule.h"

#include <algorithm>
#include <charconv>
#include <system_error>

#include "telephony_log_wrapper.h"


namespace OHOS {
namespace Telephony {
constexpr int32_t INT32_INITVALUE = 0;
static bool readOneByte(std::string::const_iterator &it, const std::string::const_iterator &ed, int32_t &res)
{
    if (it == ed) {
        TELEPHONY_LOGE("can not readTLVLength for empty string!!' ");
        return false;
    }
    ++it;
    if (it == ed) {
        TELEPHONY_LOGE("can not readTLVLength for string length less 2");
        return false;
    }
    const auto [nextPtr, err] =
        std::from_chars(std::addressof(*(it - 1)), std::addressof(*(it + 1)), res, IccOperatorRule::HEX_);
    if (err != std::errc()) {
        const auto cond = std::make_error_condition(err);
        TELEPHONY_LOGE("readLength occurent error!! '%{public}s' ", cond.message().data());
        return false;
    }
    ++it;
    return true;
}

static bool parseSimpleTLV(std::string::const_iterator &it, const std::string::const_iterator &ed,
    std::string &tagName, int32_t &len, std::string &value)
{
    size_t inputSize = static_cast<long unsigned int>(std::distance(it, ed));
    if (inputSize < IccOperatorRule::TLV_STAG_CHARLEN) {
        std::string temp(it, ed);
        TELEPHONY_LOGE("parseSimpleTLV from '%{public}s' size:%{public}zu < %{public}d", temp.data(), inputSize,
            IccOperatorRule::TLV_STAG_CHARLEN);
        return false;
    }
    /* begin parse tagName */
    tagName.clear();
    std::copy_n(it, IccOperatorRule::TLV_STAG_CHARLEN, std::back_inserter(tagName));
    TELEPHONY_LOGI("parseSimpleTLV read tagName: '%{public}s' ", tagName.data());
    it += IccOperatorRule::TLV_STAG_CHARLEN;
    /* begin parse length */
    len = INT32_INITVALUE;
    if (inputSize < IccOperatorRule::TLV_STAG_CHARLEN + IccOperatorRule::TLV_LEN_CHARLEN) {
        std::string temp(it, ed);
        TELEPHONY_LOGE("parseSimpleTLV from '%{public}s' size:%{public}zu < %{public}d", temp.data(), inputSize,
            IccOperatorRule::TLV_STAG_CHARLEN + IccOperatorRule::TLV_LEN_CHARLEN);
        return false;
    }
    if (!readOneByte(it, ed, len)) {
        TELEPHONY_LOGE("parseSimpleTLV parse length fail!");
        return false;
    }
    /* begin parse value */
    value.clear();
    const auto valueCharLen = len + len;
    if (static_cast<int>(inputSize) <
        IccOperatorRule::TLV_STAG_CHARLEN + IccOperatorRule::TLV_LEN_CHARLEN + valueCharLen) {
        std::string temp(it, ed);
        TELEPHONY_LOGE("parseSimpleTLV from '%{public}s' size:%{public}zu < %{public}d", temp.data(), inputSize,
            IccOperatorRule::TLV_STAG_CHARLEN + IccOperatorRule::TLV_LEN_CHARLEN + valueCharLen);
        return false;
    }
    std::copy_n(it, valueCharLen, std::back_inserter(value));
    it += valueCharLen;
    return true;
}

bool IccOperatorRule::CreateFromTLV(const std::string &hexStr, std::vector<IccOperatorRule> &result)
{
    TELEPHONY_LOGI("IccOperatorRule::CreateFromTLV  by hexStr Begin!");
    return CreateFromTLV(hexStr.begin(), hexStr.end(), result);
}

bool IccOperatorRule::CreateFromTLV(const std::string::const_iterator &hexStrBeg,
    const std::string::const_iterator &hexStrEnd, std::vector<IccOperatorRule> &result)
{
    TELEPHONY_LOGD("IccOperatorRule::CreateFromTLV by iterator Begin!");
    result.clear();
    const auto &[hexStrIt, prefixIt] =
        std::mismatch(hexStrBeg, hexStrEnd, TAG_ALL_RULE.begin(), TAG_ALL_RULE.end());
    // when TAG_ALL_RULE not a prefix of hexStrBeg
    if (prefixIt != TAG_ALL_RULE.end()) {
        std::string temp(hexStrBeg, hexStrEnd);
        TELEPHONY_LOGE("hexStr:[%{public}s] not strartWith '%{public}s' !", temp.data(), TAG_ALL_RULE.data());
        return false;
    }
    TELEPHONY_LOGI("start parse after of tag:'%{public}s'  !", TAG_ALL_RULE.data());
    std::string::const_iterator strIt = hexStrBeg + TAG_ALL_RULE.size();
    int32_t len = INT32_INITVALUE;
    if (!readOneByte(strIt, hexStrEnd, len)) {
        TELEPHONY_LOGE("after tagStr '%{public}s' had not LenStr !", TAG_ALL_RULE.data());
        return false;
    }
    TELEPHONY_LOGI("read TAG_ALL_RULE len:%{public}d ", len);
    IccOperatorRule rule;
    int32_t totalLen = INT32_INITVALUE;
    while (strIt != hexStrEnd && totalLen < len) {
        int32_t ruleLen = INT32_INITVALUE;
        if (!DecodeTLVTagRule(strIt, hexStrEnd, rule, ruleLen)) {
            break;
        }
        totalLen += ruleLen;
        TELEPHONY_LOGI("DecodeRule once count:%{public}d ,TAG_ALL_RULE len:%{public}d", totalLen, len);
        result.push_back(rule);
    }
    TELEPHONY_LOGI("End parse element of Rule! Size:[%{public}zu]", result.size());
    return true;
}

bool IccOperatorRule::DecodeTLVTagCertPkg(
    std::string::const_iterator &hexStrBeg, const std::string::const_iterator &hexStrEnd, IccOperatorRule &result)
{
    TELEPHONY_LOGI("Start parse TAG_CERT_PKG(%{public}s) for [%{public}s]", TAG_CERT_PKG.data(),
        std::string(hexStrBeg, hexStrEnd).data());
    const auto [hexStrIt, prefixIt] = std::mismatch(hexStrBeg, hexStrEnd, TAG_CERT_PKG.begin(), TAG_CERT_PKG.end());
    if (prefixIt != TAG_CERT_PKG.end()) {
        std::string temp(hexStrBeg, hexStrEnd);
        TELEPHONY_LOGE("hexStr:[%{public}s] not strartWith '%{public}s' !", temp.data(), TAG_CERT_PKG.data());
        return false;
    }
    hexStrBeg += TAG_CERT_PKG.size();
    int32_t refDoLen = INT32_INITVALUE;
    if (!readOneByte(hexStrBeg, hexStrEnd, refDoLen)) {
        TELEPHONY_LOGE("after tagStr '%{public}s' had not LenStr !", TAG_CERT_PKG.data());
        return false;
    }
    bool hasCertificate = false;
    int32_t totalLen = INT32_INITVALUE;
    while (hexStrBeg != hexStrEnd && totalLen < refDoLen) {
        std::string tagName;
        int32_t length = INT32_INITVALUE;
        std::string value;
        if (!parseSimpleTLV(hexStrBeg, hexStrEnd, tagName, length, value)) {
            std::string temp(hexStrBeg, hexStrEnd);
            TELEPHONY_LOGE("can not parse simple TLV at : '%{public}s'", temp.data());
            return false;
        }
        totalLen += length + TLV_SIMPLE_TAG_ONEBYTE_LEN + TLV_SIMPLE_TAG_LENGTH_LEN;
        TELEPHONY_LOGI("parse more TLV count:%{public}d , refDoLen:%{public}d", totalLen, refDoLen);
        if (tagName == TAG_CERTIFICATE) {
            result.SetCertificate(std::move(value));
            hasCertificate = true;
        } else if (tagName == TAG_PACKAGE) {
            if (!result.SetPackageNameByHexStr(value)) {
                return false;
            }
        }
    }
    return hasCertificate;
}

bool IccOperatorRule::DecodeTLVTagLimits(
    std::string::const_iterator &hexStrBeg, const std::string::const_iterator &hexStrEnd, IccOperatorRule &result)
{
    TELEPHONY_LOGI("Start parse TAG_LIMITS(%{public}s) for [%{public}s]", TAG_LIMITS.data(),
        std::string(hexStrBeg, hexStrEnd).data());
    const auto [hexStrIt, prefixIt] = std::mismatch(hexStrBeg, hexStrEnd, TAG_LIMITS.begin(), TAG_LIMITS.end());
    if (prefixIt != TAG_LIMITS.end()) {
        std::string temp(hexStrBeg, hexStrEnd);
        TELEPHONY_LOGE("hexStr:[%{public}s] not strartWith '%{public}s' !", temp.data(), TAG_LIMITS.data());
        return false;
    }
    hexStrBeg += TAG_LIMITS.size();
    int32_t arDoLen = INT32_INITVALUE;
    if (!readOneByte(hexStrBeg, hexStrEnd, arDoLen)) {
        TELEPHONY_LOGE("after tagStr '%{public}s' had not LenStr !", TAG_LIMITS.data());
        return false;
    }
    int32_t totalLen = INT32_INITVALUE;
    bool isReadTagPermArDo = false;
    while (hexStrBeg != hexStrEnd && totalLen < arDoLen) {
        std::string tagName;
        int32_t length = INT32_INITVALUE;
        std::string value;
        if (!parseSimpleTLV(hexStrBeg, hexStrEnd, tagName, length, value)) {
            std::string temp(hexStrBeg, hexStrEnd);
            TELEPHONY_LOGE("can not parse simple TLV at : '%{public}s'", temp.data());
            return false;
        }
        totalLen += length + TLV_SIMPLE_TAG_ONEBYTE_LEN + TLV_SIMPLE_TAG_LENGTH_LEN;
        TELEPHONY_LOGI("parse more TLV count:%{public}d , arDolen:%{public}d", totalLen, arDoLen);
        if (tagName == TAG_LIMIT) {
            result.SetAccessLimit(std::move(value));
            isReadTagPermArDo = true;
        }
    }
    return isReadTagPermArDo;
}

bool IccOperatorRule::DecodeTLVTagRule(std::string::const_iterator &hexStrBeg,
    const std::string::const_iterator &hexStrEnd, IccOperatorRule &result, int32_t &len)
{
    TELEPHONY_LOGI(
        "Start parse TAG_RULE(%{public}s) for [%{public}s]", TAG_RULE.data(), std::string(hexStrBeg, hexStrEnd).data());
    len = INT32_INITVALUE;
    const auto [hexStrIt, prefixIt] =
        std::mismatch(hexStrBeg, hexStrEnd, TAG_RULE.begin(), TAG_RULE.end());
    if (prefixIt != TAG_RULE.end()) {
        TELEPHONY_LOGE("hexStr not strartWith '%{public}s' !", TAG_RULE.data());
        return false;
    }
    len += TLV_SIMPLE_TAG_ONEBYTE_LEN;
    hexStrBeg += TAG_RULE.size();
    int32_t refArLen = INT32_INITVALUE;
    if (!readOneByte(hexStrBeg, hexStrEnd, refArLen)) {
        TELEPHONY_LOGE("after tagStr '%{public}s' had not LenStr !", TAG_RULE.data());
        return false;
    }
    len += TLV_SIMPLE_TAG_LENGTH_LEN + refArLen;
    if (!DecodeTLVTagCertPkg(hexStrBeg, hexStrEnd, result)) {
        TELEPHONY_LOGE("DecodeTLVTagCertPkg fail !");
        return false;
    }
    if (!DecodeTLVTagLimits(hexStrBeg, hexStrEnd, result)) {
        TELEPHONY_LOGE("DecodeTLVTagLimits fail !");
        return false;
    }
    return true;
}

IccOperatorRule::IccOperatorRule() {}
IccOperatorRule::~IccOperatorRule() {}

void IccOperatorRule::GetPackageName(std::string &result) const
{
    result.clear();
    result = std::string(packageName_.begin(), packageName_.end());
}

void IccOperatorRule::SetPackageName(const std::string &packageName)
{
    this->packageName_ = packageName;
}

void IccOperatorRule::SetPackageName(std::string &&packageName)
{
    this->packageName_.swap(packageName);
}

bool IccOperatorRule::SetPackageNameByHexStr(const std::string &hexStr)
{
    packageName_.clear();
    auto it = hexStr.begin();
    while (it != hexStr.end()) {
        int32_t value = INT32_INITVALUE;
        if (!readOneByte(it, hexStr.end(), value)) {
            TELEPHONY_LOGE("IccOperatorRule::SetPackageNameByHexStr fail !");
            return false;
        }
        this->packageName_.push_back(static_cast<char>(value));
    }
    return true;
}

void IccOperatorRule::GetCertificate(std::string &result) const
{
    result.clear();
    result = std::string(certificate_.begin(), certificate_.end());
}

void IccOperatorRule::SetCertificate(const std::string &certificate)
{
    this->certificate_ = certificate;
}

void IccOperatorRule::SetCertificate(std::string &&certificate)
{
    this->certificate_.swap(certificate);
}

void IccOperatorRule::SetAccessLimit(const std::string &accessLimit)
{
    this->accessLimit_ = accessLimit;
}

void IccOperatorRule::SetAccessLimit(std::string &&accessLimit)
{
    this->accessLimit_.swap(accessLimit);
}

bool IccOperatorRule::Matche(const std::string_view &certHash, const std::string_view &packageName) const
{
    bool res = (this->certificate_ == certHash);
    if (this->packageName_.empty()) {
        return res;
    }
    return res && (this->packageName_ == packageName);
}
} // namespace Telephony
} // namespace OHOS
