/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_OPERATOR_MATCHING_RULE_H
#define OHOS_OPERATOR_MATCHING_RULE_H

#include <regex>
#include <string>

#include "string_ex.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
static const std::string MCCMNC = "mccmnc";
static const std::string ICCID = "iccid";
static const std::string IMSI = "imsi";
static const std::string SPN = "spn";
static const std::string GID1 = "gid1";
static const std::string GID2 = "gid2";
static const std::string OPKEY = "operator_key";
static const std::string OPKEY_EXT = "operator_key_ext";
static const std::string OPNAME = "operator_name";
static const int32_t PREFIX_INDEX = 0;
class OperatorMatchingRule {
public:
    static bool IccidRegexMatch(const std::string &iccidFromSim, const std::string &iccidRegex);
    static bool ImsiRegexMatch(const std::string &imsiFromSim, const std::string &imsiRegex);
    static bool SpnRegexMatch(const std::string &spnFromSim, const std::string &spnRegex);
    static bool PrefixMatch(const std::string &valueFromSim, const std::string &valuePrefix);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_OPERATOR_MATCHING_RULE_H