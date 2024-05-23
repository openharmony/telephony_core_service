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
#include "operator_matching_rule.h"

using namespace std;
namespace OHOS {
namespace Telephony {
bool OperatorMatchingRule::IccidRegexMatch(const std::string &iccidFromSim, const std::string &iccidRegex)
{
    if (iccidFromSim.empty()) {
        return false;
    }
    return std::regex_match(iccidFromSim, std::regex(iccidRegex));
}

bool OperatorMatchingRule::ImsiRegexMatch(const std::string &imsiFromSim, const std::string &imsiRegex)
{
    if (imsiFromSim.empty()) {
        return false;
    }
    return std::regex_match(imsiFromSim, std::regex(imsiRegex));
}

bool OperatorMatchingRule::SpnRegexMatch(const std::string &spnFromSim, const std::string &spnRegex)
{
    if (spnRegex == "null") {
        if (spnFromSim.empty()) {
            return true;
        }
    }
    if (spnFromSim.empty()) {
        return false;
    }
    return std::regex_match(spnFromSim, std::regex(spnRegex));
}

bool OperatorMatchingRule::PrefixMatch(const std::string &valueFromSim, const std::string &valuePrefix)
{
    if (valueFromSim.empty()) {
        return false;
    }
    return !(valueFromSim.compare(PREFIX_INDEX, valuePrefix.size(), valuePrefix));
}
} // namespace Telephony
} // namespace OHOS
