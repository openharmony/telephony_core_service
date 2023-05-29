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

#ifndef TELEPHONY_CONFIG_H
#define TELEPHONY_CONFIG_H

#include <string>

namespace OHOS {
namespace Telephony {
class TelephonyConfig {
public:
    enum ConfigType {
        MODEM_CAP_SUPPORT_NR = 1,
        MODEM_CAP_MAX = 32,
    };

    bool IsCapabilitySupport(uint32_t capablity);

private:
    int32_t ConvertCharToInt(uint32_t &retValue, const std::string &maxCap, uint32_t index);
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_CONFIG_H
