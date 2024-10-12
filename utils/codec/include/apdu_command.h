/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef APDU_COMMAND_H
#define APDU_COMMAND_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Telephony {
struct ApduData {
    /* Class of an APDU as defined in GlobalPlatform Card Specification v.2.3. */
    uint32_t cla = 0;

    /* Instruction of an APDU as defined in GlobalPlatform Card Specification v.2.3. */
    uint32_t ins = 0;

    /* Parameter 1 of an APDU as defined in GlobalPlatform Card Specification v.2.3. */
    uint32_t p1 = 0;

    /* Parameter 2 of an APDU as defined in GlobalPlatform Card Specification v.2.3. */
    uint32_t p2 = 0;

    /* Parameter 3 of an APDU as defined in GlobalPlatform Card Specification v.2.3. */
    uint32_t p3 = 0;

    /* Command data of an APDU as defined in GlobalPlatform Card Specification v.2.3. */
    std::string cmdHex = "";
};

struct ApduCommand {
    /* Channel of an APDU as defined in GlobalPlatform Card Specification v.2.3. */
    uint32_t channel = 0;

    /* Apdu data. */
    ApduData data;

    ApduCommand(int32_t channelId, const ApduData &apduData) : channel(channelId), data(apduData) {}
};
} // namespace Telephony
} // namespace OHOS
#endif // APDU_COMMAND_H