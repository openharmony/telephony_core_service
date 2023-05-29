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

#include "telephony_config.h"

#include <securec.h>

#include "parameters.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
static const uint32_t BCD_MAX_VALUE = 15;
static const uint32_t ASCII_BASE_OFFSET_VALUE = 10;
static const uint32_t MODEM_CAP_MIN_VALUE = 0;
static const uint32_t MODEM_CAP_MAX_VALUE = 32;
static const uint32_t BCD_LEN = 4;
static const uint32_t BASE_VALUE = 1;
static const int32_t INVALID_VALUE = -1;
static const int32_t VALID_VALUE = 0;
static const uint32_t VALID_VALUE_LENGTH = 100;
static constexpr const char *NULL_STRING = "";
static constexpr const char *MODEM_CAP = "persist.radio.modem.cap";

bool TelephonyConfig::IsCapabilitySupport(uint32_t capablity)
{
    if (capablity < MODEM_CAP_MIN_VALUE || capablity >= MODEM_CAP_MAX_VALUE) {
        TELEPHONY_LOGE("IsCapabilitySupport capablity is out of range.");
        return false;
    }
    uint32_t bcdIndex = capablity / BCD_LEN;
    uint32_t bcdOffset = capablity % BCD_LEN;
    std::string maxCap = system::GetParameter(MODEM_CAP, NULL_STRING);
    uint32_t bcdValue = BCD_MAX_VALUE + 1;
    if (ConvertCharToInt(bcdValue, maxCap, bcdIndex) != VALID_VALUE) {
        return false;
    }
    if (bcdValue > BCD_MAX_VALUE) {
        return false;
    }
    return (bcdValue & (BASE_VALUE << (BCD_LEN - BASE_VALUE - bcdOffset))) > 0;
}

int32_t TelephonyConfig::ConvertCharToInt(uint32_t &retValue, const std::string &maxCap, uint32_t index)
{
    if (index > VALID_VALUE_LENGTH) {
        return INVALID_VALUE;
    }
    if (maxCap.length() > static_cast<size_t>(VALID_VALUE_LENGTH)) {
        return INVALID_VALUE;
    }
    char content[VALID_VALUE_LENGTH + 1] = { 0 };
    size_t cpyLen = maxCap.length() + 1;
    if (strcpy_s(content, cpyLen, maxCap.c_str()) != EOK) {
        TELEPHONY_LOGE("ConvertCharToInt strcpy_s fail.");
        return INVALID_VALUE;
    }

    char originChar = content[index];
    if (originChar >= '0' && originChar <= '9') {
        retValue = static_cast<uint32_t>(originChar - '0');
    } else if (originChar >= 'a' && originChar <= 'f') {
        retValue = static_cast<uint32_t>(originChar - 'a') + ASCII_BASE_OFFSET_VALUE;
    } else if (originChar >= 'A' && originChar <= 'F') {
        retValue = static_cast<uint32_t>(originChar - 'A') + ASCII_BASE_OFFSET_VALUE;
    } else {
        return INVALID_VALUE;
    }
    return VALID_VALUE;
}
} // namespace Telephony
} // namespace OHOS
