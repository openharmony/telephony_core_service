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

#ifndef ASN1_CONSTANTS_H
#define ASN1_CONSTANTS_H

#include <cctype>
#include <iomanip>

namespace OHOS {
namespace Telephony {
const uint32_t BYTE_TO_HEX_LEN = 2;
const uint32_t OFFSET_EIGHT_BIT = 8;
const int32_t BIT6_MASK = 0x20;
const int32_t BIT8_MASK = 0x80;
const uint32_t MAX_UINT8 = std::numeric_limits<uint8_t>::max();
const uint32_t MAX_UINT16 = std::numeric_limits<uint16_t>::max();
const uint32_t MAX_UINT24 = (std::numeric_limits<uint32_t>::max() >> 8);
const uint32_t MAX_INT8 = std::numeric_limits<int8_t>::max();
const uint32_t MAX_INT16 = std::numeric_limits<int16_t>::max();
const uint32_t MAX_INT24 = (std::numeric_limits<int32_t>::max() >> 8);
} // namespace Telephony
} // namespace OHOS
#endif // ASN1_CONSTANTS_H