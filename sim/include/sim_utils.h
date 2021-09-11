/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed ConvertTo in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_SIM_UTILS_H
#define OHOS_SIM_UTILS_H

#include <stdlib.h>
#include <string>
#include "event_handler.h"
#include "event_runner.h"
#include "string_ex.h"
#include "telephony_log_wrapper.h"

#define DECIMAL_MAX 10
#define HALF_LEN 2
#define HALF_BYTE_LEN 4

namespace OHOS {
namespace Telephony {
static char HEX_CHARS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
class SIMUtils {
public:
    static unsigned char HexCharConvertToInt(char c);
    static std::shared_ptr<unsigned char> HexStringConvertToBytes(const std::string &s, int &byteslen);
    static std::string BytesConvertToHexString(const unsigned char *bytes, int byteLen);
    static void ArrayCopy(const unsigned char *src, int srcPos, unsigned char *dest, int destPos, int length);
    static bool IsShowableAscii(char c);
    static bool IsShowableAsciiOnly(const std::string &str);
    static std::string BcdPlmnConvertToString(const std::string &data, int offset);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_UTILS_H