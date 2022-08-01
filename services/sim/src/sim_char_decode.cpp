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

#include "sim_char_decode.h"

using namespace std;

namespace OHOS {
namespace Telephony {
SimCharDecode::SimCharDecode() {}

bool SimCharDecode::IsChineseString(const std::string &str)
{
    uint32_t len = str.length();
    for (uint32_t i = 0; i < len; i++) {
        if (str[i] & CHINESE_FLAG) {
            return true;
        }
    }
    return false;
}

SimCharDecode::~SimCharDecode() {}
} // namespace Telephony
} // namespace OHOS
