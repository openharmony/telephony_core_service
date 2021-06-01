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

#include <stdio.h>
#include <codecvt>
#include <locale>
#include <string>

#ifndef CALL_MANAGER_STR_CONVERT_H
#define CALL_MANAGER_STR_CONVERT_H

namespace OHOS {
std::u16string ToUtf16(std::string str);
std::string ToUtf8(std::u16string str16);
std::u32string ToUtf32(std::string str);
std::string ToUtf8(std::u32string str32);
std::wstring ToWcharT(std::string str);
std::string ToUtf8(std::wstring wstr);
} // namespace OHOS
#endif // CALL_MANAGER_STR_CONVERT_H
