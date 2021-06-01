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

#ifndef STR_CONVERT_H
#define STR_CONVERT_H

#include <codecvt>
#include <cstdio>
#include <locale>
#include <string>

namespace OHOS {
namespace CellularData {
std::u16string ToUtf16(std::string str);
std::string ToUtf8(std::u16string str16);
std::u32string ToUtf32(std::string str);
std::string ToUtf8(std::u32string str32);
std::string ToUtf8(std::wstring wstr);
} // namespace CellularData
} // namespace OHOS
#endif // STR_CONVERT_H
