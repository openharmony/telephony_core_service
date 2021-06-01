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

#include "str_convert.h"

namespace OHOS {
std::u16string ToUtf16(std::string str)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.from_bytes(str);
}

std::string ToUtf8(std::u16string str16)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.to_bytes(str16);
}

std::u32string ToUtf32(std::string str)
{
    return std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> {}.from_bytes(str);
}

std::string ToUtf8(std::u32string str32)
{
    return std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> {}.to_bytes(str32);
}

std::wstring ToWcharT(std::string str)
{
    return std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> {}.from_bytes(str);
}

std::string ToUtf8(std::wstring wstr)
{
    return std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> {}.to_bytes(wstr);
}
} // namespace OHOS
