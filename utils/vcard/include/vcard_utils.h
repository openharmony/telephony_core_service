/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef VCARD_UTILS_H
#define VCARD_UTILS_H

#include <string>
#include <vector>

namespace OHOS {
namespace Telephony {
class VCardUtils {
public:
    static bool EqualsIgnoreCase(const std::string &str1, const std::string &str2);
    static std::vector<std::string> Split(const std::string &input, const std::string &delimiter);
    static std::string Trim(std::string &str);
    static std::string ToUpper(const std::string &str);
    static bool StartWith(const std::string &str, const std::string &prefix);
    static bool EndWith(const std::string &fullString, const std::string &ending);
    static std::string EncodeBase64(const std::string &from);
    static std::string DecodeBase64(const std::string &encoded);
    static std::string DecodeBase64NoWrap(const std::string &input);
    static std::string ConvertCharset(
        const std::string &input, const std::string &fromCharset, const std::string &toCharset, int32_t &errorCode);
    static std::string ConvertCharset(
        const std::string &decodedBytes, const std::string &targetCharset, int32_t &errorCode);
    static std::string GetBytes(const std::string &str, const std::string &charset);
    static std::string CreateFileName();
    static void SaveFile(const std::string &fileStr, const std::string &path);
    static bool IsPrintableAscii(std::vector<std::string> strs);
    static bool IsPrintableAscii(const std::string &str);
    static bool IsPrintableAscii(char c);
    static bool IsWrapPrintableAscii(std::vector<std::string> strs);
    static std::string GetTypeFromImLabelId(std::string labelId);
    static std::vector<std::string> GetTypeFromPhoneLabelId(std::string labelId);
    static std::string GetImageType(std::string bytes);
    static bool IsNum(const std::string &str);
    static std::string TrimListToString(const std::vector<std::string> &strs);
    static std::vector<std::string> ConstructListFromValue(const std::string &value, std::string vcardType);
    static void GetPhoneTypeFromStrings(
        const std::vector<std::string> &types, std::string number, std::tuple<int32_t, std::string> &result);
    static int32_t VcardtypeToInt(const std::string &vcardType);
    static std::string FormatNumber(std::string source);
    static int32_t GetPhoneNumberFormat(const int32_t vcardType);
    static bool IsAllEmpty(std::vector<std::string> values);
    static int32_t GetLabelIdFromImType(std::string type);
    static std::string HandleCh(char nextCh, std::string vcardType);
    static void HandleTypeAndLabel(int32_t &type, std::string &label, std::string number, std::string typeStringOrg);
};
} // namespace Telephony
} // namespace OHOS
#endif /* VCARD_UTILS_H */
