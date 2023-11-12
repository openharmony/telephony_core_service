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

#ifndef VCARD_CONFIGURATION_H
#define VCARD_CONFIGURATION_H
#include <cstdint>
#include <vector>

namespace OHOS {
namespace Telephony {
class VCardConfiguration {
public:
    static const int32_t VER_21 = 0;
    static const int32_t VER_30 = 1;
    static const int32_t VER_40 = 2;
    static const int32_t VER_FLAG = 3;
    static const int32_t FLAG_REFRAIN_PHONE_NUMBER_FORMATTING = 0x02000000;
    static const int32_t NAME_ORDER_JAPANESE = 0x8;
    static const int32_t FLAG_USE_DEFACT_PROPERTY = 0x40000000;
    static const int32_t FLAG_USE_ANZHUO_PROPERTY = 0x80000000;
    static const int32_t FLAG_CONVERT_PHONETIC_NAME_STRINGS = 0x08000000;
    static const int32_t FLAG_REFRAIN_QP_TO_NAME_PROPERTIES = 0x10000000;
    static const int32_t FLAG_DOCOMO = 0x20000000;
    static const int32_t VCARD_TYPE_V21_JAPANESE =
        (VER_21 | NAME_ORDER_JAPANESE | FLAG_USE_DEFACT_PROPERTY | FLAG_USE_ANZHUO_PROPERTY);
    static const int32_t VCARD_TYPE_V30_JAPANESE =
        (VER_30 | NAME_ORDER_JAPANESE | FLAG_USE_DEFACT_PROPERTY | FLAG_USE_ANZHUO_PROPERTY);
    static const int32_t VCARD_TYPE_V21_JAPANESE_MOBILE =
        (VER_21 | NAME_ORDER_JAPANESE | FLAG_CONVERT_PHONETIC_NAME_STRINGS | FLAG_REFRAIN_QP_TO_NAME_PROPERTIES);
    static const int32_t VCARD_TYPE_DOCOMO = (VCARD_TYPE_V21_JAPANESE_MOBILE | FLAG_DOCOMO);
    static bool IsVer21(int32_t vcardType);
    static bool IsVer30(int32_t vcardType);
    static bool IsVer40(int32_t vcardType);
    static bool RefrainPhoneNumberFormatting(const int32_t vcardType);
    static bool IsJapaneseDevice(const int32_t vcardType);
};
} // namespace Telephony
} // namespace OHOS
#endif // VVCARD_CONFIGURATION_H