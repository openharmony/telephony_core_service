/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "vcard_configuration.h"

namespace OHOS {
namespace Telephony {
namespace {
std::vector<int32_t> sJapaneseMobileTypeList = { VCardConfiguration::VCARD_TYPE_V21_JAPANESE,
    VCardConfiguration::VCARD_TYPE_V30_JAPANESE, VCardConfiguration::VCARD_TYPE_V21_JAPANESE_MOBILE,
    VCardConfiguration::VCARD_TYPE_DOCOMO };
}

bool VCardConfiguration::IsVer21(const int32_t vcardType)
{
    return (vcardType & VER_FLAG) == VER_21;
}

bool VCardConfiguration::IsVer30(const int32_t vcardType)
{
    return (vcardType & VER_FLAG) == VER_30;
}

bool VCardConfiguration::IsVer40(const int32_t vcardType)
{
    return (vcardType & VER_FLAG) == VER_40;
}

bool VCardConfiguration::RefrainPhoneNumberFormatting(const int32_t vcardType)
{
    return ((vcardType & FLAG_REFRAIN_PHONE_NUMBER_FORMATTING) != 0);
}

bool VCardConfiguration::IsJapaneseDevice(const int32_t vcardType)
{
    bool contains = false;
    if (std::find(sJapaneseMobileTypeList.begin(), sJapaneseMobileTypeList.end(), vcardType) !=
        sJapaneseMobileTypeList.end()) {
        contains = true;
    }
    return contains;
}
} // namespace Telephony
} // namespace OHOS
