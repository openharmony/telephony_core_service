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
#include "vcard_decoder_v40.h"

namespace OHOS {
namespace Telephony {

std::string VCardDecoderV40::GetVersion()
{
    return VERSION_40;
}

std::vector<std::string> VCardDecoderV40::GetSupportType()
{
    return { VCARD_TYPE_BEGIN, VCARD_TYPE_END, VCARD_TYPE_VERSION, "SOURCE", "KIND", VCARD_TYPE_FN, VCARD_TYPE_N,
        VCARD_TYPE_NICKNAME, VCARD_TYPE_PHOTO, VCARD_TYPE_BDAY, "ANNIVERSARY", "GENDER", "ADR", VCARD_TYPE_TEL,
        VCARD_TYPE_EMAIL, "IMPP", "LANG", "TZ", "GEO", VCARD_TYPE_TITLE, "ROLE", VCARD_TYPE_LOGO, "ORG", "MEMBER",
        "RELATED", "CATEGORIES", VCARD_TYPE_NOTE, "PRODID", "REV", "SOUND", "UID", "CLIENTPIDMAP", VCARD_TYPE_URL,
        "KEY", "FBURL", "CALENDRURI", "CALURI", "XML" };
}
} // namespace Telephony
} // namespace OHOS
