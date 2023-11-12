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

#ifndef NAPI_VCARD_INCLUDE_NAPI_VCARD_TYPE_H
#define NAPI_VCARD_INCLUDE_NAPI_VCARD_TYPE_H

enum ContactType {
    GENERAL_CONTACT = 1,
    FIXED_DIALING = 2,
};

enum VCardType {
    VCARD_VERSION_21 = 0,
    VCARD_VERSION_30 = 1,
    VCARD_VERSION_40 = 2,
};

#endif
