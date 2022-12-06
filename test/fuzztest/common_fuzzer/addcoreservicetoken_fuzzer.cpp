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

#include "addcoreservicetoken_fuzzer.h"

#include <iostream>

#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
const int PERMS_NUM = 11;

AddCoreServiceTokenFuzzer::AddCoreServiceTokenFuzzer()
{
    const char *perms[PERMS_NUM] = {
        "ohos.permission.WRITE_CONTACTS",
        "ohos.permission.SET_TELEPHONY_STATE",
        "ohos.permission.GET_TELEPHONY_STATE",
        "ohos.permission.READ_CONTACTS",
        "ohos.permission.WRITE_CONTACTS",
        "ohos.permission.LOCATION",
        "ohos.permission.COMMONEVENT_STICKY",
        "ohos.permission.CONNECTIVITY_INTERNAL",
        "ohos.permission.PERMISSION_USED_STATS",
        "ohos.permission.RECEIVE_SMS",
        "ohos.permission.MANAGE_SECURE_SETTINGS",
    };

    NativeTokenInfoParams testCoreServiceInfoParams = {
        .dcapsNum = 0,
        .permsNum = PERMS_NUM,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "core_service_fuzzer",
        .aplStr = "system_basic",
    };
    currentID_ = GetAccessTokenId(&testCoreServiceInfoParams);
    SetSelfTokenID(currentID_);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}
AddCoreServiceTokenFuzzer::~AddCoreServiceTokenFuzzer() {}
} // namespace OHOS