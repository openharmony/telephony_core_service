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
AddCoreServiceTokenFuzzer::AddCoreServiceTokenFuzzer()
{
    const char **perms = new const char *[11];
    perms[0] = "ohos.permission.WRITE_CONTACTS";
    perms[1] = "ohos.permission.SET_TELEPHONY_STATE";
    perms[2] = "ohos.permission.GET_TELEPHONY_STATE";
    perms[3] = "ohos.permission.READ_CONTACTS";
    perms[4] = "ohos.permission.WRITE_CONTACTS";
    perms[5] = "ohos.permission.LOCATION";
    perms[6] = "ohos.permission.COMMONEVENT_STICKY";
    perms[7] = "ohos.permission.CONNECTIVITY_INTERNAL";
    perms[8] = "ohos.permission.PERMISSION_USED_STATS";
    perms[9] = "ohos.permission.RECEIVE_SMS";
    perms[10] = "ohos.permission.MANAGE_SECURE_SETTINGS";

    NativeTokenInfoParams testCoreServiceInfoParams = {
        .dcapsNum = 0,
        .permsNum = 11,
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