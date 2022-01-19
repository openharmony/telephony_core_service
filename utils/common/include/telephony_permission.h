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

#ifndef TELEPHONY_PERMISSION_H
#define TELEPHONY_PERMISSION_H

#include <string>

namespace OHOS {
namespace Telephony {
namespace Permission {
static const std::string GET_NETWORK_INFO = "ohos.permission.GET_NETWORK_INFO";
static const std::string GET_SIM_STATE = "ohos.permission.GET_SIM_STATE";
static const std::string SET_TELEPHONY_STATE = "ohos.permission.SET_TELEPHONY_STATE";
static const std::string GET_TELEPHONY_STATE = "ohos.permission.GET_TELEPHONY_STATE";
static const std::string TELEPHONY_SEND_MESSAGES = "ohos.permission.SEND_MESSAGES";
static const std::string TELEPHONY_RECEIVE_MESSAGES = "ohos.permission.RECEIVE_SMS";
static const std::string GET_SIM_INFO = "ohos.permission.GET_SIM_INFO";
static const std::string SET_SIM_INFO = "ohos.permission.SET_SIM_INFO";
static const std::string GET_CALL_HISTORY = "ohos.permission.GET_CALL_HISTORY";
static const std::string GET_CALL_STATE = "ohos.permission.GET_CALL_STATE";
} // namespace Permission

class TelephonyPermission {
public:
    static bool CheckPermission(const std::string &permissionName);
    static bool CheckPermission(const std::string &bundleName, const std::string &permissionName);
    static bool GetBundleNameByUid(int32_t uid, std::string &bundleName);
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_PERMISSION_H
