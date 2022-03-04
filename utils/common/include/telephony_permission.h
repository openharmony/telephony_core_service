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
static const std::string PLACE_CALL = "ohos.permission.PLACE_CALL";
static const std::string ANSWER_CALL = "ohos.permission.ANSWER_CALL";
static const std::string WRITE_CALL_LOG = "ohos.permission.WRITE_CALL_LOG";
static const std::string READ_CALL_LOG = "ohos.permission.READ_CALL_LOG";
static const std::string WRITE_CALENDAR = "ohos.permission.WRITE_CALENDAR";
static const std::string READ_CELL_MESSAGES = "ohos.permission.READ_CELL_MESSAGES";
static const std::string WRITE_CONTACTS = "ohos.permission.WRITE_CONTACTS";
static const std::string READ_CONTACTS = "ohos.permission.READ_CONTACTS";
static const std::string SET_TELEPHONY_STATE = "ohos.permission.SET_TELEPHONY_STATE";
static const std::string GET_TELEPHONY_STATE = "ohos.permission.GET_TELEPHONY_STATE";
static const std::string SET_NETWORK_INFO = "ohos.permission.SET_NETWORK_INFO";
static const std::string GET_NETWORK_INFO = "ohos.permission.GET_NETWORK_INFO";
static const std::string CELL_LOCATION = "ohos.permission.LOCATION";
static const std::string READ_MESSAGES = "ohos.permission.READ_MESSAGES";
static const std::string SEND_MESSAGES = "ohos.permission.SEND_MESSAGES";
static const std::string RECEIVE_MESSAGES = "ohos.permission.RECEIVE_SMS";
} // namespace Permission

class TelephonyPermission {
public:
    static bool CheckPermission(const std::string &permissionName);
    static bool GetBundleNameByUid(int32_t uid, std::string &bundleName);
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_PERMISSION_H
