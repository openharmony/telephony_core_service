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
/**
 * This permission indicates being allowed to place an outgoing call.
 */
static constexpr const char *PLACE_CALL = "ohos.permission.PLACE_CALL";
/**
 * This permission indicates being allowed to answer an incoming call.
 */
static constexpr const char *ANSWER_CALL = "ohos.permission.ANSWER_CALL";
/**
 * This permission indicates being allowed to write user's call log data.
 */
static constexpr const char *WRITE_CALL_LOG = "ohos.permission.WRITE_CALL_LOG";
/**
 * This permission indicates being allowed to read user's call log data.
 */
static constexpr const char *READ_CALL_LOG = "ohos.permission.READ_CALL_LOG";
/**
 * This permission indicates being allowed to write user's calendar data.
 */
static constexpr const char *WRITE_CALENDAR = "ohos.permission.WRITE_CALENDAR";
/**
 * This permission indicates being allowed to read cell messages.
 */
static constexpr const char *READ_CELL_MESSAGES = "ohos.permission.READ_CELL_MESSAGES";
/**
 * This permission indicates being allowed to write user's contacts data.
 */
static constexpr const char *WRITE_CONTACTS = "ohos.permission.WRITE_CONTACTS";
/**
 * This permission indicates being allowed to read user's contacts data.
 */
static constexpr const char *READ_CONTACTS = "ohos.permission.READ_CONTACTS";
/**
 * This permission indicates being allowed to set state of telephony.
 */
static constexpr const char *SET_TELEPHONY_STATE = "ohos.permission.SET_TELEPHONY_STATE";
/**
 * This permission indicates being allowed to get state of telephony.
 */
static constexpr const char *GET_TELEPHONY_STATE = "ohos.permission.GET_TELEPHONY_STATE";
/**
 * This permission indicates being allowed to get MSISDN of SIM card.
 */
static constexpr const char *GET_PHONE_NUMBERS = "ohos.permission.GET_PHONE_NUMBERS";
/**
 * This permission indicates being allowed to set information about network.
 */
static constexpr const char *SET_NETWORK_INFO = "ohos.permission.SET_NETWORK_INFO";
/**
 * This permission indicates being allowed to get information about network.
 */
static constexpr const char *GET_NETWORK_INFO = "ohos.permission.GET_NETWORK_INFO";
/**
 * This permission indicates being allowed to access cell loaction.
 */
static constexpr const char *CELL_LOCATION = "ohos.permission.LOCATION";
/**
 * This permission indicates being allowed to read messages.
 */
static constexpr const char *READ_MESSAGES = "ohos.permission.READ_MESSAGES";
/**
 * This permission indicates being allowed to send messages.
 */
static constexpr const char *SEND_MESSAGES = "ohos.permission.SEND_MESSAGES";
/**
 * This permission indicates being allowed to receive sms messages.
 */
static constexpr const char *RECEIVE_MESSAGES = "ohos.permission.RECEIVE_SMS";
/**
 * This permission indicates being allowed to connect cellular call service.
 */
static constexpr const char *CONNECT_CELLULAR_CALL_SERVICE = "ohos.permission.CONNECT_CELLULAR_CALL_SERVICE";
/**
 * This permission indicates being allowed to connect IMS service.
 */
static constexpr const char *CONNECT_IMS_SERVICE = "ohos.permission.CONNECT_IMS_SERVICE";
/**
 * This permission indicates being allowed to receive mms.
 */
static constexpr const char *RECEIVE_MMS = "ohos.permission.RECEIVE_MMS";
/**
 * This permission allows a system application to modify the eSIM profile and upgrade the eSIM.
 */
static constexpr const char *SET_TELEPHONY_ESIM_STATE = "ohos.permission.SET_TELEPHONY_ESIM_STATE";
/**
 * This permission allows a system application or carrier application to set the eSIM nickname and activate the eSIM.
 */
static constexpr const char *SET_TELEPHONY_ESIM_STATE_OPEN = "ohos.permission.SET_TELEPHONY_ESIM_STATE_OPEN";
/**
 * This permission allows a system application to obtain eSIM profile information and information written
 * on the device chip when the eSIM is activated.
 */
static constexpr const char *GET_TELEPHONY_ESIM_STATE = "ohos.permission.GET_TELEPHONY_ESIM_STATE";
/**
 * This permission allows a application to obtain apn info and set apn.
 */
static constexpr const char *MANAGE_APN_SETTING = "ohos.permission.MANAGE_APN_SETTING";
} // namespace Permission

class TelephonyPermission {
public:
    /**
     * @brief Permission check by callingUid.
     *
     * @param permissionName permission name.
     * @return Return {@code true} on success, {@code false} on failure.
     */
    static bool CheckPermission(const std::string &permissionName);

    /**
     * @brief Get bundleName by callingUid.
     *
     * @param callingUid.
     * @param bundleName.
     * @return Return {@code true} on success, {@code false} on failure.
     */
    static bool GetBundleNameByUid(int32_t uid, std::string &bundleName);

    /**
     * @brief Check if the caller is System App.
     *
     * @return Return {@code true} if the caller is System App, return {@code false} otherwise.
     */
    static bool CheckCallerIsSystemApp();
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_PERMISSION_H
