/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ani_util.h"
#include "core_service_errors.h"
#include "enum_convert_for_js.h"
#include "state_registry_errors.h"
#include "telephony_log_wrapper.h"

#include <codecvt>
#include <cstdio>
#include <cstring>
#include <locale>
#include <map>
#include <memory>
#include <vector>

namespace OHOS {
namespace Telephony {
constexpr const char *JS_ERROR_TELEPHONY_PERMISSION_DENIED_STRING = "Permission denied.";
constexpr const char *JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API_STRING = "Non-system applications use system APIs.";
constexpr const char *JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER_STRING =
    "Parameter error. The type of parameter should match or the number of parameters must match.";
constexpr const char *JS_ERROR_DEVICE_NOT_SUPPORT_THIS_API_STRING = "The device does not support this API.";
constexpr const char *JS_ERROR_TELEPHONY_SUCCESS_STRING = "Success.";
constexpr const char *JS_ERROR_TELEPHONY_ARGUMENT_ERROR_STRING = "Invalid parameter value.";
constexpr const char *JS_ERROR_TELEPHONY_SERVICE_ERROR_STRING = "Operation failed. Cannot connect to service.";
constexpr const char *JS_ERROR_TELEPHONY_SYSTEM_ERROR_STRING = "System internal error.";
constexpr const char *JS_ERROR_TELEPHONY_NO_SIM_CARD_STRING = "Do not have sim card.";
constexpr const char *JS_ERROR_TELEPHONY_UNKNOW_ERROR_STRING = "Unknown error code.";
constexpr const char *JS_ERROR_SIM_BASE_ERROR_STRING = "Sim module base error.";
constexpr const char *JS_ERROR_SIM_CARD_IS_NOT_ACTIVE_STRING = "SIM card is not activated.";
constexpr const char *JS_ERROR_SIM_CARD_OPERATION_ERROR_STRING = "SIM card operation error.";
constexpr const char *JS_ERROR_OPERATOR_CONFIG_ERROR_STRING = "Operator config error.";
constexpr const char *JS_ERROR_NETWORK_SEARCH_BASE_ERROR_STRING = "Network search module base error.";
constexpr const char *JS_ERROR_CALL_MANAGER_BASE_ERROR_STRING = "Call manager module base error.";
constexpr const char *JS_ERROR_CELLULAR_CALL_CS_BASE_ERROR_STRING = "Cellular call module cs base error.";
constexpr const char *JS_ERROR_CELLULAR_CALL_IMS_BASE_ERROR_STRING = "Cellular call module ims base error.";
constexpr const char *JS_ERROR_CELLULAR_DATA_BASE_ERROR_STRING = "Cellular data module base error.";
constexpr const char *JS_ERROR_SMS_MMS_BASE_ERROR_STRING = "Sms mms module base error.";
constexpr const char *JS_ERROR_STATE_REGISTRY_BASE_ERROR_STRING = "State registry module base error.";
constexpr const char *JS_ERROR_AIRPLANE_MODE_ON_STRING = "Airplane mode is on.";
constexpr const char *JS_ERROR_NETWORK_NOT_IN_SERVICE = "Network not in service.";
constexpr const char *JS_ERROR_CONFERENCE_EXCEED_LIMIT_STRING = "Conference call is exceed limit.";
constexpr const char *JS_ERROR_CONFERENCE_CALL_IS_NOT_ACTIVE_STRING = "Conference call is not active.";
constexpr const char *JS_ERROR_TELEPHONY_CALL_COUNTS_EXCEED_LIMIT_STRING = "call count exceeds limit";
constexpr const char *JS_ERROR_TELEPHONY_DIAL_IS_BUSY_STRING =
    "Current on a call, unable to initiate a new call";
constexpr const char *JS_ERROR_ESIM_SUCCESS_STRING = "Success.";
constexpr const char *JS_ERROR_ESIM_SERVICE_ERROR_STRING = "Service connection failed.";
constexpr const char *JS_ERROR_ESIM_SYSTEM_ERROR_STRING = "System internal error.";

const std::map<int32_t, const char *> ERROR_MAP = {
    { JsErrorCode::JS_ERROR_TELEPHONY_PERMISSION_DENIED, JS_ERROR_TELEPHONY_PERMISSION_DENIED_STRING },
    { JsErrorCode::JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API, JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER, JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER_STRING },
    { JsErrorCode::JS_ERROR_DEVICE_NOT_SUPPORT_THIS_API, JS_ERROR_DEVICE_NOT_SUPPORT_THIS_API_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_SUCCESS, JS_ERROR_TELEPHONY_SUCCESS_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_ARGUMENT_ERROR, JS_ERROR_TELEPHONY_ARGUMENT_ERROR_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_SERVICE_ERROR, JS_ERROR_TELEPHONY_SERVICE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_SYSTEM_ERROR, JS_ERROR_TELEPHONY_SYSTEM_ERROR_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_NO_SIM_CARD, JS_ERROR_TELEPHONY_NO_SIM_CARD_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_UNKNOW_ERROR, JS_ERROR_TELEPHONY_UNKNOW_ERROR_STRING },
    { JsErrorCode::JS_ERROR_SIM_BASE_ERROR, JS_ERROR_SIM_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_SIM_CARD_IS_NOT_ACTIVE, JS_ERROR_SIM_CARD_IS_NOT_ACTIVE_STRING },
    { JsErrorCode::JS_ERROR_SIM_CARD_OPERATION_ERROR, JS_ERROR_SIM_CARD_OPERATION_ERROR_STRING },
    { JsErrorCode::JS_ERROR_OPERATOR_CONFIG_ERROR, JS_ERROR_OPERATOR_CONFIG_ERROR_STRING },
    { JsErrorCode::JS_ERROR_NETWORK_SEARCH_BASE_ERROR, JS_ERROR_NETWORK_SEARCH_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_CALL_MANAGER_BASE_ERROR, JS_ERROR_CALL_MANAGER_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_CELLULAR_CALL_CS_BASE_ERROR, JS_ERROR_CELLULAR_CALL_CS_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_CELLULAR_CALL_IMS_BASE_ERROR, JS_ERROR_CELLULAR_CALL_IMS_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_CELLULAR_DATA_BASE_ERROR, JS_ERROR_CELLULAR_DATA_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_SMS_MMS_BASE_ERROR, JS_ERROR_SMS_MMS_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_STATE_REGISTRY_BASE_ERROR, JS_ERROR_STATE_REGISTRY_BASE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_AIRPLANE_MODE_ON, JS_ERROR_AIRPLANE_MODE_ON_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_NETWORK_NOT_IN_SERVICE, JS_ERROR_NETWORK_NOT_IN_SERVICE },
    { JsErrorCode::JS_ERROR_TELEPHONY_CONFERENCE_EXCEED_LIMIT, JS_ERROR_CONFERENCE_EXCEED_LIMIT_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_CONFERENCE_CALL_NOT_ACTIVE, JS_ERROR_CONFERENCE_CALL_IS_NOT_ACTIVE_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_CALL_COUNTS_EXCEED_LIMIT, JS_ERROR_TELEPHONY_CALL_COUNTS_EXCEED_LIMIT_STRING },
    { JsErrorCode::JS_ERROR_TELEPHONY_DIAL_IS_BUSY, JS_ERROR_TELEPHONY_DIAL_IS_BUSY_STRING },
    { JsErrorCode::JS_ERROR_ESIM_SUCCESS, JS_ERROR_ESIM_SUCCESS_STRING },
    { JsErrorCode::JS_ERROR_ESIM_SERVICE_ERROR, JS_ERROR_ESIM_SERVICE_ERROR_STRING },
    { JsErrorCode::JS_ERROR_ESIM_SYSTEM_ERROR, JS_ERROR_ESIM_SYSTEM_ERROR_STRING },
};

std::string AniUtil::GetErrorMessage(int32_t errorCode)
{
    std::string result = "";
    auto iter = ERROR_MAP.find(errorCode);
    if (iter == ERROR_MAP.end()) {
        TELEPHONY_LOGE("NapiUtil::GetErrorMessage return null.");
        return result;
    }
    TELEPHONY_LOGD("NapiUtil::GetErrorMessage errorCode %{public}d, message = %{public}s", errorCode, iter->second);
    result = iter->second;
    return result;
}

std::string AniUtil::ConverErrorMessageWithPermissionForJs(int errorCode, const std::string &funcName,
    const std::string &permission)
{
    if (errorCode == JS_ERROR_TELEPHONY_PERMISSION_DENIED) {
        auto errorMessage = "BusinessError 201: Permission denied. An attempt was made to " + funcName +
                             " forbidden by permission: " + permission;
        return errorMessage;
    }
    return "";
}

int32_t AniUtil::GetErrorCode(int32_t ret)
{
    switch (ret) {
        case TELEPHONY_SUCCESS:
            return JS_ERROR_TELEPHONY_SUCCESS;
        case TELEPHONY_ERR_PERMISSION_ERR:
            return JS_ERROR_TELEPHONY_PERMISSION_DENIED;
        case TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API:
            return JS_ERROR_ILLEGAL_USE_OF_SYSTEM_API;
        case TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL:
        case TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL:
        case TELEPHONY_ERR_WRITE_DATA_FAIL:
            return JS_ERROR_TELEPHONY_SERVICE_ERROR;
        case TELEPHONY_ERR_SLOTID_INVALID:
            return JS_ERROR_TELEPHONY_ARGUMENT_ERROR;
        case TELEPHONY_ERR_LOCAL_PTR_NULL:
            return JS_ERROR_TELEPHONY_SYSTEM_ERROR;
    }
    return JS_ERROR_TELEPHONY_SYSTEM_ERROR;
}

} // namespace Telephony
} // namespace OHOS