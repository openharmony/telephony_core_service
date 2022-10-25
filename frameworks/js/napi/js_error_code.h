/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef JS_ERROR_CODE_H
#define JS_ERROR_CODE_H

#include <string>

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
enum JsErrorCode {
    /**
     * Permission denied.
     */
    JS_ERROR_TELEPHONY_PERMISSION_DENIED = 201,

    /**
     * Invalid parameter value. The types of parameters should match, or the number of parameters must match.
     */
    JS_ERROR_TELEPHONY_INVALID_INPUT_PARAMETER = 401,

    /**
     * The device does not support this API. It is usually used to support a small number of APIs when the device has
     * supported the SysCap.
     */
    JS_ERROR_DEVICE_NOT_SUPPORT_THIS_API = 801,

    /**
     * Success.
     */
    JS_ERROR_TELEPHONY_SUCCESS = 8300000,

    /**
     * The input parameter value is out of range.
     */
    JS_ERROR_TELEPHONY_ARGUMENT_ERROR = 8300001,

    /**
     * Operation failed. Cannot connect to service.
     */
    JS_ERROR_TELEPHONY_SERVICE_ERROR,

    /**
     * System internal error.
     */
    JS_ERROR_TELEPHONY_SYSTEM_ERROR,

    /**
     * Unknown error code.
     */
    JS_ERROR_TELEPHONY_UNKNOW_ERROR,

    /**
     * Do not have sim card.
     */
    JS_ERROR_TELEPHONY_NO_SIM_CARD,

    /**
     * Sim module base error code.
     */
    JS_ERROR_SIM_BASE_ERROR = 8301000,

    /**
     * Network search module base error code.
     */
    JS_ERROR_NETWORK_SEARCH_BASE_ERROR = 8302000,

    /**
     * Call manager module base error code.
     */
    JS_ERROR_CALL_MANAGER_BASE_ERROR = 8401000,

    /**
     * The dialing policy is not met.
     */
    JS_ERROR_CALL_DIAL_POLICY_NOT_MET = 8401001,

    /**
     * Wrong mobile number format.
     */
    JS_ERROR_CALL_WRONG_MOBILE_NUMBER = 8401002,

    /**
     * Abnormal call status.
     */
    JS_ERROR_CALL_ABNORMAL_CALL_STATUS = 8401003,

    /**
     * Abnormal conference call.
     */
    JS_ERROR_CALL_ABNORMAL_CONFERENCE_CALL = 8401004,

    /**
     * Supplementary service exception.
     */
    JS_ERROR_SUPPLEMENTARY_SERVICE_EXCEPTION = 8401005,

    /**
     * Abnormal call parameters.
     */
    JS_ERROR_CALL_ABNORMAL_CALL_PARAMETERS = 8401006,

    /**
     * Abnormal video call status.
     */
    JS_ERROR_CALL_ABNORMAL_VIDEO_CALL_STATUS = 8401007,

    /**
     * Cellular call module cs base error code.
     */
    JS_ERROR_CELLULAR_CALL_CS_BASE_ERROR = 8501000,

    /**
     * Cellular call module ims base error code.
     */
    JS_ERROR_CELLULAR_CALL_IMS_BASE_ERROR = 8502000,

    /**
     * Cellular data module base error code.
     */
    JS_ERROR_CELLULAR_DATA_BASE_ERROR = 8601000,

    /**
     * Sms mms module base error code.
     */
    JS_ERROR_SMS_MMS_BASE_ERROR = 8701000,

    /**
     * State registry module base error code.
     */
    JS_ERROR_STATE_REGISTRY_BASE_ERROR = 8801000,
};

struct JsError {
    JsErrorCode errorCode;
    std::string errorMessage;
};
} // namespace Telephony
} // namespace OHOS
#endif // JS_ERROR_CODE_H
