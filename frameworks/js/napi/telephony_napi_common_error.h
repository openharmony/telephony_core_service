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

#ifndef TELEPHONY_NAPI_COMMON_ERROR_H
#define TELEPHONY_NAPI_COMMON_ERROR_H

namespace OHOS {
namespace Telephony {
/**
 * @brief Indicates the error of NAPI.
 */
enum NapiError : int32_t {
    /**
     * Indicates there is no error.
     */
    ERROR_NONE = 0,

    /**
     * Indicates the default value of NAPI error.
     */
    ERROR_DEFAULT = -1,

    /**
     * Indicates the service is unavailable.
     */
    ERROR_SERVICE_UNAVAILABLE = -2,

    /**
     * Indicates the count of parameter is error.
     */
    ERROR_PARAMETER_COUNTS_INVALID = -4,

    /**
     * Indicates the type of parameter is error.
     */
    ERROR_PARAMETER_TYPE_INVALID = -5,

    /**
     * Indicates the native API execute failed.
     */
    ERROR_NATIVE_API_EXECUTE_FAIL = -6,

    /**
     * Indicates the slot id is invalid.
     */
    ERROR_SLOT_ID_INVALID = 202,
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_NAPI_COMMON_ERROR_H