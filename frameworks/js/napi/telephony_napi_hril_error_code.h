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

#ifndef TELEPHONY_NAPI_HRIL_ERROR_CODE_H
#define TELEPHONY_NAPI_HRIL_ERROR_CODE_H

namespace OHOS {
namespace Telephony {
/**
 * @brief Indicates the error code of RIL.
 */
enum RilErrorCode {
    /**
     * Indicates the point is null.
     */
    HRIL_ERR_NULL_POINT = -1,

    /**
     * Indicates there is no error.
     */
    HRIL_ERR_SUCCESS = 0,

    /**
     * Indicates a generic failure.
     */
    HRIL_ERR_GENERIC_FAILURE = 1,

    /**
     * Indicates the parameter is invalid.
     */
    HRIL_ERR_INVALID_PARAMETER = 2,

    /**
     * Indicates the memory is full.
     */
    HRIL_ERR_MEMORY_FULL = 3,

    /**
     * Indicates send command failed.
     */
    HRIL_ERR_CMD_SEND_FAILURE = 4,

    /**
     * Indicates NO CARRIER response returned.
     */
    HRIL_ERR_CMD_NO_CARRIER = 5,

    /**
     * Indicates the response is invalid.
     */
    HRIL_ERR_INVALID_RESPONSE = 6,

    /**
     * Indicates the new status of radio to set is same with previous.
     */
    HRIL_ERR_REPEAT_STATUS = 7,
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_NAPI_HRIL_ERROR_CODE_H