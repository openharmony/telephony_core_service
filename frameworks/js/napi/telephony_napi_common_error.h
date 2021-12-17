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
enum NapiError : int32_t {
    ERROR_NONE = 0,
    ERROR_DEFAULT = -1,
    ERROR_SERVICE_UNAVAILABLE = -2,
    ERROR_PARAMETER_VALUE_INVALID = -3,
    ERROR_NATIVE_API_EXECUTE_FAIL = -4,
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_NAPI_COMMON_ERROR_H