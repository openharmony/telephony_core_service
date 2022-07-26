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

#ifndef TEL_RIL_COMMON_H
#define TEL_RIL_COMMON_H

namespace OHOS {
namespace Telephony {
typedef enum {
    CORE_SERVICE_NO_PHONE = 0,
    CORE_SERVICE_GSM_PHONE = 1,
    CORE_SERVICE_CDMA_PHONE = 2,
    CORE_SERVICE_CDMA_LTE_PHONE = 3
} CoreServiceTelephonyType;

typedef enum { CORE_SERVICE_SUCCESS = 0, CORE_SERVICE_ERROR = 1 } CoreServiceLteOptStatus;
} // namespace Telephony
} // namespace OHOS
#endif