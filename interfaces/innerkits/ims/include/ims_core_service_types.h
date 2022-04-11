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

#ifndef TELEPHONY_IMS_CORE_SERVICE_TYPES_H
#define TELEPHONY_IMS_CORE_SERVICE_TYPES_H

#include <stdint.h>

namespace OHOS {
namespace Telephony {
// move TELEPHONY_IMS_SYS_ABILITY_ID to system_ability_definition.h
const int32_t TELEPHONY_IMS_SYS_ABILITY_ID = 4014;
enum ImsErrType {
    IMS_SUCCESS = 0,
    IMS_FAILED = 1,
};

struct ImsResponseInfo {
    int32_t slotId;
    ImsErrType error;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CORE_SERVICE_TYPES_H
