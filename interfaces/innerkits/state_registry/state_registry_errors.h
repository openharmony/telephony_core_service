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

#ifndef STATE_REGISTRY_ERRORS_H
#define STATE_REGISTRY_ERRORS_H

#include "../../../core_service/interfaces/innerkits/core/telephony_errors.h"

namespace OHOS {
namespace Telephony {
enum {
    TELEPHONY_STATE_REGISTRY_DATA_NOT_EXIST = STATE_REGISTRY_ERR_OFFSET,
    TELEPHONY_STATE_UNREGISTRY_DATA_NOT_EXIST,
    TELEPHONY_STATE_REGISTRY_DATA_EXIST
};
} // namespace Telephony
} // namespace OHOS
#endif // STATE_REGISTRY_ERRORS_H
