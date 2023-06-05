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

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
enum {
    /**
     * State registry data not exist
     */
    TELEPHONY_STATE_REGISTRY_DATA_NOT_EXIST = STATE_REGISTRY_ERR_OFFSET,
    /**
     * State unregistry data not exist
     */
    TELEPHONY_STATE_UNREGISTRY_DATA_NOT_EXIST,
    /**
     * State registry data exist
     */
    TELEPHONY_STATE_REGISTRY_DATA_EXIST,
    /**
     * State registry not implemented
     */
    TELEPHONY_STATE_REGISTRY_NOT_IMPLEMENTED,
    /**
     * State registry permission denied
     */
    TELEPHONY_STATE_REGISTRY_PERMISSION_DENIED,
    /**
     * State registry slotId error
     */
    TELEPHONY_STATE_REGISTRY_SLODID_ERROR
};
} // namespace Telephony
} // namespace OHOS
#endif // STATE_REGISTRY_ERRORS_H
