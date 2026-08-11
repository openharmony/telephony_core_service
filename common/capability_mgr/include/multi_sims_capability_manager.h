/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTI_SIMS_CAPABILITY_MANAGER_H
#define OHOS_MULTI_SIMS_CAPABILITY_MANAGER_H

#include <cstdint>

namespace OHOS {
namespace Telephony {
static constexpr int32_t SLOT_3_INDEX = 3;
class MultiSimsCapabilityMgr {
public:
    /**
     * @brief Checks whether an app supports the multi-SIMs feature given a certain slotId.
     *
     * @param slotId.
     * @return Return {@code true} on success, {@code false} on failure.
     */
    static bool IsMultiSimsCapabilitySupported(int32_t slotId);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_MULTI_SIMS_CAPABILITY_MANAGER_H