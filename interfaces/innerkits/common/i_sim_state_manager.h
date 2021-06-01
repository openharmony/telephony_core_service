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

#ifndef OHOS_I_SIM_STATE_MANAGER_H
#define OHOS_I_SIM_STATE_MANAGER_H

#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>
#include "event_handler.h"

namespace OHOS {
namespace SIM {
class ISimStateManager {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    virtual void Init() = 0;
    virtual bool HasSimCard(int32_t slotId) = 0;
    virtual int32_t GetSimState(int32_t slotId) = 0;
    virtual bool IsSimActive(int32_t slotId) = 0;
    // Event register
    virtual void RegisterForIccStateChanged(HANDLE &handler) = 0;
    virtual void UnregisterForIccStateChanged(HANDLE &handler) = 0;
    virtual void RegisterForReady(HANDLE &handler) = 0;
    virtual void UnregisterForReady(HANDLE &handler) = 0;
};
} // namespace SIM
} // namespace OHOS
#endif // OHOS_I_SIM_MANAGER_H
