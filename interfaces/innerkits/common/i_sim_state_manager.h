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

#include "event_handler.h"

namespace OHOS {
namespace Telephony {
enum UnlockResult {
    UNLOCK_FAIL = -2, // unlock fail
    UNLOCK_INCORRECT = -1, // password error
    UNLOCK_OK = 0, // unlock sucessful
};

enum ExternalState {
    EX_UNKNOWN,
    EX_ABSENT,
    EX_PIN_LOCKED,
    EX_PUK_LOCKED,
    EX_SIMLOCK,
    EX_READY,
    EX_UNREADY,
    EX_BLOCKED_PERM,
    EX_ICC_ERROR,
    EX_ICC_RESTRICTED,
    EX_LOADED,
};

struct LockStatusResponse {
    int32_t result;
    int32_t remain;
};

class ISimStateManager {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    virtual void Init() = 0;
    virtual bool HasSimCard(int32_t slotId) = 0;
    virtual int32_t GetSimState(int32_t slotId) = 0;
    virtual bool IsSimActive(int32_t slotId) = 0;
    virtual bool UnlockPin(std::string pin, LockStatusResponse &response, int32_t slotId) = 0;
    virtual bool UnlockPuk(std::string newPin, std::string puk, LockStatusResponse &response, int32_t phoneId) = 0;
    virtual bool AlterPin(
        std::string newPin, std::string oldPin, LockStatusResponse &response, int32_t phoneId) = 0;
    virtual bool SetLockState(std::string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId) = 0;
    virtual int32_t GetLockState(int32_t phoneId) = 0;
    virtual int32_t RefreshSimState(int32_t slotId) = 0;
    // Event register
    virtual void RegisterIccStateChanged(HANDLE &handler) = 0;
    virtual void UnregisterIccStateChanged(HANDLE &handler) = 0;
    virtual void RegisterIccReady(HANDLE &handler) = 0;
    virtual void UnregisterIccReady(HANDLE &handler) = 0;
    virtual void RegisterIccLocked(HANDLE &handler) = 0;
    virtual void UnregisterIccLocked(HANDLE &handler) = 0;
    virtual void RegisterIccSimLock(HANDLE &handler) = 0;
    virtual void UnregisterIccSimLock(HANDLE &handler) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_I_SIM_MANAGER_H
