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
#include "sim_state_type.h"

namespace OHOS {
namespace Telephony {
struct LockStatusResponse {
    int32_t result;
    int32_t remain;
};

class ISimStateManager {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    virtual void Init() = 0;
    virtual bool HasSimCard(int32_t slotId) = 0;
    virtual SimState GetSimState(int32_t slotId) = 0;
    virtual bool UnlockPin(int32_t slotId, std::string pin, LockStatusResponse &response) = 0;
    virtual bool UnlockPuk(int32_t slotId, std::string newPin, std::string puk, LockStatusResponse &response) = 0;
    virtual bool AlterPin(int32_t slotId, std::string newPin, std::string oldPin, LockStatusResponse &response) = 0;
    virtual bool SetLockState(int32_t slotId, std::string pin, int32_t enable, LockStatusResponse &response) = 0;
    virtual int32_t GetLockState(int32_t slotId) = 0;
    virtual int32_t RefreshSimState(int32_t slotId) = 0;
    virtual bool UnlockPin2(int32_t slotId, std::string pin2, LockStatusResponse &response) = 0;
    virtual bool UnlockPuk2(
        int32_t slotId, std::string newPin2, std::string puk2, LockStatusResponse &response) = 0;
    virtual bool AlterPin2(
        int32_t slotId, std::string newPin2, std::string oldPin2, LockStatusResponse &response) = 0;
    virtual bool SetActiveSim(int32_t slotId, int32_t type, int32_t enable) = 0;
    // Event register
    virtual void RegisterCoreNotify(const HANDLE &handler, int what) = 0;
    virtual void UnRegisterCoreNotify(const HANDLE &observerCallBack, int what) = 0;
    static const int UNLOCK_FAIL = -2; // unlock fail
    static const int UNLOCK_INCORRECT = -1; // password error
    static const int UNLOCK_OK = 0; // unlock sucessful
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_I_SIM_MANAGER_H
