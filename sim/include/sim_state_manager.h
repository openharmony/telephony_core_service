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

#ifndef OHOS_SIM_STATE_MANAGER_H
#define OHOS_SIM_STATE_MANAGER_H

#include "i_sim_state_manager.h"
#include "sim_state_handle.h"

namespace OHOS {
namespace Telephony {
enum SimHandleRun { STATE_NOT_START, STATE_RUNNING };

class SimStateManager : public ISimStateManager, public std::enable_shared_from_this<SimStateManager> {
public:
    SimStateManager();
    virtual ~SimStateManager();
    void NotifyIccStateChanged();
    void NotifyIccReady();
    void NotifyIccLock();
    void NotifyIccSimLock();
    virtual void Init() override;
    virtual bool HasSimCard(int32_t slotId) override;
    virtual int32_t GetSimState(int32_t slotId) override;
    virtual bool IsSimActive(int32_t slotId) override;
    virtual bool UnlockPin(std::string pin, LockStatusResponse &response, int32_t phoneId) override;
    virtual bool UnlockPuk(
        std::string newPin, std::string puk, LockStatusResponse &response, int32_t phoneId) override;
    virtual bool AlterPin(
        std::string newPin, std::string oldPin, LockStatusResponse &response, int32_t phoneId) override;
    virtual bool SetLockState(
        std::string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId) override;
    virtual int32_t GetLockState(int32_t phoneId) override;
    virtual void RegisterIccStateChanged(HANDLE &handler) override;
    virtual void UnregisterIccStateChanged(HANDLE &handler) override;
    virtual void RegisterIccReady(HANDLE &handler) override;
    virtual void UnregisterIccReady(HANDLE &handler) override;
    virtual void RegisterIccLocked(HANDLE &handler) override;
    virtual void UnregisterIccLocked(HANDLE &handler) override;
    virtual void RegisterIccSimLock(HANDLE &handler) override;
    virtual void UnregisterIccSimLock(HANDLE &handler) override;
    virtual int32_t RefreshSimState(int32_t slotId) override;

public:
    bool responseReady_ = false;
    std::mutex ctx_;
    std::condition_variable cv_;

private:
    void RequestUnlock(UnlockCmd type);

private:
    std::shared_ptr<SimStateHandle> simStateHandle_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_ = nullptr;
    SimHandleRun simStateRun_ = STATE_NOT_START;
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
    std::mutex mtx_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_STATE_MANAGER_H
