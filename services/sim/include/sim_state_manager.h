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
enum SimHandleRun {
    STATE_NOT_START,
    STATE_RUNNING
};

class SimStateManager : public ISimStateManager, public std::enable_shared_from_this<SimStateManager> {
public:
    SimStateManager(std::shared_ptr<ITelRilManager> telRilManager);
    virtual ~SimStateManager();
    virtual void Init() override;
    virtual bool HasSimCard(int32_t slotId) override;
    virtual SimState GetSimState(int32_t slotId) override;
    virtual bool UnlockPin(int32_t slotId, std::string pin, LockStatusResponse &response) override;
    virtual bool UnlockPuk(
        int32_t slotId, std::string newPin, std::string puk, LockStatusResponse &response) override;
    virtual bool AlterPin(
        int32_t slotId, std::string newPin, std::string oldPin, LockStatusResponse &response) override;
    virtual bool SetLockState(
        int32_t slotId, std::string pin, int32_t enable, LockStatusResponse &response) override;
    virtual int32_t GetLockState(int32_t slotId) override;
    virtual int32_t RefreshSimState(int32_t slotId) override;
    virtual bool UnlockPin2(int32_t slotId, std::string pin2, LockStatusResponse &response) override;
    virtual bool UnlockPuk2(
        int32_t slotId, std::string newPin2, std::string puk2, LockStatusResponse &response) override;
    virtual bool AlterPin2(
        int32_t slotId, std::string newPin2, std::string oldPin2, LockStatusResponse &response) override;
    virtual bool SetActiveSim(int32_t slotId, int32_t type, int32_t enable) override;
    virtual void RegisterCoreNotify(const HANDLE &handler, int what) override;
    virtual void UnRegisterCoreNotify(const HANDLE &observerCallBack, int what) override;

public:
    static bool responseReady_;
    static std::mutex ctx_;
    static std::condition_variable cv_;

private:
    void RequestUnlock(UnlockCmd type);

private:
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<SimStateHandle> simStateHandle_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_ = nullptr;
    SimHandleRun simStateRun_ = STATE_NOT_START;
    static std::mutex mtx_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_STATE_MANAGER_H
