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

#include "sim_state_type.h"
#include "sim_state_handle.h"
#include "i_tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
enum SimHandleRun {
    STATE_NOT_START,
    STATE_RUNNING
};

class SimStateManager : public std::enable_shared_from_this<SimStateManager> {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    explicit SimStateManager(std::shared_ptr<ITelRilManager> telRilManager);
    ~SimStateManager();
    void Init(int32_t slotId);
    bool HasSimCard();
    SimState GetSimState();
    CardType GetCardType();
    bool UnlockPin(int32_t slotId, std::string pin, LockStatusResponse &response);
    bool UnlockPuk(
        int32_t slotId, std::string newPin, std::string puk, LockStatusResponse &response);
    bool AlterPin(
        int32_t slotId, std::string newPin, std::string oldPin, LockStatusResponse &response);
    bool SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response);
    int32_t GetLockState(int32_t slotId, LockType lockType);
    int32_t RefreshSimState(int32_t slotId);
    bool UnlockPin2(int32_t slotId, std::string pin2, LockStatusResponse &response);
    bool UnlockPuk2(
        int32_t slotId, std::string newPin2, std::string puk2, LockStatusResponse &response);
    bool AlterPin2(
        int32_t slotId, std::string newPin2, std::string oldPin2, LockStatusResponse &response);
    bool UnlockSimLock(
        int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);
    void RegisterCoreNotify(const HANDLE &handler, int what);
    void UnRegisterCoreNotify(const HANDLE &observerCallBack, int what);
    int32_t SimAuthentication(int32_t slotId, const std::string &aid, const std::string &authData,
        SimAuthenticationResponse &response);

public:
    static bool responseReady_;
    static std::mutex ctx_;
    static std::condition_variable cv_;

private:
    void RequestUnlock(UnlockCmd type);

private:
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<SimStateHandle> simStateHandle_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_ = nullptr;
    SimHandleRun simStateRun_ = STATE_NOT_START;
    static std::mutex mtx_;
    constexpr static const int32_t WAIT_TIME_SECOND = 1;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_STATE_MANAGER_H
