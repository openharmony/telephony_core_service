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

#include "i_tel_ril_manager.h"
#include "sim_state_handle.h"
#include "sim_state_type.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
enum SimHandleRun { STATE_NOT_START, STATE_RUNNING };

class SimStateManager : public std::enable_shared_from_this<SimStateManager> {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    explicit SimStateManager(std::shared_ptr<ITelRilManager> telRilManager);
    ~SimStateManager();
    void Init(int32_t slotId);
    bool HasSimCard();
    SimState GetSimState();
    CardType GetCardType();
    std::string GetIccid();
    int32_t SetModemInit(bool state);
    int32_t UnlockPin(int32_t slotId, const std::string &pin, LockStatusResponse &response);
    int32_t UnlockPuk(int32_t slotId, const std::string &newPin, const std::string &puk, LockStatusResponse &response);
    int32_t AlterPin(
        int32_t slotId, const std::string &newPin, const std::string &oldPin, LockStatusResponse &response);
    int32_t SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response);
    int32_t GetLockState(int32_t slotId, LockType lockType, LockState &lockState);
    int32_t RefreshSimState(int32_t slotId);
    int32_t UnlockPin2(int32_t slotId, const std::string &pin2, LockStatusResponse &response);
    int32_t UnlockPuk2(
        int32_t slotId, const std::string &newPin2, const std::string &puk2, LockStatusResponse &response);
    int32_t AlterPin2(
        int32_t slotId, const std::string &newPin2, const std::string &oldPin2, LockStatusResponse &response);
    int32_t UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response);
    void RegisterCoreNotify(const HANDLE &handler, int what);
    void UnRegisterCoreNotify(const HANDLE &observerCallBack, int what);
    int32_t SimAuthentication(
        int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response);
    int32_t SendSimMatchedOperatorInfo(
        int32_t slotId, int32_t state, const std::string &operName, const std::string &operKey);
    bool IfModemInitDone();
    int32_t GetSimIO(int32_t slotId, SimIoRequestInfo requestInfo, SimAuthenticationResponse &response);
    void SyncCmdResponse();

public:
    bool responseReady_ = false;
    std::mutex ctx_;
    std::condition_variable cv_;

private:
    void RequestUnlock(UnlockCmd type);

private:
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<SimStateHandle> simStateHandle_ = nullptr;
    SimHandleRun simStateRun_ = STATE_NOT_START;
    static std::mutex mtx_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_STATE_MANAGER_H
