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

#ifndef OHOS_SIM_STATE_HANDLE_H
#define OHOS_SIM_STATE_HANDLE_H

#include <list>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <string>
#include <vector>

#include "event_handler.h"
#include "event_runner.h"
#include "want.h"
#include "i_tel_ril_manager.h"
#include "i_sim_manager.h"
#include "icc_state.h"
#include "observer_handler.h"
#include "sim_state_type.h"

namespace OHOS {
namespace Telephony {
class SimStateManager;

enum UnlockType {
    PIN_TYPE,
    PUK_TYPE,
};

enum UnlockCmd {
    REQUEST_UNLOCK_PIN,
    REQUEST_UNLOCK_PUK,
    REQUEST_UNLOCK_REMAIN,
};

// pin/puk password incorect
const int UNLOCK_PIN_PUK_INCORRECT = 16; // incorrect password
// Phone number
const int SIM_CARD_NUM = 2;
// The events for handleMessage
const int MSG_SIM_GET_ICC_STATUS_DONE = 3;
// Unlock pin
const int MSG_SIM_UNLOCK_PIN_DONE = 4;
// Unlock puk
const int MSG_SIM_UNLOCK_PUK_DONE = 5;
// Change pin
const int MSG_SIM_CHANGE_PIN_DONE = 6;
// Check pin state
const int MSG_SIM_CHECK_PIN_DONE = 7;
// Set pin state[0:close_lock_state], [1:open_lock_state]
const int MSG_SIM_ENABLE_PIN_DONE = 8;
// Get sim unlock pin remain
const int MSG_SIM_UNLOCK_REMAIN_DONE = 10;
// Get sim realtime icc state
const int MSG_SIM_GET_REALTIME_ICC_STATUS_DONE = 21;
// Unlock pin2
const int MSG_SIM_UNLOCK_PIN2_DONE = 31;
// Unlock puk2
const int MSG_SIM_UNLOCK_PUK2_DONE = 32;
// Change pin2
const int MSG_SIM_CHANGE_PIN2_DONE = 33;
// Get sim unlock pin2 remain
const int MSG_SIM_UNLOCK_PIN2_REMAIN_DONE = 34;
// Unlock simlock
const int MSG_SIM_UNLOCK_SIMLOCK_DONE = 51;

// pin lock type
const std::string FAC_PIN_LOCK = "SC";
// change pin2 type
const std::string FDN_PIN_LOCK = "P2";
// FDN lock type
const std::string FDN_PIN2_LOCK = "FD";

struct UnlockData {
    UnlockType type;
    int32_t lockState = 0;
    int32_t result = 0;
    int32_t remain = 0;
    int32_t pinRemain = 0;
    int32_t pin2Remain = 0;
    int32_t puk2Remain = 0;
};

class SimStateHandle : public AppExecFwk::EventHandler {
public:
    SimStateHandle(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        const std::weak_ptr<SimStateManager> &simStateManager);
    ~SimStateHandle();
    void Init(int32_t slotId);
    SimState GetSimState();
    CardType GetCardType();
    bool HasSimCard();
    void ObtainRealtimeIccStatus(int32_t slotId);
    void UnlockPin(int32_t slotId, std::string pin);
    void UnlockPuk(int32_t slotId, std::string newPin, std::string puk);
    void AlterPin(int32_t slotId, std::string newPin, std::string oldPin);
    void UnlockRemain(int32_t slotId);
    void SetLockState(int32_t slotId, const LockInfo &options);
    void GetLockState(int32_t slotId, LockType lockType);
    UnlockData GetUnlockData();
    LockStatusResponse GetSimlockResponse();
    bool ConnectService();
    void UnlockPin2(int32_t slotId, std::string pin2);
    void UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2);
    void AlterPin2(int32_t slotId, std::string newPin2, std::string oldPin2);
    void UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo);
    void SetRilManager(std::shared_ptr<Telephony::ITelRilManager> telRilManager);
    const std::string SIM_STATE_ACTION = "com.hos.action.SIM_STATE_CHANGED";
    bool IsIccReady();
    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);
    void UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what);

private:
    void SyncCmdResponse();
    void ObtainIccStatus(int32_t slotId);
    void GetSimCardData(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void GetSimLockState(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void GetSetLockResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void GetUnlockReult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void GetUnlockRemain(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessIccCardState(IccState &ar, int32_t slotId);
    void UpdateAppInfo(IccState &ar, int32_t slotId);
    bool PublishSimStateEvent(std::string event, int32_t eventCode, std::string eventData);
    void SimStateEscape(int32_t simState, int32_t slotId, LockReason &reason);
    void CardTypeEscape(int32_t simType, int32_t slotId);
    void SimLockStateEscape(int32_t simState, int32_t slotId, LockReason &reason);
    void NotifySimLock(int slotId);
    void GetUnlockSimLockResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);

private:
    int32_t oldSimType_ = ICC_UNKNOWN_TYPE;
    int32_t oldSimStatus_ = ICC_CONTENT_UNKNOWN;
    int32_t slotId_ = DEFAULT_SIM_SLOT_ID;
    UnlockData unlockRespon_;
    LockStatusResponse simlockRespon_ = {0};
    IccState iccState_; // icc card states
    SimState externalState_; // need to broadcast sim state;
    CardType externalType_ = CardType::UNKNOWN_CARD; // need to broadcast card type;
    std::weak_ptr<SimStateManager> simStateManager_;
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr; // ril manager
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_SIM_STATE_HANDLE_H
