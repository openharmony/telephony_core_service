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

#include "core_manager.h"
#include "event_handler.h"
#include "event_runner.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "want.h"
#include "i_tel_ril_manager.h"
#include "icc_state.h"
#include "observer_handler.h"
#include "telephony_state_registry_proxy.h"
#include "i_sim_state_manager.h"

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
// active sim
const int ACTIVE_INIT = -1;
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
// Set sim active
const int MSG_SIM_SET_ACTIVE_DONE = 41;

// pin lock type
const std::string FAC_PIN_LOCK = "SC";
// pin2 lock type
const std::string FDN_PIN_LOCK = "P2";

struct UnlockData {
    UnlockType type;
    int32_t lockState;
    int32_t result;
    int32_t remain;
    int32_t pinRemain;
    int32_t pin2Remain;
    int32_t puk2Remain;
};

class SimStateHandle : public AppExecFwk::EventHandler {
public:
    SimStateHandle(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        const std::weak_ptr<SimStateManager> &simStateManager);
    ~SimStateHandle();
    void Init();
    SimState GetSimState(int slotId);
    bool HasSimCard(int slotId);
    void ObtainIccStatus();
    void ObtainRealtimeIccStatus();
    void GetSimCardData(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void GetSimLockState(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void GetSetLockResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void GetSetActiveSimResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void UnlockPin(int32_t slotId, std::string pin);
    void UnlockPuk(int32_t slotId, std::string newPin, std::string puk);
    void AlterPin(int32_t slotId, std::string newPin, std::string oldPin);
    void UnlockRemain(int32_t slotId);
    void SetLockState(int32_t slotId, std::string pin, int32_t enable);
    void GetLockState(int32_t slotId);
    UnlockData GetUnlockData();
    int32_t GetActiveSimResult();
    bool ConnectService();
    void UnlockPin2(int32_t slotId, std::string pin2);
    void UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2);
    void AlterPin2(int32_t slotId, std::string newPin2, std::string oldPin2);
    void SetActiveSim(int32_t slotId, int32_t type, int32_t enable);
    void SetRilManager(std::shared_ptr<Telephony::ITelRilManager> telRilManager);
    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);
    void UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what);
    const std::string SIM_STATE_ACTION = "com.hos.action.SIM_STATE_CHANGED";

private:
    void SyncCmdResponse();
    void GetUnlockReult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void GetUnlockRemain(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessIccCardState(IccState &ar, int32_t slotId);
    void UpdateAppInfo(IccState &ar, int32_t slotId);
    void UpdateIccState(IccState &ar, int32_t slotId);
    bool PublishSimStateEvent(std::string event, int eventCode, std::string eventData);

private:
    UnlockData unlockRespon_;
    int32_t activeRespon_ = 0;
    std::weak_ptr<SimStateManager> simStateManager_;
    std::vector<IccState> iccState_; // icc card states
    std::vector<SimState> externalState_; // need to broadcast sim state;
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_; // ril manager
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
    sptr<ITelephonyStateNotify> telephonyStateNotify_;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_SIM_STATE_HANDLE_H
