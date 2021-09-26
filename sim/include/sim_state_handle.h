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

#ifndef __SIM_STATE_HANDLE__
#define __SIM_STATE_HANDLE__

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

enum UnlockType { PIN_TYPE, PUK_TYPE };

enum UnlockCmd {
    REQUEST_UNLOCK_PIN,
    REQUEST_UNLOCK_PUK,
    REQUEST_UNLOCK_REMAIN,
};

// pin/puk password incorect
const int UNLOCK_PIN_PUK_INCORRECT = 16; // incorrect password
// Current valid phone id
const int CUR_VALID_PHONEID = 0;
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
// Get sim unlock remain
const int MSG_SIM_UNLOCK_REMAIN_DONE = 10;
// Get sim realtime icc state
const int MSG_SIM_GET_REALTIME_ICC_STATUS_DONE = 21;

// pin lock type
const std::string FAC_PIN_LOCK = "SC";

struct UnlockData {
    UnlockType type = PIN_TYPE;
    int32_t lockState = 0;
    int32_t result = 0;
    int32_t remain = 0;
    int32_t pinRemain = 0;
};

class SimStateHandle : public AppExecFwk::EventHandler {
public:
    SimStateHandle(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        const std::weak_ptr<SimStateManager> &simStateManager);
    ~SimStateHandle();
    void Init();
    int GetSimState(int slotId);
    bool HasSimCard(int slotId);
    void ObtainIccStatus();
    void ObtainRealtimeIccStatus();
    void GetSimCardData(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId);
    void GetSimLockState(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId);
    void GetSetLockResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId);
    void UnlockPin(std::string pin, int32_t phoneId);
    void UnlockPuk(std::string newPin, std::string puk, int32_t phoneId);
    void AlterPin(std::string newPin, std::string oldPin, int32_t phoneId);
    void UnlockRemain(int32_t phoneId);
    void SetLockState(std::string pin, int32_t enable, int32_t phoneId);
    void GetLockState(int32_t phoneId);
    UnlockData GetUnlockData();
    bool ConnectService();
    const std::string SIM_STATE_ACTION = "com.hos.action.SIM_STATE_CHANGED";

private:
    void SyncCmdResponse();
    void GetUnlockReult(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId);
    void GetUnlockRemain(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessIccCardState(IccState &ar, int32_t index);
    void UpdateAppInfo(IccState &ar, int32_t index);
    void UpdateIccState(IccState &ar, int32_t index);
    bool PublishSimStateEvent(std::string event, int eventCode, std::string eventData);

private:
    UnlockData unlockRespon_;
    std::weak_ptr<SimStateManager> simStateManager_;
    std::vector<IccState> iccState_; // icc card states
    std::vector<ExternalState> externalState_; // need to broadcast sim state;
    std::shared_ptr<Telephony::IRilManager> rilManager_ = nullptr; // ril manager
    sptr<ITelephonyStateNotify> telephonyStateNotify_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS

#endif // __SIM_STATE_HANDLE__
