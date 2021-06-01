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
#include <string>
#include <vector>
#include "phone_manager.h"
#include "event_handler.h"
#include "event_runner.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "want.h"
#include "i_tel_ril_manager.h"
#include "icc_state.h"
#include "observer_handler.h"

namespace OHOS {
namespace SIM {
class SimStateManager;

enum ExternalState {
    EX_UNKNOWN,
    EX_ABSENT,
    EX_PIN_LOCKED,
    EX_PUK_LOCKED,
    EX_NETWORK_LOCKED,
    EX_READY,
    EX_UNREADY,
    EX_BLOCKED_PERM,
    EX_ICC_ERROR,
    EX_ICC_RESTRICTED,
};

// Phone number
const int SIM_CARD_NUM = 2;
// The events for handleMessage
const int MSG_SIM_GET_ICC_STATUS_DONE = 3;

class SimStateHandle : public AppExecFwk::EventHandler {
public:
    SimStateHandle(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        const std::weak_ptr<SimStateManager> &simStateManager);
    ~SimStateHandle();
    void Init();
    void ReleaseStateManger();
    int GetSimState(int slotId);
    bool HasSimCard(int slotId);
    void ObtainIccStatus();
    void GetSimCardData(const AppExecFwk::InnerEvent::Pointer &event, int phoneId);
    void GetSmsData(const AppExecFwk::InnerEvent::Pointer &event, int phoneId);

private:
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessIccCardState(IccState &ar, int index);
    void UpdateAppInfo(IccState &ar, int index);
    void UpdateIccState(IccState &ar, int index);
    bool PublishSimStateEvent(std::string event, int eventCode, std::string eventData);

private:
    std::weak_ptr<SimStateManager> simStateManager_;
    std::vector<IccState> iccState_; // icc card states
    std::vector<ExternalState> externalState_; // need to broadcast sim state;
    IRilManager *rilManager_; // ril manager
};
} // namespace SIM
} // namespace OHOS

#endif // __SIM_STATE_HANDLE__
