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

#ifndef OHOS_STK_CONTROLLER_H
#define OHOS_STK_CONTROLLER_H

#include "event_handler.h"
#include "inner_event.h"
#include "i_tel_ril_manager.h"
#include "i_sim_state_manager.h"
#include "want.h"

namespace OHOS {
namespace Telephony {
const int MSG_STK_TERMINAL_RESPONSE = 1;
const int MSG_STK_CMD_ENVELOPE = 2;
const int MSG_STK_CONTROLLER_IS_READY = 3;

class StkController : public AppExecFwk::EventHandler {
public:
    StkController(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~StkController();
    void Init(int slotId);
    void SetRilAndSimStateManager(std::shared_ptr<Telephony::ITelRilManager> ril,
        const std::shared_ptr<Telephony::ISimStateManager> simstateMgr);
    bool SendTerminalResponseCmd(const std::string &strCmd);
    bool SendEnvelopeCmd(const std::string &strCmd);

private:
    void RegisterEvents();
    void UnRegisterEvents();
    bool OnsendRilSessionEnd(const AppExecFwk::InnerEvent::Pointer &event);
    bool OnsendRilProactiveCommand(const AppExecFwk::InnerEvent::Pointer &event);
    bool OnsendRilAlphaNotify(const AppExecFwk::InnerEvent::Pointer &event);
    bool OnIccStateChanged(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    bool PublishStkEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData);
    void GetTerminalResponseResult(const AppExecFwk::InnerEvent::Pointer &event);
    void GetEnvelopeCmdResult(const AppExecFwk::InnerEvent::Pointer &event);

private:
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<Telephony::ISimStateManager> simStateManager_ = nullptr;
    int slotId_ = 0;
    const std::string ACTION_SESSION_END = "usual.event.telpnony.STK_SESSION_END";
    const std::string ACTION_ALPHA_IDENTIFIER = "usual.event.telpnony.STK_ALPHA_IDENTIFIER";
    const std::string ACTION_CARD_STATUS_INFORM = "usual.event.telpnony.STK_CARD_STATUS_INFORM";
    const std::string ACTION_STK_COMMAND = "usual.event.telpnony.STK_COMMAND";

    int32_t iccCardState_ = 0;
    int32_t envelopeResponse_ = 0;
    int32_t terminalResponse_ = 0;
    bool responseReady_ = false;
    std::mutex ctx_;
    std::condition_variable cv_;

    const int32_t EVENT_CODE = 1;
    const std::string PARAM_SLOTID = "slotID";
    const std::string PARAM_MSG_CMD = "msgCmd";
    const std::string PARAM_CARD_STATUS = "cardStatus";
    const std::string PARAM_ALPHA_STRING = "alphaString";

    const int32_t ICC_CARD_STATE_ABSENT = 0;
    const int32_t ICC_CARD_STATE_PRESENT = 1;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_STK_CONTROLLER_H
