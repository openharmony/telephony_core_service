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

#include "i_tel_ril_manager.h"
#include "inner_event.h"
#include "sim_state_manager.h"
#include "tel_event_handler.h"
#include "want.h"

namespace OHOS {
namespace Telephony {
class StkController : public TelEventHandler {
public:
    explicit StkController(const std::weak_ptr<Telephony::ITelRilManager> &telRilManager,
        const std::weak_ptr<Telephony::SimStateManager> &simStateManager, int32_t slotId);
    virtual ~StkController() = default;
    void Init();
    int32_t SendTerminalResponseCmd(const std::string &strCmd);
    int32_t SendEnvelopeCmd(const std::string &strCmd);
    int32_t SendCallSetupRequestResult(bool accept);
    void UnRegisterEvents();

private:
    void RegisterEvents();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    void OnIccStateChanged(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendRilSessionEnd(const AppExecFwk::InnerEvent::Pointer &event) const;
    void OnSendRilProactiveCommand(const AppExecFwk::InnerEvent::Pointer &event) const;
    void OnSendRilAlphaNotify(const AppExecFwk::InnerEvent::Pointer &event) const;
    void OnSendRilEventNotify(const AppExecFwk::InnerEvent::Pointer &event) const;
    void OnIccRefresh(const AppExecFwk::InnerEvent::Pointer &event) const;
    bool PublishStkEvent(const AAFwk::Want &want) const;
    void OnSendTerminalResponseResult(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendEnvelopeCmdResult(const AppExecFwk::InnerEvent::Pointer &event);
    void OnSendCallSetupRequestResult(const AppExecFwk::InnerEvent::Pointer &event);

private:
    std::weak_ptr<Telephony::ITelRilManager> telRilManager_;
    std::weak_ptr<Telephony::SimStateManager> simStateManager_;
    int slotId_ = 0;
    int32_t iccCardState_ = 0;
    int32_t envelopeResponseResult_ = 0;
    int32_t terminalResponseResult_ = 0;
    int32_t callSetupResponseResult_ = 0;
    bool responseFinished_ = false;
    std::mutex stkMutex_;
    std::condition_variable stkCv_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_STK_CONTROLLER_H
