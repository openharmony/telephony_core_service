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

#ifndef OHOS_USIM_OPERATOR_PRIVILEGE_CONTROLLER_H
#define OHOS_USIM_OPERATOR_PRIVILEGE_CONTROLLER_H

#include <atomic>
#include <string_view>

#include "event_handler.h"
#include "event_runner.h"

#include "sim_state_manager.h"
#include "i_tel_ril_manager.h"
#include "icc_operator_rule.h"

namespace OHOS {
namespace Telephony {
class IccOperatorPrivilegeController : public AppExecFwk::EventHandler {
public:
    enum : uint32_t {
        MSG_OPEN_LOGICAL_CHANNEL_DONE = 0x7ffffff0,
        MSG_TRANSMIT_LOGICAL_CHANNEL_DONE = 0x7ffffff1,
        MSG_CLOSE_LOGICAL_CHANNEL_DONE = 0x7ffffff2
    };

    IccOperatorPrivilegeController(std::shared_ptr<AppExecFwk::EventRunner> runner,
        std::shared_ptr<Telephony::ITelRilManager> telRilManager,
        std::shared_ptr<SimStateManager> simStateManager);

    virtual ~IccOperatorPrivilegeController();

    void Init(const int32_t slotId);
    int32_t HasOperatorPrivileges(bool &hasOperatorPrivileges);
    int32_t HasOperatorPrivileges(
        const std::string_view &certHash, const std::string_view &packageName, bool &hasOperatorPrivileges);

protected:
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    virtual void ProcessSimStateChanged();
    virtual void ProcessOpenLogicalChannelDone(const AppExecFwk::InnerEvent::Pointer &event);
    virtual void ProcessTransmitLogicalChannelDone(const AppExecFwk::InnerEvent::Pointer &event);
    virtual void ProcessCloseLogicalChannelDone();

private:
    void OpenChannel();

private:
    int32_t slotId_;
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_;
    std::shared_ptr<SimStateManager> simStateManager_;
    std::vector<IccOperatorRule> rules_;

    class LogicalStateMachine;
    LogicalStateMachine *const state_;
};
} // namespace Telephony
} // namespace OHOS
#endif
