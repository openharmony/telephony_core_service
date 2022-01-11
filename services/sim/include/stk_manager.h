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

#ifndef OHOS_STK_MANAGER_H
#define OHOS_STK_MANAGER_H

#include "observer_handler.h"
#include "i_stk_manager.h"
#include "i_sim_state_manager.h"
#include "i_tel_ril_manager.h"
#include "stk_controller.h"

namespace OHOS {
namespace Telephony {
class StkManager : public IStkManager {
public:
    StkManager(std::shared_ptr<ITelRilManager> telRilManager, std::shared_ptr<ISimStateManager> simStateManage);
    ~StkManager() {};
    void Init(int slotId) override;
    bool SendEnvelopeCmd(const std::string &cmd) override;
    bool SendTerminalResponseCmd(const std::string &cmd) override;

private:
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<ISimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<StkController> stkController_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopStkController_ = nullptr;
    enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };
    HandleRunningState stateStkMgr_ = HandleRunningState::STATE_NOT_START;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_STK_MANAGER_H
