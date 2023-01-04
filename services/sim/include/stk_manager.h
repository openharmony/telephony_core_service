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

#include "i_tel_ril_manager.h"
#include "sim_state_manager.h"
#include "stk_controller.h"

namespace OHOS {
namespace Telephony {
class StkManager {
public:
    StkManager(std::shared_ptr<ITelRilManager> telRilManager, std::shared_ptr<SimStateManager> simStateManager);
    virtual ~StkManager();
    void Init(int slotId);
    int32_t SendEnvelopeCmd(int32_t slotId, const std::string &cmd) const;
    int32_t SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) const;
    int32_t SendCallSetupRequestResult(int32_t slotId, bool accept) const;

private:
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<SimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<StkController> stkController_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> stkEventLoop_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_STK_MANAGER_H
