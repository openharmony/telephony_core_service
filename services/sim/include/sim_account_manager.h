/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_SIM_ACCOUNT_MANAGER_H
#define OHOS_SIM_ACCOUNT_MANAGER_H

#include "i_tel_ril_manager.h"
#include "icc_operator_privilege_controller.h"
#include "operator_config_cache.h"
#include "sim_file_manager.h"
#include "sim_state_manager.h"
#include "sim_state_tracker.h"

namespace OHOS {
namespace Telephony {
class SimAccountManager {
public:
    SimAccountManager(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
        std::shared_ptr<SimStateManager> simStateManager, std::shared_ptr<SimFileManager> simFileManager);
    ~SimAccountManager();

    void Init(int32_t slotId);
    bool GetOperatorConfigs(int slotId, OperatorConfig &poc);
    bool HasOperatorPrivileges(const int32_t slotId);

private:
    bool IsValidSlotId(int32_t);
    bool IsValidSlotIdForDefault(int32_t);

private:
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<SimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<SimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<SimStateTracker> simStateTracker_ = nullptr;
    std::shared_ptr<OperatorConfigCache> operatorConfigCache_ = nullptr;
    std::shared_ptr<IccOperatorPrivilegeController> privilegeController_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> simAccountRunner_;
    std::shared_ptr<AppExecFwk::EventRunner> privilegesRunner_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_ACCOUNT_MANAGER_H
