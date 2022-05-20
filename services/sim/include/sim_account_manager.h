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

#ifndef OHOS_SIM_ACCOUNT_MANAGER_H
#define OHOS_SIM_ACCOUNT_MANAGER_H

#include "multi_sim_controller.h"
#include "multi_sim_monitor.h"
#include "i_tel_ril_manager.h"
#include "sim_state_manager.h"
#include "sim_file_manager.h"
#include "sim_state_tracker.h"
#include "icc_operator_privilege_controller.h"

namespace OHOS {
namespace Telephony {
class SimAccountManager {
public:
    SimAccountManager(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
        std::shared_ptr<SimStateManager> simStateManager, std::shared_ptr<SimFileManager> simFileManager);
    ~SimAccountManager();
    void Init(int32_t slotId);
    void SetNetworkSearchManager(std::shared_ptr<INetworkSearch> networkSearchManager);
    bool IsSimActive(int32_t slotId);
    bool IsSimActivatable(int32_t slotId);
    bool SetActiveSim(int32_t slotId, int32_t enable);
    bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    bool SetDefaultVoiceSlotId(int32_t slotId);
    bool SetDefaultSmsSlotId(int32_t slotId);
    bool SetDefaultCellularDataSlotId(int32_t slotId);
    bool SetPrimarySlotId(int32_t slotId);
    bool SetShowNumber(int32_t slotId, std::u16string Number);
    bool SetShowName(int32_t slotId, std::u16string name);
    int32_t GetDefaultVoiceSlotId();
    int32_t GetDefaultSmsSlotId();
    int32_t GetDefaultCellularDataSlotId();
    int32_t GetPrimarySlotId();
    std::u16string GetShowNumber(int32_t slotId);
    std::u16string GetShowName(int32_t slotId);
    bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    bool GetOperatorConfigs(int slotId, OperatorConfig &poc);
    bool HasOperatorPrivileges(const int32_t slotId);
    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);

private:
    bool IsValidSlotId(int32_t);
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<SimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<SimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<MultiSimController> multiSimController_ = nullptr;
    std::shared_ptr<MultiSimMonitor> multiSimMonitor_ = nullptr;
    std::shared_ptr<SimStateTracker> simStateTracker_ = nullptr;
    std::vector<IccAccountInfo> activeInfos_;
    std::shared_ptr<IccOperatorPrivilegeController> privilegeController_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> controllerRunner_;
    std::shared_ptr<AppExecFwk::EventRunner> monitorRunner_;
    std::shared_ptr<AppExecFwk::EventRunner> privilegesRunner_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_ACCOUNT_MANAGER_H
