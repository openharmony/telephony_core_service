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

#include "i_tel_ril_manager.h"
#include "i_sim_account_manager.h"
#include "i_sim_state_manager.h"
#include "i_sim_file_manager.h"
#include "i_network_search.h"
#include "multi_sim_controller.h"
#include "multi_sim_monitor.h"
#include "sim_state_tracker.h"
#include "icc_operator_privilege_controller.h"

namespace OHOS {
namespace Telephony {
class SimAccountManager : public ISimAccountManager {
public:
    SimAccountManager(std::shared_ptr<ITelRilManager> telRilManager,
               std::shared_ptr<ISimStateManager> simStateManager,
               std::shared_ptr<ISimFileManager> simFileManager,
               std::shared_ptr<INetworkSearch> networkSearchManager);
    virtual ~SimAccountManager();
    void Init(int32_t slotId) override;
    bool IsSimActive(int32_t slotId) override;
    bool SetActiveSim(int32_t slotId, int32_t enable) override;
    bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info) override;
    bool SetDefaultVoiceSlotId(int32_t slotId) override;
    bool SetDefaultSmsSlotId(int32_t slotId) override;
    bool SetDefaultCellularDataSlotId(int32_t slotId) override;
    bool SetPrimarySlotId(int32_t slotId) override;
    bool SetShowNumber(int32_t slotId, std::u16string Number) override;
    bool SetShowName(int32_t slotId, std::u16string name) override;
    int32_t GetDefaultVoiceSlotId() override;
    int32_t GetDefaultSmsSlotId() override;
    int32_t GetDefaultCellularDataSlotId() override;
    int32_t GetPrimarySlotId() override;
    std::u16string GetShowNumber(int32_t slotId) override;
    std::u16string GetShowName(int32_t slotId) override;
    bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList) override;
    bool GetOperatorConfigs(int slotId, OperatorConfig &poc) override;
    bool HasOperatorPrivileges(const int32_t slotId) override;

private:
    bool IsValidSlotId(int32_t);
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<ISimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<INetworkSearch> netWorkSearchManager_ = nullptr;
    std::shared_ptr<MultiSimController> multiSimController_ = nullptr;
    std::shared_ptr<SimStateTracker> simStateTracker_ = nullptr;
    std::vector<IccAccountInfo> activeInfos_;
    std::shared_ptr<MultiSimMonitor> multiSimMonitor_ = nullptr;
    std::map<int32_t, std::shared_ptr<IccOperatorPrivilegeController>> privilegeControllers_;
    std::shared_ptr<AppExecFwk::EventRunner> runner_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_ACCOUNT_MANAGER_H
