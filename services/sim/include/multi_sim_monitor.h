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

#ifndef OHOS_MULTI_SIM_MONITOR_H
#define OHOS_MULTI_SIM_MONITOR_H

#include <list>

#include "multi_sim_controller.h"
#include "sim_file_manager.h"
#include "telephony_log_wrapper.h"
#include "sim_constant.h"
#include "sim_data.h"
#include "rdb_sim_helper.h"

namespace OHOS {
namespace Telephony {
class MultiSimMonitor : public AppExecFwk::EventHandler {
public:
    MultiSimMonitor(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        const std::shared_ptr<MultiSimController> &controller,
        std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
        std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager);
    virtual ~MultiSimMonitor() = default;

    void Init();
    bool RegisterForIccLoaded(int32_t slotId);
    bool UnRegisterForIccLoaded(int32_t slotId);
    bool RegisterForSimStateChanged(int32_t slotId);
    bool UnRegisterForSimStateChanged(int32_t slotId);
    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);

private:
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void RefreshData(int32_t slotId);
    void InitData(int32_t slotId);
    bool IsValidSlotId(int32_t slotId);

private:
    bool ready_ = false;
    std::shared_ptr<MultiSimController> controller_ = nullptr;
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager_;
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_MULTI_SIM_MONITOR_H

