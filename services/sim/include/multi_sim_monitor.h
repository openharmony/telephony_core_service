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

#include "i_sim_account_manager.h"
#include "telephony_log_wrapper.h"
#include "sim_constant.h"
#include "sim_data.h"
#include "multi_sim_controller.h"
#include "rdb_sim_helper.h"

namespace OHOS {
namespace Telephony {
class MultiSimMonitor : public AppExecFwk::EventHandler {
public:
    MultiSimMonitor(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
            const std::shared_ptr<MultiSimController> &controller,
            std::shared_ptr<ISimStateManager> simStateManager,
            std::shared_ptr<ISimFileManager> simFileManager);
    virtual ~MultiSimMonitor();
    void Init(int32_t slotId);
    bool RegisterForIccLoaded();
    bool UnRegisterForIccLoaded();

private:
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    int32_t slotId_;
    std::shared_ptr<MultiSimController> controller_ = nullptr;
    std::shared_ptr<ISimStateManager> simStateManager_ = nullptr;
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_MULTI_SIM_MONITOR_H

