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

#ifndef TELEPHONY_SIMSTATETRACKER_H
#define TELEPHONY_SIMSTATETRACKER_H

#include <string>

#include "telephony_log_wrapper.h"
#include "operator_conf.h"

namespace OHOS {
namespace Telephony {
class SimStateTracker : public AppExecFwk::EventHandler {
public:
    SimStateTracker(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
            std::shared_ptr<SimFileManager> simFileManager, int32_t slotId);
    virtual ~SimStateTracker();
    bool GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    bool RegisterForIccLoaded();
    bool UnRegisterForIccLoaded();

    std::unique_ptr<OperatorConf> operatorConf_ = nullptr;

private:
    bool AnnounceOperatorConfigChanged();
    inline static const std::string COMMON_EVENT_TELEPHONY_OPERATOR_CONFIG_CHANGED =
            "com.hos.action.OPERATOR_CONFIG_CHANGED";
    inline static const std::string OPERATOR_CONFIG_CHANGED = "operatorConfigChanged";
    std::shared_ptr<SimFileManager> simFileManager_ = nullptr;
    int32_t slotId_;
    OperatorConfig conf_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_SIMSTATETRACKER_H