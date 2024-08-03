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

#include "iservice_registry.h"
#include "operator_config_cache.h"
#include "operator_config_loader.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace OHOS::EventFwk;
class SimStateTracker : public TelEventHandler {
public:
    SimStateTracker(std::weak_ptr<SimFileManager> simFileManager,
        std::shared_ptr<OperatorConfigCache> operatorConfigCache, int32_t slotId);
    ~SimStateTracker();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    bool RegisterForIccLoaded();
    bool RegisterOpkeyLoaded();
    bool RegisterOperatorCacheDel();
    bool UnRegisterForIccLoaded();
    bool UnRegisterOpkeyLoaded();
    bool UnregisterOperatorCacheDel();

    std::shared_ptr<OperatorConfigLoader> operatorConfigLoader_ = nullptr;

private:
    inline static const std::string OPERATOR_CONFIG_CHANGED = "operatorConfigChanged";
    std::weak_ptr<SimFileManager> simFileManager_;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
    std::shared_ptr<OperatorConfigCache> operatorConfigCache_ = nullptr;
    int32_t slotId_;
    OperatorConfig config_;
    void ProcessSimRecordLoad(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessSimOpkeyLoad(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessOperatorCacheDel(const AppExecFwk::InnerEvent::Pointer &event);
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_SIMSTATETRACKER_H