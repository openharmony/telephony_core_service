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

#include "common_event_subscriber.h"
#include "iservice_registry.h"
#include "operator_config_cache.h"
#include "operator_config_loader.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace OHOS::EventFwk;
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
class SimStateTracker : public AppExecFwk::EventHandler {
public:
    SimStateTracker(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        std::shared_ptr<SimFileManager> simFileManager, std::shared_ptr<OperatorConfigCache> operatorConfigCache,
        int32_t slotId);
    ~SimStateTracker();
    void InitListener();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    bool RegisterForIccLoaded();
    bool UnRegisterForIccLoaded();

    std::shared_ptr<OperatorConfigLoader> operatorConfigLoader_ = nullptr;

private:
    inline static const std::string OPERATOR_CONFIG_CHANGED = "operatorConfigChanged";
    std::shared_ptr<SimFileManager> simFileManager_ = nullptr;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
    std::shared_ptr<OperatorConfigCache> operatorConfigCache_ = nullptr;
    int32_t slotId_;
    OperatorConfig config_;

private:
    class UserSwitchEventSubscriber : public CommonEventSubscriber {
    public:
        explicit UserSwitchEventSubscriber(
            const CommonEventSubscribeInfo &info, int32_t slotId, std::shared_ptr<OperatorConfigLoader> configLoader)
            : CommonEventSubscriber(info), slotId_(slotId), configLoader_(configLoader)
        {}
        ~UserSwitchEventSubscriber() = default;
        void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;

    private:
        const int32_t slotId_;
        std::shared_ptr<OperatorConfigLoader> configLoader_ = nullptr;
    };
    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        explicit SystemAbilityStatusChangeListener(int32_t slotId, std::shared_ptr<OperatorConfigLoader> configLoader);
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

    private:
        const int32_t slotId_;
        std::shared_ptr<OperatorConfigLoader> configLoader_ = nullptr;
        std::shared_ptr<UserSwitchEventSubscriber> userSwitchSubscriber_ = nullptr;
    };
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_SIMSTATETRACKER_H