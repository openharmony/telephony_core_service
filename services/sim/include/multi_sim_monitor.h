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
#include "sim_constant.h"
#include "sim_file_manager.h"
#include "system_ability_status_change_stub.h"
#include "telephony_log_wrapper.h"

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
    void RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);
    int32_t RegisterSimAccountCallback(const std::string &bundleName, const sptr<SimAccountCallback> &callback);
    int32_t UnregisterSimAccountCallback(const std::string &bundleName);
    void NotifySimAccountChanged();

private:
    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        SystemAbilityStatusChangeListener(std::shared_ptr<AppExecFwk::EventHandler> multiSimMonitorHandler,
            std::shared_ptr<MultiSimController> controller,
            std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_);
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

    private:
        std::weak_ptr<AppExecFwk::EventHandler> multiSimMonitorHandler_;
        std::shared_ptr<MultiSimController> controller_ = nullptr;
        std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    };

private:
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    void RefreshData(int32_t slotId);
    void InitData(int32_t slotId);
    bool IsValidSlotId(int32_t slotId);
    void InitListener();

private:
    struct SimAccountCallbackRecord {
        std::string bundleName = "";
        sptr<SimAccountCallback> simAccountCallback = nullptr;
    };

    std::shared_ptr<MultiSimController> controller_ = nullptr;
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager_;
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    std::unique_ptr<ObserverHandler> observerHandler_ = nullptr;
    std::list<SimAccountCallbackRecord> listSimAccountCallbackRecord_;
    std::mutex mutexInner_;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_MULTI_SIM_MONITOR_H

