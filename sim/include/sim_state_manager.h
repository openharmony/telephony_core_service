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

#ifndef __SIM_STATE_MANAGER__
#define __SIM_STATE_MANAGER__

#include "i_sim_state_manager.h"
#include "sim_state_handle.h"

namespace OHOS {
namespace SIM {
enum SimHandleRun { STATE_NOT_START, STATE_RUNNING };

class SimStateManager : public ISimStateManager, public std::enable_shared_from_this<SimStateManager> {
public:
    SimStateManager();
    virtual ~SimStateManager();
    void NotifyIccStateChanged();
    void NotifyIccReady();
    void TestSimStateManager();
    virtual void Init() override;
    virtual bool HasSimCard(int32_t slotId) override;
    virtual int32_t GetSimState(int32_t slotId) override;
    virtual bool IsSimActive(int32_t slotId) override;
    virtual void RegisterForIccStateChanged(HANDLE &handler) override;
    virtual void UnregisterForIccStateChanged(HANDLE &handler) override;
    virtual void RegisterForReady(HANDLE &handler) override;
    virtual void UnregisterForReady(HANDLE &handler) override;

private:
    std::shared_ptr<SimStateHandle> simStateHandle_;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop_;
    SimHandleRun simStateRun_;
    std::unique_ptr<ObserverHandler> observerHandler_;
    std::mutex mtx_;
};
} // namespace SIM
} // namespace OHOS
#endif // __SIM_STATE_MANAGER__
