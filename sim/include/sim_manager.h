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

#ifndef TELEPHONY_SIM_MANAGER_H
#define TELEPHONY_SIM_MANAGER_H

#include "i_sim_manager.h"
#include "telephony_log_wrapper.h"
#include "multi_sim_controller.h"

namespace OHOS {
namespace Telephony {
class SimManager : public ISimManager {
public:
    SimManager();
    virtual ~SimManager();
    void Init() override;
    bool GetSimAccountInfo(int32_t subId, IccAccountInfo &info) override;
    bool SetDefaultVoiceSlotId(int32_t subId) override;
    bool SetDefaultSmsSlotId(int32_t subId) override;
    int32_t GetDefaultVoiceSlotId() override;
    int32_t GetDefaultSmsSlotId() override;
    bool IsValidSimId(int32_t);

protected:
private:
    std::unique_ptr<MultiSimController> multiSimController_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_SIM_MANAGER_H
