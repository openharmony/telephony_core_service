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

#ifndef OHOS_SIM_SMS_MANAGER_H
#define OHOS_SIM_SMS_MANAGER_H

#include "core_manager.h"
#include "event_handler.h"
#include "event_runner.h"
#include "i_tel_ril_manager.h"
#include "i_sim_sms_manager.h"
#include "sim_sms_controller.h"

namespace OHOS {
namespace Telephony {
class SimSmsManager : public ISimSmsManager {
public:
    SimSmsManager(std::shared_ptr<ITelRilManager> telRilManager,
        std::shared_ptr<ISimFileManager> simFileManager, std::shared_ptr<ISimStateManager> simStateManager);
    virtual ~SimSmsManager();
    void Init(int slotId);
    bool AddSmsToIcc(int status, std::string &pdu, std::string &smsc);
    bool UpdateSmsIcc(int index, int status, std::string &pduData, std::string &smsc);
    bool DelSmsIcc(int index);
    std::vector<std::string> ObtainAllSmsOfIcc();
    enum class HandleRunningState {
        STATE_NOT_START,
        STATE_RUNNING
    };

protected:
    int slotId_ = 0;
    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<ISimStateManager> stateManager_ = nullptr;
    std::shared_ptr<SimSmsController> smsController_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopSms_ = nullptr;
    HandleRunningState stateSms_ = HandleRunningState::STATE_NOT_START;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_SMS_MANAGER_H
