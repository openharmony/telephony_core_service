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

#ifndef OHOS_SIM_SMS_CONTROLLER_H
#define OHOS_SIM_SMS_CONTROLLER_H

#include "icc_file_controller.h"
#include "sim_state_manager.h"
#include "sim_file_manager.h"

namespace OHOS {
namespace Telephony {
enum {
    SIM_SMS_STATE_DELETE = 0,
    SIM_SMS_STATE_READ = 1,
    SIM_SMS_STATE_UNREAD = 3,
    SIM_SMS_STATE_SENT = 5,
    SIM_SMS_STATE_UNSENT = 7,
};

enum {
    SIM_SMS_GET_COMPLETED = 1,
    SIM_SMS_UPDATE_COMPLETED = 2,
    SIM_SMS_WRITE_COMPLETED = 3,
    SIM_SMS_DELETE_COMPLETED = 4
};

class SimSmsController : public AppExecFwk::EventHandler {
public:
    SimSmsController(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        std::shared_ptr<ISimStateManager> simStateManager);
    ~SimSmsController();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    bool AddSmsToIcc(int status, std::string &pdu, std::string &smsc);
    bool UpdateSmsIcc(int index, int status, std::string &pduData, std::string &smsc);
    bool DelSmsIcc(int index);
    std::vector<std::string> ObtainAllSmsOfIcc();
    void SetRilAndFileManager(
        std::shared_ptr<Telephony::ITelRilManager> ril, std::shared_ptr<SimFileManager> fileMgr);
    void Init(int slotId);

protected:
    std::shared_ptr<SimFileManager> fileManager_ = nullptr;
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<ISimStateManager> stateManager_ = nullptr;
    bool result_ = false;
    int slotId_ = 0;

private:
    bool IsCdmaCardType() const;
    std::vector<std::string> smsList_;
    static std::mutex mtx_;
    std::condition_variable processWait_;
    void ProcessLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessWriteDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDeleteDone(const AppExecFwk::InnerEvent::Pointer &event);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_SMS_CONTROLLER_H