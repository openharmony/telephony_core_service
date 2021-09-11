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

#include <iostream>
#include <cstring>
#include <string>
#include "icc_file_controller.h"

#define SIM_SMS_GET_COMPLETED 1
#define SIM_SMS_UPDATE_COMPLETED 2
#define SIM_SMS_WRITE_COMPLETED 3
#define SIM_SMS_DELETE_COMPLETED 4

namespace OHOS {
namespace Telephony {
enum Action_Type { ACTION_NONE, OBTAIN_SMS, WRITE_SMS, UPDATE_SMS, DELETE_SMS };
enum {
    SIM_SMS_STATE_DELETE = 0,
    SIM_SMS_STATE_READ = 1,
    SIM_SMS_STATE_UNREAD = 3,
    SIM_SMS_STATE_SENT = 5,
    SIM_SMS_STATE_UNSENT = 7,
};
static Action_Type g_CurAction = ACTION_NONE;
class SimSmsController : public AppExecFwk::EventHandler {
public:
    SimSmsController(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~SimSmsController();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    bool AddSmsToIcc(int status, std::string &pdu, std::string &smsc);
    bool RenewSmsIcc(int index, int status, std::string &pduData, std::string &smsc);
    bool DelSmsIcc(int index);
    std::vector<std::string> ObtainAllSmsOfIcc();
    void SetRilAndFileController(
        std::shared_ptr<Telephony::IRilManager> ril, std::shared_ptr<IccFileController> file);
    void Init();

protected:
    std::shared_ptr<IccFileController> fileController_ = nullptr;
    std::shared_ptr<Telephony::IRilManager> rilManager_ = nullptr;
    bool result_ = false;

private:
    bool PhoneTypeGsmOrNot() const;
    std::vector<std::string> smsList_;
    std::mutex mtx_;
    std::condition_variable processWait_;
    void ProcessLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessWriteDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDeleteDone(const AppExecFwk::InnerEvent::Pointer &event);
    AppExecFwk::InnerEvent::Pointer CreatePointer(int eventId);
    static bool IsActionOn();
    void SetCurAction(Action_Type action);
    Action_Type GetCurAction();
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_SMS_CONTROLLER_H