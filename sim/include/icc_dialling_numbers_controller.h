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

#ifndef OHOS_ICC_DIALLING_NUMBERS_CONTROLLER_H
#define OHOS_ICC_DIALLING_NUMBERS_CONTROLLER_H

#include <iostream>
#include <cstring>
#include <string>
#include "i_tel_ril_manager.h"
#include "sim_dialling_numbers_station.h"
#include "sim_file_manager.h"

namespace OHOS {
namespace Telephony {
enum PhoneBook_Action_Type {
    ACTION_READY,
    OBTAIN_PHONE_BOOK,
    WRITE_PHONE_BOOK,
    UPDATE_PHONE_BOOK,
    DELETE_PHONE_BOOK,
};

enum PhoneBookMessageType {
    PHONE_BOOK_GET_COMPLETED  = 1,
    PHONE_BOOK_UPDATE_COMPLETED,
    PHONE_BOOK_WRITE_COMPLETED,
    PHONE_BOOK_DELETE_COMPLETED,
};

static PhoneBook_Action_Type g_CurCtrlAction = ACTION_READY;
class IccDiallingNumbersController : public AppExecFwk::EventHandler {
public:
    IccDiallingNumbersController(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        std::shared_ptr<ISimFileManager> simFileManager);
    ~IccDiallingNumbersController();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type);
    bool AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    void Init();
    enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };

protected:
    std::shared_ptr<SimDiallingNumbersStation> phoneBookCache_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopPhoneBook_ = nullptr;
    HandleRunningState statePhoneBook_ = HandleRunningState::STATE_NOT_START;
    bool result_ = false;

private:
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> phoneBookList_;
    std::mutex mtx_;
    std::condition_variable processWait_;
    void ProcessLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessWriteDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDeleteDone(const AppExecFwk::InnerEvent::Pointer &event);
    AppExecFwk::InnerEvent::Pointer CreatePointer(int eventId);
    static bool IsActionOn();
    void SetCurAction(PhoneBook_Action_Type action);
    PhoneBook_Action_Type GetCurAction();
    void ClearRecords();
    int GetFileIdForType(int fileType);
    void FillResults(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &listInfo);
    bool IsValidType(int type);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ICC_DIALLING_NUMBERS_CONTROLLER_H