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

#ifndef OHOS_ICC_DIALLING_NUMBERS_MANAGER_H
#define OHOS_ICC_DIALLING_NUMBERS_MANAGER_H

#include <iostream>
#include <cstring>
#include <string>

#include "i_tel_ril_manager.h"
#include "icc_dialling_numbers_cache.h"
#include "sim_file_manager.h"

namespace OHOS {
namespace Telephony {
enum DiallingNumbers_Action_Type {
    ACTION_READY,
    OBTAIN_DIALLING_NUMBERS,
    WRITE_DIALLING_NUMBERS,
    UPDATE_DIALLING_NUMBERS,
    DELETE_DIALLING_NUMBERS,
};

enum DiallingNumbersMessageType {
    MSG_SIM_DIALLING_NUMBERS_GET_DONE  = 1,
    MSG_SIM_DIALLING_NUMBERS_UPDATE_DONE,
    MSG_SIM_DIALLING_NUMBERS_WRITE_DONE,
    MSG_SIM_DIALLING_NUMBERS_DELETE_DONE,
};
static DiallingNumbers_Action_Type g_CurCtrlAction = ACTION_READY;
class IccDiallingNumbersManager : public AppExecFwk::EventHandler, public IIccDiallingNumbersManager {
public:
    IccDiallingNumbersManager(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        std::shared_ptr<ISimFileManager> simFileManager, std::shared_ptr<ISimStateManager> simState);
    ~IccDiallingNumbersManager();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type);
    bool AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    void Init();
    static std::shared_ptr<IIccDiallingNumbersManager> CreateInstance(
        const std::shared_ptr<ISimFileManager> &simFile, const std::shared_ptr<ISimStateManager> &simState);
    enum class HandleRunningState {
        STATE_NOT_START,
        STATE_RUNNING
    };

protected:
    std::shared_ptr<IccDiallingNumbersCache> diallingNumbersCache_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopDiallingNumbers_ = nullptr;
    HandleRunningState stateDiallingNumbers_ = HandleRunningState::STATE_NOT_START;
    bool result_ = false;

private:
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<Telephony::ISimStateManager> simStateManager_ = nullptr;
    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbersList_;
    static std::mutex mtx_;
    std::condition_variable processWait_;
    void ProcessLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessWriteDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDeleteDone(const AppExecFwk::InnerEvent::Pointer &event);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(int eventId);
    void ClearRecords();
    int GetFileIdForType(int fileType);
    void FillResults(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &listInfo);
    bool IsValidType(int type);
    bool HasSimCard(int slotId);
    bool IsValidParam(int type, const std::shared_ptr<DiallingNumbersInfo> &info);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ICC_DIALLING_NUMBERS_MANAGER_H