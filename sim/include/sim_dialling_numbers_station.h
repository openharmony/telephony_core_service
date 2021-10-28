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

#ifndef OHOS_SIM_DIALLING_NUMBERS_STATION_H
#define OHOS_SIM_DIALLING_NUMBERS_STATION_H

#include <algorithm>
#include <iostream>
#include <vector>
#include <map>

#include "core_manager.h"
#include "icc_file_controller.h"
#include "sim_file_manager.h"
#include "sim_dialling_numbers_handler.h"
#include "usim_dialling_numbers_service.h"

#define MSG_SIM_OBTAIN_ALL_ADN_FILES_DONE 1
#define MSG_SIM_CHANGE_ADN_COMPLETED 2

namespace OHOS {
namespace Telephony {
class UsimDiallingNumbersService;
class SimDiallingNumbersStation : public AppExecFwk::EventHandler {
public:
    SimDiallingNumbersStation(
        const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<ISimFileManager> simFileManager);
    ~SimDiallingNumbersStation();
    void Init();
    void Reset();
    void ResetPointers();
    void ResetCallerPointers();
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> LoadReadyDiallingNumbers(int efid);
    int ExtendedElementFile(int efid);
    void ChangeDiallingNumberForId(int efid, std::shared_ptr<DiallingNumbersInfo> diallingNumberInfor,
        int recordIndex, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response);
    void ChangeDiallingNumberForContents(int efid, std::shared_ptr<DiallingNumbersInfo> oldDiallingNumber,
        std::shared_ptr<DiallingNumbersInfo> latestDiallingNumber, std::string pin2,
        const AppExecFwk::InnerEvent::Pointer &response);
    void ObtainAllDiallingNumberFiles(int efid, int extensionEf, const AppExecFwk::InnerEvent::Pointer &response);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);

protected:
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<SimDiallingNumbersHandler> pbLoader_ = nullptr;
    std::shared_ptr<UsimDiallingNumbersService> usimDiallingNumberSrv_ = nullptr;
    std::map<int, std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>>> diallingNumberFileList_;
    std::map<int, std::vector<AppExecFwk::InnerEvent::Pointer>> diallingNumberFilePointers_;
    std::map<int, AppExecFwk::InnerEvent::Pointer> callerPointers_;
    void BackToAllPointers(const std::vector<AppExecFwk::InnerEvent::Pointer> &waiters,
        const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &ar,
        const std::shared_ptr<void> &object);
    void SendUpdateResult(const AppExecFwk::InnerEvent::Pointer &response, const std::shared_ptr<void> &object);
    void SendBackResult(const AppExecFwk::InnerEvent::Pointer &response,
        const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &ar,
        const std::shared_ptr<void> &object);

private:
    void SendExceptionResult(const AppExecFwk::InnerEvent::Pointer &response, int errCode);
    AppExecFwk::InnerEvent::Pointer CreatePointer(int eventid, int efId, int index, std::shared_ptr<void> pobj);
    void ProcessDiallingNumberAllLikeLoadDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessDiallingNumberUpdateDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool IsDiallingNumberEqual(
        const std::shared_ptr<DiallingNumbersInfo> &src, const std::shared_ptr<DiallingNumbersInfo> &dest);
    bool StringCompareNullEqualsEmpty(std::u16string &s1, std::u16string &s2);
    bool ArrayEqual(const std::vector<std::u16string> &mailsSrc, const std::vector<std::u16string> &mailsDest);
    bool CheckValueAndOperation(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list,
        const std::shared_ptr<DiallingNumbersInfo> &info, int &index, int efId);
    bool CheckForSearch(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list,
        const std::shared_ptr<DiallingNumbersInfo> &info, int &index,
        const AppExecFwk::InnerEvent::Pointer &response);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_DIALLING_NUMBERS_STATION_H