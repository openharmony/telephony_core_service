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

#ifndef OHOS_SIM_DIALLING_NUMBERS_CACHE_H
#define OHOS_SIM_DIALLING_NUMBERS_CACHE_H

#include <algorithm>
#include <iostream>
#include <vector>
#include <map>

#include "icc_file_controller.h"
#include "sim_file_manager.h"
#include "icc_dialling_numbers_handler.h"
#include "usim_dialling_numbers_service.h"

namespace OHOS {
namespace Telephony {
enum {
    MSG_SIM_OBTAIN_ADN_DETAILS_DONE,
    MSG_SIM_CHANGE_DIALLING_NUMBERS_DONE,
    MSG_SIM_OBTAIN_PBR_DETAILS_DONE,
};

const int ADD_FLAG = -1;
class IccDiallingNumbersCache : public AppExecFwk::EventHandler {
public:
    IccDiallingNumbersCache(
        const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<SimFileManager> simFileManager);
    ~IccDiallingNumbersCache();
    void Init();
    std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> LoadReadyDiallingNumbers(int fileId);
    int ExtendedElementFile(int fileId);
    void UpdateDiallingNumberToIcc(int fileId, std::shared_ptr<DiallingNumbersInfo> diallingNumberInfor,
        int recordIndex, bool isDel, const AppExecFwk::InnerEvent::Pointer &caller);
    void ObtainAllDiallingNumberFiles(int fileId, int extensionEf, const AppExecFwk::InnerEvent::Pointer &caller);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);

protected:
    std::shared_ptr<SimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<IccDiallingNumbersHandler> diallingNumbersHandler_ = nullptr;
    std::shared_ptr<UsimDiallingNumbersService> usimDiallingNumberSrv_ = nullptr;
    std::map<int, std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>>> diallingNumberFileList_;
    std::map<int, int> extTypeMap_;
    void SendUpdateResult(const AppExecFwk::InnerEvent::Pointer &caller, const std::shared_ptr<void> &object);
    void SendBackResult(const AppExecFwk::InnerEvent::Pointer &caller,
        const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &ar,
        const std::shared_ptr<void> &object);

private:
    void SendExceptionResult(const AppExecFwk::InnerEvent::Pointer &caller, int errCode);
    AppExecFwk::InnerEvent::Pointer BuildCallerInfo(
        int eventId, int fileId, int index, std::shared_ptr<void> pobj, const AppExecFwk::InnerEvent::Pointer &caller);
    AppExecFwk::InnerEvent::Pointer CreateUsimPointer(
        int eventId, int fileId, const AppExecFwk::InnerEvent::Pointer &caller);
    void ProcessObtainAdnDetailsDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessChangeDiallingNumbersDone(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessObtainPbrDetailsDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool IsDiallingNumberEqual(
        const std::shared_ptr<DiallingNumbersInfo> &src, const std::shared_ptr<DiallingNumbersInfo> &dest);
    bool StringEqual(const std::u16string &s1, const std::u16string &s2);
    bool ArrayEqual(const std::vector<std::u16string> &mailsSrc, const std::vector<std::u16string> &mailsDest);
    bool CheckValueAndOperation(const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &list,
        const std::shared_ptr<DiallingNumbersInfo> &info, int &index, int fileId);
    void InitFileTypeMap();
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_DIALLING_NUMBERS_CACHE_H