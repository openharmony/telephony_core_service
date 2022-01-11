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

#ifndef OHOS_ISIM_FILE_H
#define OHOS_ISIM_FILE_H

#include "icc_file.h"

namespace OHOS {
namespace Telephony {
class IsimFile : public IccFile {
public:
    IsimFile(
        const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<ISimStateManager> simStateManager);
    void Init();
    void StartLoad();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    ~IsimFile();
    bool ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event);
    std::string ObtainIsimImpi();
    std::string ObtainIsimDomain();
    std::string *ObtainIsimImpu();
    std::string ObtainIsimIst();
    std::string *ObtainIsimPcscf();
    bool UpdateVoiceMail(const std::string &mailName, const std::string &mailNumber);
    int ObtainSpnCondition(bool roaming, const std::string &operatorNum);
    std::string ObtainIsoCountryCode();

protected:
    void ProcessIccRefresh(int msgId);
    void ProcessFileLoaded(bool response);
    void OnAllFilesFetched();
    void LoadIsimFiles();
    bool ProcessIsimRefresh(const AppExecFwk::InnerEvent::Pointer &event);

private:
    using RecordProcessFunc = bool (IsimFile::*)(const AppExecFwk::InnerEvent::Pointer &event);
    std::map<int, RecordProcessFunc> memberFuncMap_;
    void InitMemberFunc();
    void ProcessLockedAllFilesFetched();
    bool ProcessGetImsiDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetIccidDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetImpiDone(const AppExecFwk::InnerEvent::Pointer &event);
    const int LOAD_STEP = 1;
    // see 3GPP TS 31.103
    std::string impi_ = "";
    std::string domain_ = "";
    std::string* impu_ = nullptr;
    std::string ist_ = "";
    std::string* pcscf_ = nullptr;
    std::string authRsp_ = "";
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ISIM_FILE_H