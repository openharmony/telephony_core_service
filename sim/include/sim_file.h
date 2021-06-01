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
#ifndef OHOS_SIM_FILE_H
#define OHOS_SIM_FILE_H

#include <stdlib.h>
#include <cstring>
#include <string>
#include "sim_constant.h"
#include "icc_file.h"
#include "mcc_pool.h"

namespace OHOS {
namespace SIM {
class SimFile : public IccFile {
public:
    SimFile(
        const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<ISimStateManager> simStateManager);
    void Init();
    void StartLoad();
    std::string ObtainMsisdnNumber();
    std::string ObtainSimOperator();
    std::string ObtainIsoCountryCode();
    int ObtainCallForwardStatus();
    std::shared_ptr<UsimFunctionHandle> ObtainUsimFunctionHandle();
    void UpdateMsisdnNumber(std::string alphaTag, std::string number, EventPointer &onComplete);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    ~SimFile();
    bool ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event);

protected:
    enum SpnStatus {
        OBTAIN_SPN_NONE,
        OBTAIN_SPN_START,
        OBTAIN_SPN_GENERAL,
        OBTAIN_OPERATOR_NAMESTRING,
        OBTAIN_OPERATOR_NAME_SHORTFORM
    };
    void ProcessIccRefresh(int msgId);
    void ProcessFileLoaded(bool response);
    void OnAllFilesFetched();
    void LoadSimFiles();
    bool ProcessIccLocked(const AppExecFwk::InnerEvent::Pointer &event);
    void ObtainCallForwardFiles();
    void UpdateSimLanguage();
    int callFowardStatus_ = 0;
    unsigned char *cphsInfo_ = nullptr;
    bool cspPlmnOn_ = false;
    unsigned char *efMWIS_ = nullptr;
    unsigned char *efCphsMwi_ = nullptr;
    unsigned char *efCff_ = nullptr;
    unsigned char *efCfis_ = nullptr;
    std::string efLi_ = NULLSTR;
    std::string efPl_ = NULLSTR;
    SpnStatus spnStatus_ = OBTAIN_SPN_NONE;
    int displayConditionOfSpn_ = 0;
    std::vector<std::string> spdiNetworks_;
    std::shared_ptr<UsimFunctionHandle> UsimFunctionHandle_ = nullptr;

private:
    using FileProcessFunc = bool (SimFile::*)(const AppExecFwk::InnerEvent::Pointer &event);
    std::map<int, FileProcessFunc> memberFuncMap_;
    void InitMemberFunc();
    void LoadElementaryFileLiAndPI();
    void ObtainSpnPhase(bool start, const AppExecFwk::InnerEvent::Pointer &event);
    std::string AnalysisBcdPlmn(std::string data, std::string description);
    void ProcessElementaryFileCsp(std::string data);
    void AnalysisElementaryFileSpdi(std::string data);
    void ProcessSmses(std::string messages);
    void ProcessSms(std::string data);

    void ProcessSpnGeneral(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessSpnCphs(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessSpnShortCphs(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetAdDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessVoiceMailCphs(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetMwisDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetMbdnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetMbiDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetCfisDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetCffDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainIMSIDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetIccIdDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetPlmnActDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetOplmnActDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSpdiDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetMsisdnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSetMsisdnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainGid1Done(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainGid2Done(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSmsOnSim(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetCspCphs(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetInfoCphs(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSstDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetSmsDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetAllSmsDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetHplmActDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetEhplmnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetPnnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSetCphsMaibox(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetFplmnDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSetMbdn(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessMarkSms(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainSpnPhase(const AppExecFwk::InnerEvent::Pointer &event);
    void StartObtainSpn();

    void CheckMncLength();
    bool IsContinueGetSpn(bool start, SpnStatus curStatus, SpnStatus &newStatus);
    const int MCC_LEN = 3;
    const int MNC_LEN = 2;
    const int MCCMNC_LEN = 6;
    const int LOAD_STEP = 1;
    const int SPN_COND = 2;
    const uint8_t BYTE_NUM = 0xff;
    class ElementaryFilePlLoaded : public IccFileLoaded {
    public:
        ElementaryFilePlLoaded(std::shared_ptr<SimFile> file) : file_(file) {}
        std::string ObtainElementaryFileName();
        void ProcessFileLoaded(std::string &result);
        virtual ~ElementaryFilePlLoaded() {}

    private:
        std::shared_ptr<SimFile> file_ = nullptr;
    };

    class ElementaryFileUsimLiLoaded : public IccFileLoaded {
    public:
        ElementaryFileUsimLiLoaded(std::shared_ptr<SimFile> file) : file_(file) {}
        std::string ObtainElementaryFileName();
        void ProcessFileLoaded(std::string &result);
        virtual ~ElementaryFileUsimLiLoaded() {}

    private:
        std::shared_ptr<SimFile> file_ = nullptr;
    };
};
} // namespace SIM
} // namespace OHOS

#endif // OHOS_SIM_FILE_H