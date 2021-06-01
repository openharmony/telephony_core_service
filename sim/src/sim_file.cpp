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
#include "sim_file.h"
using namespace std;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace SIM {
SimFile::SimFile(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<ISimStateManager> simStateManager)
    : IccFile(runner, simStateManager)
{
    fileQueried_ = false;
    InitMemberFunc();
}

void SimFile::Init()
{
    TELEPHONY_INFO_LOG("SimFile:::Init():start");
    std::shared_ptr<AppExecFwk::EventHandler> pthis = shared_from_this();
    if (stateManager_ != nullptr) {
        stateManager_->RegisterForReady(pthis);
    }
}

void SimFile::StartLoad()
{
    TELEPHONY_INFO_LOG("SimFile::StartLoad() start");
    LoadSimFiles();
}

std::string SimFile::ObtainSimOperator()
{
    std::string imsi = ObtainIMSI();
    if (imsi.empty()) {
        TELEPHONY_ERR_LOG("SimFile ObtainSimOperator: IMSI is null");
        return "";
    }
    if ((lengthOfMnc_ == UNINITIALIZED_MNC) || (lengthOfMnc_ == UNKNOWN_MNC)) {
        TELEPHONY_ERR_LOG("SimFile ObtainSimOperator:  mncLength invalid");
        return "";
    }

    int len = MCC_LEN + lengthOfMnc_;
    int imsilen = imsi.size();
    return ((imsilen >= len) ? imsi.substr(0, MCC_LEN + lengthOfMnc_) : "");
}

std::string SimFile::ObtainIsoCountryCode()
{
    std::string imsi = ObtainSimOperator();
    if (imsi.empty()) {
        TELEPHONY_ERR_LOG("SimFile ObtainIsoCountryCode: IMSI == null");
        return "";
    }
    int len = imsi.length();
    if (len >= MCC_LEN) {
        std::string mnc = imsi.substr(0, MCC_LEN);
        std::string iso = MccPool::MccCountryCode(std::stoi(mnc));
        return iso;
    } else {
        return "";
    }
}

int SimFile::ObtainCallForwardStatus()
{
    return callFowardStatus_;
}

void SimFile::UpdateMsisdnNumber(std::string alphaTag, std::string number, EventPointer &onComplete) {}

void SimFile::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto id = event->GetInnerEventId();
    bool isFileHandleResponse = false;
    TELEPHONY_INFO_LOG("SimFile::ProcessEvent id %{public}d", id);
    auto itFunc = memberFuncMap_.find(id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            isFileHandleResponse = (this->*memberFunc)(event);
        }
    } else {
        IccFile::ProcessEvent(event);
    }
    ProcessFileLoaded(isFileHandleResponse);
}

void SimFile::ProcessIccRefresh(int msgId)
{
    switch (msgId) {
        case ELEMENTARY_FILE_MBDN:
            fileToGet_++;
            break;
        case ELEMENTARY_FILE_MAILBOX_CPHS:
            fileToGet_++;
            break;
        case ELEMENTARY_FILE_CSP_CPHS:
            fileToGet_++;
            break;
        case ELEMENTARY_FILE_FDN:
            break;
        case ELEMENTARY_FILE_MSISDN:
            fileToGet_++;
            break;
        case ELEMENTARY_FILE_CFIS:
        case ELEMENTARY_FILE_CFF_CPHS:
            break;
        default:
            LoadSimFiles();
            break;
    }
}

void SimFile::ProcessFileLoaded(bool response)
{
    if (!response) {
        return;
    }
    fileToGet_ -= LOAD_STEP;
    TELEPHONY_INFO_LOG("SimFile ProcessFileLoaded: %{public}d requested: %{public}d", fileToGet_, fileQueried_);
    if (ObtainFilesFetched()) {
        OnAllFilesFetched();
    } else if (LockQueriedOrNot()) {
        UpdateSimLanguage();
    } else if (fileToGet_ < 0) {
        fileToGet_ = 0;
    }
}

void SimFile::OnAllFilesFetched()
{
    UpdateSimLanguage();
    UpdateLoaded(true);
    filesFetchedObser_->NotifyObserver(ObserverHandler::RADIO_SIM_RECORDS_LOADED);
    PublishSimFileEvent(SIM_STATE_ACTION, ICC_STATE_LOADED, "");
}

bool SimFile::ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_INFO_LOG("SimFile::SIM_STATE_READY --received");
    LoadSimFiles();
    return false;
}

bool SimFile::ProcessIccLocked(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_INFO_LOG(
        "only fetch ELEMENTARY_FILE_LI, ELEMENTARY_FILE_PL and ELEMENTARY_FILE_ICCID in locked state");
    lockQueried_ = true;
    LoadElementaryFileLiAndPI();
    AppExecFwk::InnerEvent::Pointer eventICCID = CreatePointer(MSG_SIM_OBTAIN_ICCID_DONE);
    fileController_->GetTransparentFile(ELEMENTARY_FILE_ICCID, eventICCID);
    fileToGet_++;
    return false;
}

void SimFile::ObtainCallForwardFiles()
{
    fileQueried_ = true;

    AppExecFwk::InnerEvent::Pointer eventCFIS = CreatePointer(MSG_SIM_OBTAIN_CFIS_DONE);
    fileController_->GetFixedLinearFile(ELEMENTARY_FILE_CFIS, 1, eventCFIS);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventCFF = CreatePointer(MSG_SIM_OBTAIN_CFF_DONE);
    fileController_->GetTransparentFile(ELEMENTARY_FILE_CFF_CPHS, eventCFF);
    fileToGet_++;
}

void SimFile::LoadSimFiles()
{
    TELEPHONY_INFO_LOG("SimFile LoadSimFiles started");
    fileQueried_ = true;

    AppExecFwk::InnerEvent::Pointer eventIMSI = CreatePointer(MSG_SIM_OBTAIN_IMSI_DONE);
    rilManager_->GetImsi("sim", eventIMSI);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventICCID = CreatePointer(MSG_SIM_OBTAIN_ICCID_DONE);
    fileController_->GetTransparentFile(ELEMENTARY_FILE_ICCID, eventICCID);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventSpn = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    ObtainSpnPhase(true, eventSpn);
}

void SimFile::LoadElementaryFileLiAndPI()
{
    std::shared_ptr<SimFile> psim = std::shared_ptr<SimFile>(this);

    std::shared_ptr<ElementaryFileUsimLiLoaded> pli = std::make_shared<ElementaryFileUsimLiLoaded>(psim);
    if (pli == nullptr) {
        TELEPHONY_ERR_LOG("SimFile::LoadElementaryFileLiAndPI ElementaryFileUsimLiLoaded create nullptr.");
        return;
    }
    std::shared_ptr<void> pefusim = static_cast<std::shared_ptr<void>>(pli);
    AppExecFwk::InnerEvent::Pointer eventLI = CreatePointer(MSG_SIM_OBTAIN_ICC_FILE_DONE, pefusim);
    fileController_->GetTransparentFile(ELEMENTARY_FILE_LI, eventLI);
    fileToGet_++;

    std::shared_ptr<ElementaryFilePlLoaded> pEfPl = std::make_shared<ElementaryFilePlLoaded>(psim);
    if (pEfPl == nullptr) {
        TELEPHONY_ERR_LOG("SimFile::LoadElementaryFileLiAndPI ElementaryFilePlLoaded create nullptr.");
        return;
    }
    std::shared_ptr<void> pPL = static_cast<std::shared_ptr<void>>(pEfPl);
    AppExecFwk::InnerEvent::Pointer eventPL = CreatePointer(MSG_SIM_OBTAIN_ICC_FILE_DONE, pPL);
    fileController_->GetTransparentFile(ELEMENTARY_FILE_PL, eventPL);
    fileToGet_++;
}

void SimFile::ObtainSpnPhase(bool start, const AppExecFwk::InnerEvent::Pointer &event)
{
    SpnStatus curStatu = spnStatus_;
    if (!IsContinueGetSpn(start, curStatu, spnStatus_)) {
        return;
    }

    TELEPHONY_INFO_LOG("SimFile::ObtainSpnPhase state is %{public}d", spnStatus_);
    if (spnStatus_ == OBTAIN_SPN_START) {
        StartObtainSpn();
    } else if (spnStatus_ == OBTAIN_SPN_GENERAL) {
        ProcessSpnGeneral(event);
    } else if (spnStatus_ == OBTAIN_OPERATOR_NAMESTRING) {
        ProcessSpnCphs(event);
    } else if (spnStatus_ == OBTAIN_OPERATOR_NAME_SHORTFORM) {
        ProcessSpnShortCphs(event);
    } else {
        spnStatus_ = SpnStatus::OBTAIN_SPN_NONE;
    }
}
void SimFile::StartObtainSpn()
{
    UpdateSPN(NULLSTR);
    AppExecFwk::InnerEvent::Pointer eventSPN = CreatePointer(MSG_SIM_OBTAIN_SPN_DONE);
    fileController_->GetTransparentFile(ELEMENTARY_FILE_SPN, eventSPN);
    fileToGet_++;
    spnStatus_ = SpnStatus::OBTAIN_SPN_GENERAL;
}

void SimFile::ProcessSpnGeneral(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    unsigned char *ucdata = nullptr;
    if (ar != nullptr) {
        std::string data = ar->resultData;
        char *pdata = const_cast<char *>(data.c_str());
        ucdata = reinterpret_cast<unsigned char *>(pdata);
        UpdateSPN(data);
        std::string spn = ObtainSPN();
        if (spn.empty() || spn.size() == 0) {
            spnStatus_ = SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM;
        } else {
            displayConditionOfSpn_ = SPN_COND;
            TELEPHONY_INFO_LOG("SimFile Load Spn3Gpp done: %{public}s", spn.c_str());
            spnStatus_ = SpnStatus::OBTAIN_SPN_NONE;
        }
    } else {
        spnStatus_ = SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM;
    }

    if (spnStatus_ == SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM) {
        AppExecFwk::InnerEvent::Pointer eventSHORTCPHS = CreatePointer(MSG_SIM_OBTAIN_SPN_DONE);
        fileController_->GetTransparentFile(ELEMENTARY_FILE_SPN_SHORT_CPHS, eventSHORTCPHS);
        fileToGet_++;
    }
}

void SimFile::ProcessSpnCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    unsigned char *ucdata = nullptr;
    if (ar != nullptr) {
        std::string data = ar->resultData;
        char *pdata = const_cast<char *>(data.c_str());
        ucdata = reinterpret_cast<unsigned char *>(pdata);
        UpdateSPN(data);
        std::string spn = ObtainSPN();
        if (spn.empty() || spn.size() == 0) {
            spnStatus_ = SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM;
        } else {
            displayConditionOfSpn_ = SPN_COND;
            TELEPHONY_INFO_LOG("SimFile Load ELEMENTARY_FILE_SPN_CPHS done: %{public}s", spn.c_str());
            spnStatus_ = SpnStatus::OBTAIN_SPN_NONE;
        }
    } else {
        spnStatus_ = SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM;
    }

    if (spnStatus_ == SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM) {
        AppExecFwk::InnerEvent::Pointer eventSHORTCPHS = CreatePointer(MSG_SIM_OBTAIN_SPN_DONE);
        fileController_->GetTransparentFile(ELEMENTARY_FILE_SPN_SHORT_CPHS, eventSHORTCPHS);
        fileToGet_++;
    }
}

void SimFile::ProcessSpnShortCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    unsigned char *ucdata = nullptr;
    if (ar != nullptr) {
        std::string data = ar->resultData;
        char *pdata = const_cast<char *>(data.c_str());
        ucdata = reinterpret_cast<unsigned char *>(pdata);
        UpdateSPN(data);
        std::string spn = ObtainSPN();
        if (spn.empty() || spn.size() == 0) {
            TELEPHONY_INFO_LOG("SimFile No SPN loaded");
        } else {
            displayConditionOfSpn_ = SPN_COND;
            TELEPHONY_INFO_LOG("SimFile Load ELEMENTARY_FILE_SPN_SHORT_CPHS: %{public}s", spn.c_str());
        }
    } else {
        UpdateSPN(NULLSTR);
        TELEPHONY_INFO_LOG("SimFile No SPN get in either CHPS or 3GPP");
    }
    spnStatus_ = SpnStatus::OBTAIN_SPN_NONE;
}

std::shared_ptr<UsimFunctionHandle> SimFile::ObtainUsimFunctionHandle()
{
    return UsimFunctionHandle_;
}

void SimFile::UpdateSimLanguage() {}

std::string SimFile::AnalysisBcdPlmn(std::string data, std::string description)
{
    return "";
}

void SimFile::ProcessElementaryFileCsp(std::string data) {}

void SimFile::AnalysisElementaryFileSpdi(std::string data) {}

void SimFile::ProcessSmses(std::string messages) {}

void SimFile::ProcessSms(std::string data) {}

bool SimFile::ProcessObtainGid1Done(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr) {
        TELEPHONY_ERR_LOG("SimFile faild in get GID1 ");
        gid1_ = "";
        return isFileHandleResponse;
    }

    gid1_ = SIMUtils::BytesConvertToHexString(data);
    TELEPHONY_INFO_LOG("SimFile GID1: %{public}s", chardata);
    return isFileHandleResponse;
}

bool SimFile::ProcessObtainGid2Done(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr) {
        TELEPHONY_ERR_LOG("SimFile faild in get GID2 ");
        gid2_ = "";
        return isFileHandleResponse;
    }

    gid2_ = SIMUtils::BytesConvertToHexString(data);
    TELEPHONY_INFO_LOG("SimFile GID2: %{public}s", chardata);
    return isFileHandleResponse;
}

bool SimFile::ProcessGetMsisdnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    if (ar->exception != nullptr) {
        TELEPHONY_ERR_LOG("SimFile Invalid or missing EF[MSISDN]");
        return isFileHandleResponse;
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessSetMsisdnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = false;
    if (ar->exception == nullptr) {
        msisdn_ = lastMsisdn_;
        msisdnTag_ = lastMsisdnTag_;
        TELEPHONY_INFO_LOG("SimFile Success to update EF[MSISDN]");
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessGetSpdiDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr) {
        return isFileHandleResponse;
    }
    TELEPHONY_INFO_LOG("SimFile MSG_SIM_OBTAIN_SPDI_DONE data:%{public}s", chardata);
    AnalysisElementaryFileSpdi(data);
    return isFileHandleResponse;
}

bool SimFile::ProcessGetCfisDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr) {
        efCfis_ = nullptr;
    } else {
        TELEPHONY_INFO_LOG("ELEMENTARY_FILE_CFIS: %{public}s", SIMUtils::BytesConvertToHexString(data).c_str());
        efCfis_ = chardata;
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessGetMbiDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    bool isValidMbdn = false;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    isValidMbdn = false;
    if (ar->exception == nullptr) {
        TELEPHONY_INFO_LOG("ELEMENTARY_FILE_MBI: %{public}s", pdata);
        indexOfMailbox_ = chardata[0] & BYTE_NUM;
        if (indexOfMailbox_ != 0 && indexOfMailbox_ != BYTE_NUM) {
            TELEPHONY_INFO_LOG("fetch valid mailbox number for MBDN");
            isValidMbdn = true;
        }
    }
    fileToGet_ += LOAD_STEP;
    return isFileHandleResponse;
}

bool SimFile::ProcessGetMbdnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    auto eventId = event->GetInnerEventId();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    voiceMailNum_ = NULLSTR;
    voiceMailTag_ = NULLSTR;
    if (ar->exception != nullptr) {
        bool cphs = eventId == MSG_SIM_OBTAIN_CPHS_MAILBOX_DONE;
        TELEPHONY_ERR_LOG("SimFile failed missing EF %{public}s", (cphs ? "[MAILBOX]" : "[MBDN]"));
        if (eventId == MSG_SIM_OBTAIN_MBDN_DONE) {
            fileToGet_ += LOAD_STEP;
        }
        return isFileHandleResponse;
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessGetMwisDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);
    TELEPHONY_INFO_LOG("SimFile ELEMENTARY_FILE_MWIS : %{public}s", pdata);
    if (ar->exception != nullptr) {
        TELEPHONY_ERR_LOG("MSG_SIM_OBTAIN_MWIS_DONE exception = ");
        return isFileHandleResponse;
    }

    if ((chardata[0] & 0xff) == 0xff) {
        TELEPHONY_INFO_LOG("SimFiles: Uninitialized record MWIS");
        return isFileHandleResponse;
    }
    efMWIS_ = chardata;
    return isFileHandleResponse;
}

bool SimFile::ProcessVoiceMailCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);
    TELEPHONY_INFO_LOG("SimFile ELEMENTARY_FILE_CPHS_MWI: %{public}s", pdata);
    if (ar->exception != nullptr) {
        TELEPHONY_ERR_LOG("MSG_SIM_OBTAIN_VOICE_MAIL_INDICATOR_CPHS_DONE exception = ");
        return isFileHandleResponse;
    }
    efCphsMwi_ = chardata;
    return isFileHandleResponse;
}

bool SimFile::ProcessGetIccIdDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    TELEPHONY_INFO_LOG("sim record SimFile::ProcessEvent -MSG_SIM_OBTAIN_ICCID_DONE");
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);
    TELEPHONY_INFO_LOG("SimFile::ProcessEvent -MSG_SIM_OBTAIN_ICCID_DONE---%{public}s", chardata);
    iccId_ = data;
    iccIdComplete_ = data;
    return isFileHandleResponse;
}

bool SimFile::ProcessObtainIMSIDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<std::string> sharedObject = event->GetSharedObject<std::string>();
    imsi_ = *sharedObject;
    bool isFileHandleResponse = true;
    TELEPHONY_INFO_LOG("SimFile::ProcessEvent MSG_SIM_OBTAIN_IMSI_DONE received:%{public}s", imsi_.c_str());
    std::string iso = ObtainIsoCountryCode();
    TELEPHONY_INFO_LOG("SimFile::ObtainIsoCountryCode result is %{public}s", iso.c_str());
    if (!imsi_.empty()) {
        imsiReadyObser_->NotifyObserver(ObserverHandler::RADIO_IMSI_LOADED_READY);
        PublishSimFileEvent(SIM_STATE_ACTION, ICC_STATE_IMSI, imsi_);
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessGetCffDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);
    if (ar->exception != nullptr) {
        efCff_ = nullptr;
    } else {
        TELEPHONY_INFO_LOG("SimFile ELEMENTARY_FILE_CFF_CPHS: %{public}s", pdata);
        efCff_ = chardata;
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessGetAdDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    bool doneData = true;
    if (!ObtainIMSI().empty()) {
        std::string imsi = ObtainIMSI();
        int mcc = atoi(imsi.substr(0, MCC_LEN).c_str());
        lengthOfMnc_ = MccPool::ShortestMncLengthFromMcc(mcc);
        TELEPHONY_INFO_LOG("SimFile [TestMode] lengthOfMnc_= %{public}d", lengthOfMnc_);
    } else {
        char *pdata = const_cast<char *>(data.c_str());
        unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);
        if (ar->exception != nullptr) {
            doneData = false;
        }
        TELEPHONY_INFO_LOG("SimFile ELEMENTARY_FILE_AD: %{public}s", pdata);
        int dataSize = data.size();
        if (dataSize < MCC_LEN) {
            TELEPHONY_INFO_LOG("Corrupt AD data on SIM");
            doneData = false;
        }
        if (dataSize == MCC_LEN) {
            TELEPHONY_INFO_LOG("MNC length not present in ELEMENTARY_FILE_AD");
            doneData = false;
        }
        if (doneData) {
            lengthOfMnc_ = chardata[MCC_LEN] & 0xf;
            TELEPHONY_INFO_LOG("setting4 lengthOfMnc_= %{public}d", lengthOfMnc_);
        }
    }

    if (doneData && (lengthOfMnc_ == 0xf)) {
        lengthOfMnc_ = UNKNOWN_MNC;
    } else if (doneData && (lengthOfMnc_ != MNC_LEN) && (lengthOfMnc_ != MCC_LEN)) {
        lengthOfMnc_ = UNINITIALIZED_MNC;
    }
    TELEPHONY_INFO_LOG("update5 length Mnc_= %{public}d", lengthOfMnc_);
    CheckMncLength();
    return isFileHandleResponse;
}

void SimFile::CheckMncLength()
{
    std::string imsi = ObtainIMSI();
    int imsiSize = imsi.size();
    if (((lengthOfMnc_ == UNINITIALIZED_MNC) || (lengthOfMnc_ == UNKNOWN_MNC) || (lengthOfMnc_ == MNC_LEN)) &&
        ((!imsi.empty()) && (imsiSize >= MCCMNC_LEN))) {
        std::string mccmncCode = imsi.substr(0, MCCMNC_LEN);
        TELEPHONY_INFO_LOG("SimFile mccmncCode= %{public}s", mccmncCode.c_str());
        if (MccPool::LengthIsThreeMnc(mccmncCode)) {
            lengthOfMnc_ = MCC_LEN;
            TELEPHONY_INFO_LOG("SimFile update6 lengthOfMnc_= %{public}d", lengthOfMnc_);
        }
    }

    if (lengthOfMnc_ == UNKNOWN_MNC || lengthOfMnc_ == UNINITIALIZED_MNC) {
        if (!imsi.empty()) {
            int mcc = atoi(imsi.substr(0, MCC_LEN).c_str());
            lengthOfMnc_ = MccPool::ShortestMncLengthFromMcc(mcc);
            TELEPHONY_INFO_LOG("SimFile update7 lengthOfMnc_= %{public}d", lengthOfMnc_);
        } else {
            lengthOfMnc_ = UNKNOWN_MNC;
            TELEPHONY_INFO_LOG(
                "MNC length not present in ELEMENTARY_FILE_AD setting9 lengthOfMnc_= %{public}d", lengthOfMnc_);
        }
    }
    int lenNum = MCC_LEN + lengthOfMnc_;
    int sz = imsi.size();
    bool cond = sz >= lenNum;
    if ((!imsi.empty()) && (lengthOfMnc_ != UNKNOWN_MNC) && cond) {
    }
}

bool SimFile::ProcessSmsOnSim(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    int index = atoi(data.c_str());
    bool isFileHandleResponse = false;
    if (ar->exception != nullptr || index == INVALID_VALUE) {
        TELEPHONY_ERR_LOG("exception on SMS_ON_SIM with index: %{public}d", index);
    } else {
        TELEPHONY_INFO_LOG("READ ELEMENTARY_FILE_SMS RECORD index= %{public}d", index);
        AppExecFwk::InnerEvent::Pointer eventSMS = CreatePointer(MSG_SIM_OBTAIN_SMS_DONE);
        fileController_->GetFixedLinearFile(ELEMENTARY_FILE_SMS, index, eventSMS);
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessGetAllSmsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    if (ar->exception != nullptr) {
        return isFileHandleResponse;
    }
    ProcessSmses(data);
    return isFileHandleResponse;
}

bool SimFile::ProcessGetSmsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = false;
    if (ar->exception == nullptr) {
        ProcessSms(data);
    } else {
        TELEPHONY_INFO_LOG("SimFile exception on GET_SMS ");
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessGetPlmnActDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr || data.empty()) {
        TELEPHONY_ERR_LOG("Failed fetech User PLMN ");
    } else {
        TELEPHONY_INFO_LOG("fetech a PlmnRAT, data= %{public}s", chardata);
    }
    return isFileHandleResponse;
}

// Process operator plmn
bool SimFile::ProcessGetOplmnActDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr || data.empty()) {
        TELEPHONY_ERR_LOG("Failed fetch Operator PLMN");
    } else {
        TELEPHONY_INFO_LOG("fetch a OPlmnRAT, data= %{public}s", chardata);
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessGetCspCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr) {
        TELEPHONY_ERR_LOG("Exception to get ELEMENTARY_FILE_CSP data ");
        return isFileHandleResponse;
    }
    TELEPHONY_INFO_LOG("SimFile MSG_SIM_OBTAIN_CSP_CPHS_DONE data:%{public}s", chardata);
    TELEPHONY_INFO_LOG("ELEMENTARY_FILE_CSP: %{public}s", SIMUtils::BytesConvertToHexString(data).c_str());
    ProcessElementaryFileCsp(data);
    return isFileHandleResponse;
}

bool SimFile::ProcessGetInfoCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);
    if (ar->exception != nullptr) {
        return isFileHandleResponse;
    }
    cphsInfo_ = chardata;
    TELEPHONY_INFO_LOG("SimFile iCPHS: %{public}s", pdata);
    return isFileHandleResponse;
}

bool SimFile::ProcessGetSstDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr) {
        return isFileHandleResponse;
    }
    TELEPHONY_INFO_LOG("SimFile MSG_SIM_OBTAIN_SST_DONE data:%{public}s", chardata);
    return isFileHandleResponse;
}

bool SimFile::ProcessGetPnnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    if (ar->exception != nullptr) {
        return isFileHandleResponse;
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = false;
    if (ar->exception != nullptr) {
        TELEPHONY_ERR_LOG("SimFile failed to update");
    }
    return isFileHandleResponse;
}

bool SimFile::ProcessSetCphsMaibox(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = false;
    if (ar->exception == nullptr) {
        voiceMailNum_ = lastVoiceMailNum_;
        voiceMailTag_ = lastVoiceMailTag_;
    } else {
        TELEPHONY_INFO_LOG("fail to update CPHS MailBox");
    }
    return isFileHandleResponse;
}

// Process forbidden PLMNs
bool SimFile::ProcessGetHplmActDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    char *pdata = const_cast<char *>(data.c_str());
    unsigned char *chardata = reinterpret_cast<unsigned char *>(pdata);

    if (ar->exception != nullptr || data.empty()) {
        TELEPHONY_ERR_LOG("Failed to fetch forbidden PLMN");
        return isFileHandleResponse;
    } else {
        TELEPHONY_INFO_LOG("fetch a FPlmnRAT, data=%{public}s", chardata);
    }
    return isFileHandleResponse;
}

// Process Equivalent Home PLMNs
bool SimFile::ProcessGetEhplmnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool isFileHandleResponse = true;
    if (ar->exception != nullptr || data.empty()) {
        TELEPHONY_ERR_LOG("Failed fetch Equivalent Home PLMNs");
        return isFileHandleResponse;
    } else {
    }
    return isFileHandleResponse;
}

// Process forbidden PLMNs
bool SimFile::ProcessGetFplmnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<IccFileData> ar = event->GetUniqueObject<IccFileData>();
    std::string data = ar->resultData;
    bool loadResponse = true;
    if (ar->exception != nullptr || data.empty()) {
        TELEPHONY_ERR_LOG("Failed to get forbidden PLMNs");
        return loadResponse;
    } else {
    }
    if (ar->arg1 == ICC_CONTROLLER_REQ_SEND_RESPONSE) {
        TELEPHONY_INFO_LOG("getForbiddenPlmns and send result");
        loadResponse = false;
    }
    return loadResponse;
}

bool SimFile::ProcessSetMbdn(const AppExecFwk::InnerEvent::Pointer &event)
{
    (void)event;
    return false;
}

bool SimFile::ProcessMarkSms(const AppExecFwk::InnerEvent::Pointer &event)
{
    (void)event;
    return false;
}

bool SimFile::ProcessObtainSpnPhase(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool loadResponse = true;
    ObtainSpnPhase(false, event);
    return loadResponse;
}
bool SimFile::IsContinueGetSpn(bool start, SpnStatus curStatus, SpnStatus &newStatus)
{
    if (start) {
        switch (curStatus) {
            case OBTAIN_SPN_GENERAL:
            case OBTAIN_OPERATOR_NAMESTRING:
            case OBTAIN_OPERATOR_NAME_SHORTFORM:
            case OBTAIN_SPN_START:
                newStatus = SpnStatus::OBTAIN_SPN_START;
                return false;
            default:
                newStatus = SpnStatus::OBTAIN_SPN_START;
                return true;
        }
    } else {
        return true;
    }
}
void SimFile::InitMemberFunc()
{
    memberFuncMap_[ObserverHandler::RADIO_SIM_STATE_READY] = &SimFile::ProcessIccReady;
    memberFuncMap_[MSG_SIM_APP_LOCKED] = &SimFile::ProcessIccLocked;
    memberFuncMap_[MSG_SIM_APP_NETWORK_LOCKED] = &SimFile::ProcessIccLocked;
    memberFuncMap_[MSG_SIM_OBTAIN_IMSI_DONE] = &SimFile::ProcessObtainIMSIDone;
    memberFuncMap_[MSG_SIM_OBTAIN_ICCID_DONE] = &SimFile::ProcessGetIccIdDone;
    memberFuncMap_[MSG_SIM_OBTAIN_MBI_DONE] = &SimFile::ProcessGetMbiDone;
    memberFuncMap_[MSG_SIM_OBTAIN_CPHS_MAILBOX_DONE] = &SimFile::ProcessGetMbdnDone;
    memberFuncMap_[MSG_SIM_OBTAIN_MBDN_DONE] = &SimFile::ProcessGetMbdnDone;
    memberFuncMap_[MSG_SIM_OBTAIN_MSISDN_DONE] = &SimFile::ProcessGetMsisdnDone;
    memberFuncMap_[MSG_SIM_SET_MSISDN_DONE] = &SimFile::ProcessSetMsisdnDone;
    memberFuncMap_[MSG_SIM_OBTAIN_MWIS_DONE] = &SimFile::ProcessGetMwisDone;
    memberFuncMap_[MSG_SIM_OBTAIN_VOICE_MAIL_INDICATOR_CPHS_DONE] = &SimFile::ProcessVoiceMailCphs;
    memberFuncMap_[MSG_SIM_OBTAIN_AD_DONE] = &SimFile::ProcessGetAdDone;
    memberFuncMap_[MSG_SIM_OBTAIN_SPN_DONE] = &SimFile::ProcessObtainSpnPhase;
    memberFuncMap_[MSG_SIM_OBTAIN_CFF_DONE] = &SimFile::ProcessGetCffDone;
    memberFuncMap_[MSG_SIM_OBTAIN_SPDI_DONE] = &SimFile::ProcessGetSpdiDone;
    memberFuncMap_[MSG_SIM_UPDATE_DONE] = &SimFile::ProcessUpdateDone;
    memberFuncMap_[MSG_SIM_OBTAIN_PNN_DONE] = &SimFile::ProcessGetPnnDone;
    memberFuncMap_[MSG_SIM_OBTAIN_ALL_SMS_DONE] = &SimFile::ProcessGetAllSmsDone;
    memberFuncMap_[MSG_SIM_MARK_SMS_READ_DONE] = &SimFile::ProcessMarkSms;
    memberFuncMap_[MSG_SIM_SMS_ON_SIM] = &SimFile::ProcessSmsOnSim;
    memberFuncMap_[MSG_SIM_OBTAIN_SMS_DONE] = &SimFile::ProcessGetSmsDone;
    memberFuncMap_[MSG_SIM_OBTAIN_SST_DONE] = &SimFile::ProcessGetSstDone;
    memberFuncMap_[MSG_SIM_OBTAIN_INFO_CPHS_DONE] = &SimFile::ProcessGetInfoCphs;
    memberFuncMap_[MSG_SIM_SET_MBDN_DONE] = &SimFile::ProcessSetMbdn;
    memberFuncMap_[MSG_SIM_SET_CPHS_MAILBOX_DONE] = &SimFile::ProcessSetCphsMaibox;
    memberFuncMap_[MSG_SIM_OBTAIN_CFIS_DONE] = &SimFile::ProcessGetCfisDone;
    memberFuncMap_[MSG_SIM_OBTAIN_CSP_CPHS_DONE] = &SimFile::ProcessGetCspCphs;
    memberFuncMap_[MSG_SIM_OBTAIN_GID1_DONE] = &SimFile::ProcessObtainGid1Done;
    memberFuncMap_[MSG_SIM_OBTAIN_GID2_DONE] = &SimFile::ProcessObtainGid2Done;
    memberFuncMap_[MSG_SIM_OBTAIN_PLMN_W_ACT_DONE] = &SimFile::ProcessGetPlmnActDone;
    memberFuncMap_[MSG_SIM_OBTAIN_OPLMN_W_ACT_DONE] = &SimFile::ProcessGetOplmnActDone;
    memberFuncMap_[MSG_SIM_OBTAIN_HPLMN_W_ACT_DONE] = &SimFile::ProcessGetHplmActDone;
    memberFuncMap_[MSG_SIM_OBTAIN_EHPLMN_DONE] = &SimFile::ProcessGetEhplmnDone;
    memberFuncMap_[MSG_SIM_OBTAIN_FPLMN_DONE] = &SimFile::ProcessGetFplmnDone;
}

SimFile::~SimFile() {}

std::string SimFile::ElementaryFilePlLoaded::ObtainElementaryFileName()
{
    return "ELEMENTARY_FILE_PL";
}

void SimFile::ElementaryFilePlLoaded::ProcessFileLoaded(std::string &result)
{
    file_->efPl_ = result;
    TELEPHONY_INFO_LOG("SimFile ProcessFileLoaded ELEMENTARY_FILE_PL= %{public}s", file_->efPl_.c_str());
}

std::string SimFile::ElementaryFileUsimLiLoaded::ObtainElementaryFileName()
{
    return "ELEMENTARY_FILE_LI";
}

void SimFile::ElementaryFileUsimLiLoaded::ProcessFileLoaded(std::string &result)
{
    file_->efLi_ = result;
    TELEPHONY_INFO_LOG("SimFile ProcessFileLoaded ELEMENTARY_FILE_LI= %{public}s", file_->efLi_.c_str());
}
} // namespace SIM
} // namespace OHOS