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
namespace Telephony {
SimFile::SimFile(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<ISimStateManager> simStateManager)
    : IccFile(runner, simStateManager)
{
    fileQueried_ = false;
    displayConditionOfSpn_ = SPN_INVALID;
    InitMemberFunc();
}

void SimFile::Init()
{
    TELEPHONY_LOGI("SimFile:::Init():start");
    std::shared_ptr<AppExecFwk::EventHandler> pThis = shared_from_this();
    if (stateManager_ != nullptr) {
        stateManager_->RegisterIccReady(pThis);
        stateManager_->RegisterIccLocked(pThis);
        stateManager_->RegisterIccSimLock(pThis);
    }
}

void SimFile::StartLoad()
{
    TELEPHONY_LOGI("SimFile::StartLoad() start");
    LoadSimFiles();
}

std::string SimFile::ObtainSimOperator()
{
    if (operatorNumeric_.empty()) {
        std::string imsi = ObtainIMSI();
        if (imsi.empty()) {
            TELEPHONY_LOGE("SimFile ObtainSimOperator: IMSI is null");
            return "";
        }
        if ((lengthOfMnc_ == UNINITIALIZED_MNC) || (lengthOfMnc_ == UNKNOWN_MNC)) {
            TELEPHONY_LOGE("SimFile ObtainSimOperator:  mncLength invalid");
            return "";
        }
        int length = MCC_LEN + lengthOfMnc_;
        int imsiLen = imsi.size();
        operatorNumeric_ = ((imsiLen >= length) ? imsi.substr(0, MCC_LEN + lengthOfMnc_) : "");
    }
    return operatorNumeric_;
}

std::string SimFile::ObtainIsoCountryCode()
{
    std::string imsi = ObtainSimOperator();
    if (imsi.empty()) {
        TELEPHONY_LOGE("SimFile ObtainIsoCountryCode: IMSI is null");
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
    return callForwardStatus_;
}

void SimFile::UpdateMsisdnNumber(
    const std::string &alphaTag, const std::string &number, const AppExecFwk::InnerEvent::Pointer &onComplete)
{}

void SimFile::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto id = event->GetInnerEventId();
    TELEPHONY_LOGI("SimFile::ProcessEvent id %{public}d", id);
    auto itFunc = memberFuncMap_.find(id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            bool isFileProcessResponse = (this->*memberFunc)(event);
            ProcessFileLoaded(isFileProcessResponse);
        }
    } else {
        IccFile::ProcessEvent(event);
    }
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
    TELEPHONY_LOGI("SimFile ProcessFileLoaded Done: %{public}d requested: %{public}d", fileToGet_, fileQueried_);
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
    TELEPHONY_LOGI("SimFile SimFile::OnAllFilesFetched: start notify");
    filesFetchedObser_->NotifyObserver(ObserverHandler::RADIO_SIM_RECORDS_LOADED);
    PublishSimFileEvent(SIM_STATE_ACTION, ICC_STATE_LOADED, "");
}

bool SimFile::ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("SimFile::SIM_STATE_READY received");
    LoadSimFiles();
    return false;
}

bool SimFile::ProcessIccLocked(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("only fetch ELEMENTARY_FILE_LI, ELEMENTARY_FILE_PL and ELEMENTARY_FILE_ICCID in locked state");
    lockQueried_ = true;
    LoadSimLanguageFile();
    AppExecFwk::InnerEvent::Pointer eventIccId = CreatePointer(MSG_SIM_OBTAIN_ICCID_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_ICCID, eventIccId);
    fileToGet_++;
    return false;
}

void SimFile::ObtainCallForwardFiles()
{
    fileQueried_ = true;

    AppExecFwk::InnerEvent::Pointer eventCFIS = CreatePointer(MSG_SIM_OBTAIN_CFIS_DONE);
    fileController_->ObtainLinearFixedFile(ELEMENTARY_FILE_CFIS, 1, eventCFIS);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventCFF = CreatePointer(MSG_SIM_OBTAIN_CFF_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_CFF_CPHS, eventCFF);
    fileToGet_++;
}

void SimFile::LoadSimFiles()
{
    TELEPHONY_LOGI("SimFile LoadSimFiles started");
    fileQueried_ = true;

    AppExecFwk::InnerEvent::Pointer eventIMSI = CreatePointer(MSG_SIM_OBTAIN_IMSI_DONE);
    rilManager_->GetImsi(eventIMSI);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventIccId = CreatePointer(MSG_SIM_OBTAIN_ICCID_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_ICCID, eventIccId);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventSpn = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    ObtainSpnPhase(true, eventSpn);

    AppExecFwk::InnerEvent::Pointer eventGid1 = CreatePointer(MSG_SIM_OBTAIN_GID1_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_GID1, eventGid1);
    fileToGet_++;

    LoadSimLanguageFile();
}
void SimFile::LoadSimLanguageFile()
{
    LoadElementaryFileLi();
    LoadElementaryFilePl();
}

void SimFile::LoadElementaryFileLi()
{
    std::shared_ptr<SimFile> owner = std::static_pointer_cast<SimFile>(shared_from_this());
    std::shared_ptr<ElementaryFileUsimLiLoaded> liFile = std::make_shared<ElementaryFileUsimLiLoaded>(owner);
    if (liFile == nullptr) {
        TELEPHONY_LOGE("SimFile::LoadSimLanguageFile ElementaryFileUsimLiLoaded create nullptr.");
        return;
    }
    std::shared_ptr<void> liBase = static_cast<std::shared_ptr<void>>(liFile);
    AppExecFwk::InnerEvent::Pointer eventLi = CreatePointer(MSG_SIM_OBTAIN_ICC_FILE_DONE, liBase);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_LI, eventLi);
    fileToGet_++;
}

void SimFile::LoadElementaryFilePl()
{
    std::shared_ptr<SimFile> owner = std::static_pointer_cast<SimFile>(shared_from_this());
    std::shared_ptr<ElementaryFilePlLoaded> plFile = std::make_shared<ElementaryFilePlLoaded>(owner);
    if (plFile == nullptr) {
        TELEPHONY_LOGE("SimFile::LoadSimLanguageFile ElementaryFilePlLoaded create nullptr.");
        return;
    }
    std::shared_ptr<void> plBase = static_cast<std::shared_ptr<void>>(plFile);
    AppExecFwk::InnerEvent::Pointer eventPl = CreatePointer(MSG_SIM_OBTAIN_ICC_FILE_DONE, plBase);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_PL, eventPl);
    fileToGet_++;
}

void SimFile::ObtainSpnPhase(bool start, const AppExecFwk::InnerEvent::Pointer &event)
{
    SpnStatus curStatus = spnStatus_;
    if (!IsContinueGetSpn(start, curStatus, spnStatus_)) {
        return;
    }

    TELEPHONY_LOGI("SimFile::ObtainSpnPhase state is %{public}d", spnStatus_);
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
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_SPN, eventSPN);
    fileToGet_++;
    spnStatus_ = SpnStatus::OBTAIN_SPN_GENERAL;
}

void SimFile::ProcessSpnGeneral(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    if (fd != nullptr && fd->exception == nullptr) {
        std::string iccData = fd->resultData;
        int length = 0;
        std::shared_ptr<unsigned char> hexData = SIMUtils::HexStringConvertToBytes(iccData, length);
        if (hexData != nullptr) {
            unsigned char *byteData = hexData.get();
            unsigned char value = byteData[0];
            displayConditionOfSpn_ = (BYTE_NUMBER & value);
        }
        UpdateSPN(iccData);
        std::string spn = ObtainSPN();
        if (spn.empty() || spn.size() == 0) {
            spnStatus_ = SpnStatus::OBTAIN_OPERATOR_NAMESTRING;
        } else {
            TELEPHONY_LOGI("SimFile Load Spn3Gpp done: %{public}s", spn.c_str());
            spnStatus_ = SpnStatus::OBTAIN_SPN_NONE;
        }
    } else {
        spnStatus_ = SpnStatus::OBTAIN_OPERATOR_NAMESTRING;
    }

    if (spnStatus_ == SpnStatus::OBTAIN_OPERATOR_NAMESTRING) {
        AppExecFwk::InnerEvent::Pointer eventCphs = CreatePointer(MSG_SIM_OBTAIN_SPN_DONE);
        fileController_->ObtainBinaryFile(ELEMENTARY_FILE_SPN_CPHS, eventCphs);
        fileToGet_++;
        displayConditionOfSpn_ = SPN_INVALID;
    }
}

void SimFile::ProcessSpnCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    if (fd != nullptr && fd->exception == nullptr) {
        std::string iccData = fd->resultData;
        UpdateSPN(iccData);
        std::string spn = ObtainSPN();
        if (spn.empty() || spn.size() == 0) {
            spnStatus_ = SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM;
        } else {
            displayConditionOfSpn_ = SPN_COND;
            TELEPHONY_LOGI("SimFile Load ELEMENTARY_FILE_SPN_CPHS done: %{public}s", spn.c_str());
            spnStatus_ = SpnStatus::OBTAIN_SPN_NONE;
        }
    } else {
        spnStatus_ = SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM;
    }

    if (spnStatus_ == SpnStatus::OBTAIN_OPERATOR_NAME_SHORTFORM) {
        AppExecFwk::InnerEvent::Pointer eventShortCphs = CreatePointer(MSG_SIM_OBTAIN_SPN_DONE);
        fileController_->ObtainBinaryFile(ELEMENTARY_FILE_SPN_SHORT_CPHS, eventShortCphs);
        fileToGet_++;
    }
}

void SimFile::ProcessSpnShortCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    if (fd != nullptr && fd->exception == nullptr) {
        std::string iccData = fd->resultData;
        UpdateSPN(iccData);
        std::string spn = ObtainSPN();
        if (spn.empty() || spn.size() == 0) {
            TELEPHONY_LOGI("SimFile No SPN loaded");
        } else {
            displayConditionOfSpn_ = SPN_COND;
            TELEPHONY_LOGI("SimFile Load ELEMENTARY_FILE_SPN_SHORT_CPHS: %{public}s", spn.c_str());
        }
    } else {
        UpdateSPN(NULLSTR);
        TELEPHONY_LOGI("SimFile No SPN get in either CHPS or 3GPP");
    }
    spnStatus_ = SpnStatus::OBTAIN_SPN_NONE;
}

std::shared_ptr<UsimFunctionHandle> SimFile::ObtainUsimFunctionHandle()
{
    return UsimFunctionHandle_;
}

void SimFile::UpdateSimLanguage()
{
    UpdateIccLanguage(efLi_, efPl_);
}

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
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("SimFile failed in get GID1 ");
        gid1_ = "";
        return isFileProcessResponse;
    }

    gid1_ = iccData;
    TELEPHONY_LOGI("SimFile GID1: %{public}s", fileData);
    return isFileProcessResponse;
}

bool SimFile::ProcessObtainGid2Done(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("SimFile failed in get GID2 ");
        gid2_ = "";
        return isFileProcessResponse;
    }

    gid2_ = iccData;
    TELEPHONY_LOGI("SimFile GID2: %{public}s", fileData);
    return isFileProcessResponse;
}

bool SimFile::ProcessGetMsisdnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("SimFile Invalid or missing EF[MSISDN]");
        return isFileProcessResponse;
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessSetMsisdnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = false;
    if (fd->exception == nullptr) {
        msisdn_ = lastMsisdn_;
        msisdnTag_ = lastMsisdnTag_;
        TELEPHONY_LOGI("SimFile Success to update EF[MSISDN]");
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessGetSpdiDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr) {
        return isFileProcessResponse;
    }
    TELEPHONY_LOGI("SimFile MSG_SIM_OBTAIN_SPDI_DONE data:%{public}s", fileData);
    AnalysisElementaryFileSpdi(iccData);
    return isFileProcessResponse;
}

bool SimFile::ProcessGetCfisDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr) {
        efCfis_ = nullptr;
    } else {
        TELEPHONY_LOGI("ELEMENTARY_FILE_CFIS: %{public}s", fileData);
        efCfis_ = fileData;
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessGetMbiDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    bool isValidMbdn = false;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    isValidMbdn = false;
    if (fd->exception == nullptr) {
        TELEPHONY_LOGI("ELEMENTARY_FILE_MBI: %{public}s", rawData);
        indexOfMailbox_ = fileData[0] & BYTE_NUM;
        if (indexOfMailbox_ != 0 && indexOfMailbox_ != BYTE_NUM) {
            TELEPHONY_LOGI("fetch valid mailbox number for MBDN");
            isValidMbdn = true;
        }
    }
    fileToGet_ += LOAD_STEP;
    return isFileProcessResponse;
}

bool SimFile::ProcessGetMbdnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    auto eventId = event->GetInnerEventId();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    voiceMailNum_ = NULLSTR;
    voiceMailTag_ = NULLSTR;
    if (fd->exception != nullptr) {
        bool cphs = (eventId == MSG_SIM_OBTAIN_CPHS_MAILBOX_DONE);
        TELEPHONY_LOGE("SimFile failed missing EF %{public}s", (cphs ? "[MAILBOX]" : "[MBDN]"));
        if (eventId == MSG_SIM_OBTAIN_MBDN_DONE) {
            fileToGet_ += LOAD_STEP;
        }
        return isFileProcessResponse;
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessGetMwisDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);
    TELEPHONY_LOGI("SimFile ELEMENTARY_FILE_MWIS : %{public}s", rawData);
    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("MSG_SIM_OBTAIN_MWIS_DONE exception = ");
        return isFileProcessResponse;
    }
    unsigned char value = fileData[0];
    if ((value & BYTE_NUMBER) == BYTE_NUMBER) {
        TELEPHONY_LOGI("SimFiles: Uninitialized record MWIS");
        return isFileProcessResponse;
    }
    efMWIS_ = fileData;
    return isFileProcessResponse;
}

bool SimFile::ProcessVoiceMailCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);
    TELEPHONY_LOGI("SimFile ELEMENTARY_FILE_CPHS_MWI: %{public}s", rawData);
    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("MSG_SIM_OBTAIN_VOICE_MAIL_INDICATOR_CPHS_DONE exception = ");
        return isFileProcessResponse;
    }
    efCphsMwi_ = fileData;
    return isFileProcessResponse;
}

bool SimFile::ProcessGetIccIdDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    bool isFileProcessResponse = true;
    if (fd->exception == nullptr) {
        std::string iccData = fd->resultData;
        TELEPHONY_LOGI("SimFile::ProcessEvent MSG_SIM_OBTAIN_ICCID_DONE result success");
        iccId_ = iccData;
        iccIdComplete_ = iccData;
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessObtainIMSIDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<std::string> sharedObject = event->GetSharedObject<std::string>();
    bool isFileProcessResponse = true;
    if (sharedObject != nullptr) {
        imsi_ = *sharedObject;
        TELEPHONY_LOGI("SimFile::ProcessEvent MSG_SIM_OBTAIN_IMSI_DONE received success");
        std::string iso = ObtainIsoCountryCode();
        TELEPHONY_LOGI("SimFile::ObtainIsoCountryCode result success");
        if (!imsi_.empty()) {
            imsiReadyObser_->NotifyObserver(ObserverHandler::RADIO_IMSI_LOADED_READY);
            PublishSimFileEvent(SIM_STATE_ACTION, ICC_STATE_IMSI, imsi_);
        }
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessGetCffDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);
    if (fd->exception != nullptr) {
        efCff_ = nullptr;
    } else {
        TELEPHONY_LOGI("SimFile ELEMENTARY_FILE_CFF_CPHS: %{public}s", rawData);
        efCff_ = fileData;
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessGetAdDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    bool doneData = true;
    if (!ObtainIMSI().empty()) {
        std::string imsi = ObtainIMSI();
        int mcc = atoi(imsi.substr(0, MCC_LEN).c_str());
        lengthOfMnc_ = MccPool::ShortestMncLengthFromMcc(mcc);
        TELEPHONY_LOGI("SimFile [TestMode] lengthOfMnc_= %{public}d", lengthOfMnc_);
    } else {
        char *rawData = const_cast<char *>(iccData.c_str());
        unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);
        if (fd->exception != nullptr) {
            doneData = false;
        }
        TELEPHONY_LOGI("SimFile ELEMENTARY_FILE_AD: %{public}s", rawData);
        int dataSize = iccData.size();
        if (dataSize < MCC_LEN) {
            TELEPHONY_LOGI("Corrupt AD data on SIM");
            doneData = false;
        }
        if (dataSize == MCC_LEN) {
            TELEPHONY_LOGI("MNC length not present in ELEMENTARY_FILE_AD");
            doneData = false;
        }
        if (doneData) {
            lengthOfMnc_ = fileData[MCC_LEN] & 0xf;
            TELEPHONY_LOGI("setting4 lengthOfMnc_= %{public}d", lengthOfMnc_);
        }
    }

    if (doneData && (lengthOfMnc_ == 0xf)) {
        lengthOfMnc_ = UNKNOWN_MNC;
    } else if (doneData && (lengthOfMnc_ != MNC_LEN) && (lengthOfMnc_ != MCC_LEN)) {
        lengthOfMnc_ = UNINITIALIZED_MNC;
    }
    TELEPHONY_LOGI("update5 length Mnc_= %{public}d", lengthOfMnc_);
    CheckMncLength();
    return isFileProcessResponse;
}

void SimFile::CheckMncLength()
{
    std::string imsi = ObtainIMSI();
    int imsiSize = imsi.size();
    if (((lengthOfMnc_ == UNINITIALIZED_MNC) || (lengthOfMnc_ == UNKNOWN_MNC) || (lengthOfMnc_ == MNC_LEN)) &&
        ((!imsi.empty()) && (imsiSize >= MCCMNC_LEN))) {
        std::string mccMncCode = imsi.substr(0, MCCMNC_LEN);
        TELEPHONY_LOGI("SimFile mccMncCode= %{public}s", mccMncCode.c_str());
        if (MccPool::LengthIsThreeMnc(mccMncCode)) {
            lengthOfMnc_ = MCC_LEN;
            TELEPHONY_LOGI("SimFile update6 lengthOfMnc_= %{public}d", lengthOfMnc_);
        }
    }

    if (lengthOfMnc_ == UNKNOWN_MNC || lengthOfMnc_ == UNINITIALIZED_MNC) {
        if (!imsi.empty()) {
            int mcc = atoi(imsi.substr(0, MCC_LEN).c_str());
            lengthOfMnc_ = MccPool::ShortestMncLengthFromMcc(mcc);
            TELEPHONY_LOGI("SimFile update7 lengthOfMnc_= %{public}d", lengthOfMnc_);
        } else {
            lengthOfMnc_ = UNKNOWN_MNC;
            TELEPHONY_LOGI(
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
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    int index = atoi(iccData.c_str());
    bool isFileProcessResponse = false;
    if (fd->exception != nullptr || index == INVALID_VALUE) {
        TELEPHONY_LOGE("exception on SMS_ON_SIM with index: %{public}d", index);
    } else {
        TELEPHONY_LOGI("READ ELEMENTARY_FILE_SMS RECORD index= %{public}d", index);
        AppExecFwk::InnerEvent::Pointer eventSMS = CreatePointer(MSG_SIM_OBTAIN_SMS_DONE);
        fileController_->ObtainLinearFixedFile(ELEMENTARY_FILE_SMS, index, eventSMS);
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessGetAllSmsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    if (fd->exception != nullptr) {
        return isFileProcessResponse;
    }
    ProcessSmses(iccData);
    return isFileProcessResponse;
}

bool SimFile::ProcessGetSmsDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = false;
    if (fd->exception == nullptr) {
        ProcessSms(iccData);
    } else {
        TELEPHONY_LOGI("SimFile exception on GET_SMS ");
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessGetPlmnActDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr || iccData.empty()) {
        TELEPHONY_LOGE("Failed fetch User PLMN ");
    } else {
        TELEPHONY_LOGI("fetch a PlmnRAT, iccData= %{public}s", fileData);
    }
    return isFileProcessResponse;
}

// Process operator plmn
bool SimFile::ProcessGetOplmnActDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr || iccData.empty()) {
        TELEPHONY_LOGE("Failed fetch Operator PLMN");
    } else {
        TELEPHONY_LOGI("fetch a OPlmnRAT, iccData= %{public}s", fileData);
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessGetCspCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("Exception to get ELEMENTARY_FILE_CSP data ");
        return isFileProcessResponse;
    }
    TELEPHONY_LOGI("SimFile MSG_SIM_OBTAIN_CSP_CPHS_DONE data:%{public}s", fileData);
    TELEPHONY_LOGI("ELEMENTARY_FILE_CSP: %{public}s", fileData);
    ProcessElementaryFileCsp(iccData);
    return isFileProcessResponse;
}

bool SimFile::ProcessGetInfoCphs(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);
    if (fd->exception != nullptr) {
        return isFileProcessResponse;
    }
    cphsInfo_ = fileData;
    TELEPHONY_LOGI("SimFile iCPHS: %{public}s", rawData);
    return isFileProcessResponse;
}

bool SimFile::ProcessGetSstDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr) {
        return isFileProcessResponse;
    }
    TELEPHONY_LOGI("SimFile MSG_SIM_OBTAIN_SST_DONE data:%{public}s", fileData);
    return isFileProcessResponse;
}

bool SimFile::ProcessGetPnnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    if (fd->exception != nullptr) {
        return isFileProcessResponse;
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = false;
    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("SimFile failed to update");
    }
    return isFileProcessResponse;
}

bool SimFile::ProcessSetCphsMailbox(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = false;
    if (fd->exception == nullptr) {
        voiceMailNum_ = lastVoiceMailNum_;
        voiceMailTag_ = lastVoiceMailTag_;
    } else {
        TELEPHONY_LOGI("fail to update CPHS MailBox");
    }
    return isFileProcessResponse;
}

// Process forbidden PLMNs
bool SimFile::ProcessGetHplmActDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    char *rawData = const_cast<char *>(iccData.c_str());
    unsigned char *fileData = reinterpret_cast<unsigned char *>(rawData);

    if (fd->exception != nullptr || iccData.empty()) {
        TELEPHONY_LOGE("Failed to fetch forbidden PLMN");
        return isFileProcessResponse;
    } else {
        TELEPHONY_LOGI("fetch a FPlmnRAT, iccData=%{public}s", fileData);
    }
    return isFileProcessResponse;
}

// Process Equivalent Home PLMNs
bool SimFile::ProcessGetEhplmnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool isFileProcessResponse = true;
    if (fd->exception != nullptr || iccData.empty()) {
        TELEPHONY_LOGE("Failed fetch Equivalent Home PLMNs");
        return isFileProcessResponse;
    } else {
    }
    return isFileProcessResponse;
}

// Process forbidden PLMNs
bool SimFile::ProcessGetFplmnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    std::string iccData = fd->resultData;
    bool loadResponse = true;
    if (fd->exception != nullptr || iccData.empty()) {
        TELEPHONY_LOGE("Failed to get forbidden PLMNs");
        return loadResponse;
    } else {
    }
    if (fd->arg1 == ICC_CONTROLLER_REQ_SEND_RESPONSE) {
        TELEPHONY_LOGI("getForbiddenPlmns and send result");
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
    memberFuncMap_[ObserverHandler::RADIO_SIM_STATE_LOCKED] = &SimFile::ProcessIccLocked;
    memberFuncMap_[ObserverHandler::RADIO_SIM_STATE_SIMLOCK] = &SimFile::ProcessIccLocked;
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
    memberFuncMap_[MSG_SIM_SET_CPHS_MAILBOX_DONE] = &SimFile::ProcessSetCphsMailbox;
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

void SimFile::ElementaryFilePlLoaded::ProcessParseFile(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<ControllerToFileMsg> fd = event->GetSharedObject<ControllerToFileMsg>();
    file_->efPl_ = fd->resultData;
    TELEPHONY_LOGI("ELEMENTARY_FILE_PL = %{public}s", fd->resultData.c_str());
}

std::string SimFile::ElementaryFileUsimLiLoaded::ObtainElementaryFileName()
{
    return "ELEMENTARY_FILE_LI";
}

void SimFile::ElementaryFileUsimLiLoaded::ProcessParseFile(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<ControllerToFileMsg> fd = event->GetSharedObject<ControllerToFileMsg>();
    file_->efLi_ = fd->resultData;
    TELEPHONY_LOGI("ELEMENTARY_FILE_LI= %{public}s", fd->resultData.c_str());
}

int SimFile::ObtainSpnCondition(bool roaming, const std::string &operatorNum)
{
    int rule = SPN_CONDITION_DISPLAY_SPN;
    // will be implemented for more
    return rule;
}
} // namespace Telephony
} // namespace OHOS