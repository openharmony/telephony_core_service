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

#include "ruim_file.h"

#include "common_event_manager.h"
#include "common_event_support.h"
#include "radio_event.h"
#include "telephony_common_utils.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {
RuimFile::RuimFile(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<SimStateManager> simStateManager)
    : IccFile(runner, simStateManager)
{
    fileQueried_ = false;
    InitMemberFunc();
}

void RuimFile::StartLoad()
{
    TELEPHONY_LOGI("RuimFile::StartLoad() start");
    LoadRuimFiles();
}

std::string RuimFile::ObtainSimOperator()
{
    if (operatorNumeric_.empty()) {
        std::string imsi = ObtainIMSI();
        if (imsi.empty()) {
            TELEPHONY_LOGE("RuimFile::ObtainSimOperator: IMSI is null");
            return "";
        }
        if ((lengthOfMnc_ != UNINITIALIZED_MNC) && (lengthOfMnc_ != UNKNOWN_MNC)) {
            operatorNumeric_ = imsi.substr(0, MCC_LEN + lengthOfMnc_);
        }
        std::string mcc = imsi.substr(0, MCC_LEN);
        if (operatorNumeric_.empty() && IsValidDecValue(mcc)) {
            operatorNumeric_ = imsi.substr(0, MCC_LEN + MccPool::ShortestMncLengthFromMcc(std::stoi(mcc)));
        }
    }
    return operatorNumeric_;
}

std::string RuimFile::ObtainIsoCountryCode()
{
    std::string numeric = ObtainSimOperator();
    if (numeric.empty()) {
        TELEPHONY_LOGE("RuimFile ObtainIsoCountryCode: numeric is null");
        return "";
    }
    size_t len = numeric.length();
    std::string mcc = numeric.substr(0, MCC_LEN);
    if (len >= MCC_LEN && IsValidDecValue(mcc)) {
        std::string iso = MccPool::MccCountryCode(std::stoi(mcc));
        return iso;
    } else {
        return "";
    }
}

void RuimFile::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    auto id = event->GetInnerEventId();
    TELEPHONY_LOGD("RuimFile::ProcessEvent id %{public}d", id);
    auto itFunc = memberFuncMap_.find(id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            bool isFileHandleResponse = (this->*memberFunc)(event);
            ProcessFileLoaded(isFileHandleResponse);
        }
    } else {
        IccFile::ProcessEvent(event);
    }
}

void RuimFile::ProcessIccRefresh(int msgId)
{
    LoadRuimFiles();
}

void RuimFile::ProcessFileLoaded(bool response)
{
    if (!response) {
        return;
    }
    fileToGet_ -= LOAD_STEP;
    TELEPHONY_LOGI("RuimFile::ProcessFileLoaded: %{public}d requested: %{public}d", fileToGet_, fileQueried_);
    if (ObtainFilesFetched()) {
        OnAllFilesFetched();
    } else if (LockQueriedOrNot()) {
        ProcessLockedAllFilesFetched();
    } else if (fileToGet_ < 0) {
        fileToGet_ = 0;
    }
}

void RuimFile::ProcessLockedAllFilesFetched()
{
}

void RuimFile::OnAllFilesFetched()
{
    UpdateLoaded(true);
    filesFetchedObser_->NotifyObserver(RadioEvent::RADIO_SIM_RECORDS_LOADED, slotId_);
    PublishSimFileEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_LOADED, "");
    LoadVoiceMail();
}

bool RuimFile::ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("RuimFile::SIM_STATE_READY --received");
    if (stateManager_->GetCardType() != CardType::SINGLE_MODE_RUIM_CARD) {
        TELEPHONY_LOGI("invalid RuimFile::SIM_STATE_READY received");
        return false;
    }
    LoadRuimFiles();
    return false;
}

bool RuimFile::ProcessIccLocked(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI(
        "only fetch ELEMENTARY_FILE_LI, ELEMENTARY_FILE_PL and ELEMENTARY_FILE_ICCID in locked state");

    lockQueried_ = true;
    AppExecFwk::InnerEvent::Pointer eventICCID = BuildCallerInfo(MSG_SIM_OBTAIN_ICCID_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_ICCID, eventICCID);
    fileToGet_++;
    return false;
}

void RuimFile::LoadRuimFiles()
{
    TELEPHONY_LOGI("LoadRuimFiles started");
    fileQueried_ = true;

    AppExecFwk::InnerEvent::Pointer eventIMSI = BuildCallerInfo(MSG_SIM_OBTAIN_IMSI_DONE);
    telRilManager_->GetImsi(slotId_, eventIMSI);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventICCID = BuildCallerInfo(MSG_SIM_OBTAIN_ICCID_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_ICCID, eventICCID);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventSpn = BuildCallerInfo(MSG_SIM_OBTAIN_CSIM_SPN_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_CSIM_SPN, eventSpn);
    fileToGet_++;
}

bool RuimFile::ProcessGetSubscriptionDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = true;
    return isFileHandleResponse;
}

bool RuimFile::ProcessGetIccidDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileProcessResponse = true;
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return isFileProcessResponse;
    }
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    if (fd == nullptr) {
        TELEPHONY_LOGE("fd is nullptr!");
        return isFileProcessResponse;
    }
    if (fd->exception == nullptr) {
        std::string iccData = fd->resultData;
        std::string fullIccData = iccData;
        GetFullIccid(fullIccData);
        SwapPairsForIccId(iccData);
        TELEPHONY_LOGI("RuimFile::ProcessEvent MSG_SIM_OBTAIN_ICCID_DONE result success");
        decIccId_ = iccData;
        iccId_ = fullIccData;
    }
    return isFileProcessResponse;
}

bool RuimFile::ProcessGetImsiDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileHandleResponse = true;
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return isFileHandleResponse;
    }
    std::shared_ptr<std::string> sharedObject = event->GetSharedObject<std::string>();
    if (sharedObject == nullptr) {
        TELEPHONY_LOGE("sharedObject is nullptr!");
        return isFileHandleResponse;
    }
    if (sharedObject != nullptr) {
        imsi_ = *sharedObject;
        TELEPHONY_LOGI("RuimFile::ProcessEvent MSG_SIM_OBTAIN_IMSI_DONE");
        SaveCountryCode();
        if (!imsi_.empty()) {
            imsiReadyObser_->NotifyObserver(RadioEvent::RADIO_IMSI_LOADED_READY);
        }
    }
    return isFileHandleResponse;
}

std::string RuimFile::ObtainMdnNumber()
{
    return phoneNumber_;
}

std::string RuimFile::ObtainCdmaMin()
{
    return min2And1_;
}

std::string RuimFile::ObtainPrlVersion()
{
    return prlVersion_;
}

std::string RuimFile::ObtainNAI()
{
    return nai_;
}
std::string RuimFile::ObtainMdn()
{
    return mdn_;
}

std::string RuimFile::ObtainMin()
{
    return min_;
}

std::string RuimFile::ObtainSid()
{
    return systemId_;
}

std::string RuimFile::ObtainNid()
{
    return networkId_;
}

bool RuimFile::ObtainCsimSpnDisplayCondition()
{
    return displayConditionOfCsimSpn_;
}

void RuimFile::InitMemberFunc()
{
    memberFuncMap_[RadioEvent::RADIO_SIM_STATE_READY] = &RuimFile::ProcessIccReady;
    memberFuncMap_[RadioEvent::RADIO_SIM_STATE_LOCKED] = &RuimFile::ProcessIccLocked;
    memberFuncMap_[RadioEvent::RADIO_SIM_STATE_SIMLOCK] = &RuimFile::ProcessIccLocked;
    memberFuncMap_[MSG_SIM_OBTAIN_IMSI_DONE] = &RuimFile::ProcessGetImsiDone;
    memberFuncMap_[MSG_SIM_OBTAIN_ICCID_DONE] = &RuimFile::ProcessGetIccidDone;
    memberFuncMap_[MSG_SIM_OBTAIN_CDMA_SUBSCRIPTION_DONE] = &RuimFile::ProcessGetSubscriptionDone;
    memberFuncMap_[MSG_SIM_OBTAIN_CSIM_SPN_DONE] = &RuimFile::ProcessGetSpnDone;
}

bool RuimFile::ProcessGetSpnDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileProcessResponse = true;
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return isFileProcessResponse;
    }
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    if (fd == nullptr) {
        TELEPHONY_LOGE("fd is nullptr!");
        return isFileProcessResponse;
    }
    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("EfCsimSpnFileWanted ProcessParseFile get exception");
        return isFileProcessResponse;
    }
    std::string iccData = fd->resultData;
    if (iccData.empty()) {
        TELEPHONY_LOGE("EfCsimSpnFileWanted ProcessParseFile get empty data");
        return isFileProcessResponse;
    }
    int dataLen = 0;
    std::shared_ptr<unsigned char> fileData = SIMUtils::HexStringConvertToBytes(iccData, dataLen);
    unsigned char* data = fileData.get();
    displayConditionOfCsimSpn_ = ((static_cast<unsigned int>(SPN_FLAG) & static_cast<unsigned int>(data[0])) != 0);

    int encoding = static_cast<int>(data[ENCODING_POS]);
    int language = static_cast<int>(data[LANG_POS]);
    unsigned char spnData[BUFFER_SIZE] = {0};

    int len = ((dataLen - FLAG_NUM) < MAX_DATA_BYTE) ? (dataLen - FLAG_NUM) : MAX_DATA_BYTE;
    SIMUtils::ArrayCopy(data, FLAG_NUM, spnData, 0, len);

    int numBytes = 0;
    int spnDataLen = strlen((char *)spnData);
    for (numBytes = 0; numBytes < spnDataLen; numBytes++) {
        if ((spnData[numBytes] & BYTE_NUM) == BYTE_NUM) {
            break;
        }
    }

    if (numBytes == 0) {
        UpdateSPN("");
        return  isFileProcessResponse;
    }
    TELEPHONY_LOGI("EfCsimSpnFileWanted encoding is %{public}d, languange is %{public}d", encoding, language);
    ParseSpnName(encoding, spnData, numBytes);
    return  isFileProcessResponse;
}
void RuimFile::ParseSpnName(int encodeType, const unsigned char* spnData, int dataLen)
{
    switch (encodeType) {
        case CSIM_SPN_OCTET:
        case CSIM_SPN_LATIN: {
            std::string spnName((char*)spnData, 0, dataLen);
            UpdateSPN(spnName);
            }
            break;
        case CSIM_SPN_IA5:
        case CSIM_SPN_7BIT_ALPHABET: {
            std::string spnName((char*)spnData, 0, dataLen);
            UpdateSPN(spnName);
            }
            break;
        case CSIM_SPN_7BIT_ASCII: {
            std::string spnName((char*)spnData, 0, dataLen);
            if (SIMUtils::IsShowableAsciiOnly(spnName)) {
                UpdateSPN(spnName);
            } else {
                TELEPHONY_LOGI("EfCsimSpnFileWanted Some corruption in SPN decoding = %{public}s", spnName.data());
            }
            }
            break;
        case CSIM_SPN_UNICODE_16: {
            int outlen = 0;
            std::shared_ptr<char16_t> cs = SIMUtils::CharsConvertToChar16(spnData, dataLen, outlen, true);
            std::u16string hs(cs.get(), 0, outlen);
            std::string spnName = Str16ToStr8(hs);
            TELEPHONY_LOGI("ENCODING_UNICODE_16 spn name = %{public}s", spnName.c_str());
            UpdateSPN(spnName);
            }
            break;
        default:
            TELEPHONY_LOGI("SPN encoding not supported");
    }
}

int RuimFile::ObtainSpnCondition(bool roaming, const std::string &operatorNum)
{
    return 0;
}

bool RuimFile::UpdateVoiceMail(const std::string &mailName, const std::string &mailNumber)
{
    // cdma not support
    return false;
}

bool RuimFile::SetVoiceMailCount(int32_t voiceMailCount)
{
    // cdma not support
    return false;
}

bool RuimFile::SetVoiceCallForwarding(bool enable, const std::string &number)
{
    // cdma not support
    return false;
}

std::string RuimFile::GetVoiceMailNumber()
{
    std::shared_lock<std::shared_mutex> lock(voiceMailMutex_);
    return voiceMailNum_;
}

void RuimFile::SetVoiceMailNumber(const std::string mailNumber)
{
    std::unique_lock<std::shared_mutex> lock(voiceMailMutex_);
    voiceMailNum_ = mailNumber;
}

RuimFile::~RuimFile() {}
} // namespace Telephony
} // namespace OHOS
