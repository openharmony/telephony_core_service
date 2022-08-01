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

#include "isim_file.h"

#include "radio_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {
IsimFile::IsimFile(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<SimStateManager> simStateManager)
    : IccFile(runner, simStateManager)
{
    fileQueried_ = false;
    InitMemberFunc();
}

void IsimFile::Init()
{
    TELEPHONY_LOGI("IsimFile:::Init():start");
    IccFile::Init();
    if (stateManager_ != nullptr) {
        stateManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_READY);
        stateManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_LOCKED);
        stateManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_SIMLOCK);
    }
}

void IsimFile::StartLoad()
{
    TELEPHONY_LOGI("IsimFile::StartLoad() start");
    LoadIsimFiles();
}

void IsimFile::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto id = event->GetInnerEventId();
    bool isFileHandleResponse = false;
    TELEPHONY_LOGI("IsimFile::ProcessEvent id %{public}d", id);
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

void IsimFile::ProcessIccRefresh(int msgId)
{
    LoadIsimFiles();
}

void IsimFile::ProcessFileLoaded(bool response)
{
    if (!response) {
        return;
    }
    fileToGet_ -= LOAD_STEP;
    TELEPHONY_LOGI("IsimFile::ProcessFileLoaded: %{public}d requested: %{public}d", fileToGet_, fileQueried_);
    if (ObtainFilesFetched()) {
        OnAllFilesFetched();
    } else if (LockQueriedOrNot()) {
        ProcessLockedAllFilesFetched();
    } else if (fileToGet_ < 0) {
        fileToGet_ = 0;
    }
}

void IsimFile::ProcessLockedAllFilesFetched() {}

void IsimFile::OnAllFilesFetched()
{
    filesFetchedObser_->NotifyObserver(RadioEvent::RADIO_SIM_RECORDS_LOADED, slotId_);
    PublishSimFileEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_LOADED, "");
}

bool IsimFile::ProcessIccReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("IsimFile::SIM_STATE_READY --received");
    if (stateManager_->GetCardType() != CardType::SINGLE_MODE_ISIM_CARD) {
        TELEPHONY_LOGI("invalid IsimFile::SIM_STATE_READY received");
        return false;
    }
    LoadIsimFiles();
    return false;
}

bool IsimFile::ProcessIsimRefresh(const AppExecFwk::InnerEvent::Pointer &event)
{
    return false;
}

void IsimFile::LoadIsimFiles()
{
    TELEPHONY_LOGI("LoadIsimFiles started");
    fileQueried_ = true;
    AppExecFwk::InnerEvent::Pointer eventImpi = BuildCallerInfo(MSG_SIM_OBTAIN_IMPI_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_IMPI, eventImpi);
    fileToGet_++;

    AppExecFwk::InnerEvent::Pointer eventIst = BuildCallerInfo(MSG_SIM_OBTAIN_IST_DONE);
    fileController_->ObtainBinaryFile(ELEMENTARY_FILE_IST, eventIst);
    fileToGet_++;
}


bool IsimFile::ProcessGetIccidDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    bool isFileProcessResponse = true;
    if (fd->exception == nullptr) {
        std::string iccData = fd->resultData;
        TELEPHONY_LOGI("IsimFile::ProcessEvent MSG_SIM_OBTAIN_ICCID_DONE result success");
        iccId_ = iccData;
    }
    return isFileProcessResponse;
}

bool IsimFile::ProcessGetImsiDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<std::string> sharedObject = event->GetSharedObject<std::string>();
    bool isFileHandleResponse = true;
    if (sharedObject != nullptr) {
        imsi_ = *sharedObject;
        TELEPHONY_LOGI("IsimFile::ProcessEvent MSG_SIM_OBTAIN_IMSI_DONE");
        if (!imsi_.empty()) {
            imsiReadyObser_->NotifyObserver(RadioEvent::RADIO_IMSI_LOADED_READY);
            PublishSimFileEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_IMSI, imsi_);
        }
    }
    return isFileHandleResponse;
}

void IsimFile::InitMemberFunc()
{
    memberFuncMap_[RadioEvent::RADIO_SIM_STATE_READY] = &IsimFile::ProcessIccReady;
    memberFuncMap_[MSG_ICC_REFRESH] = &IsimFile::ProcessIsimRefresh;
    memberFuncMap_[MSG_SIM_OBTAIN_IMSI_DONE] = &IsimFile::ProcessGetImsiDone;
    memberFuncMap_[MSG_SIM_OBTAIN_ICCID_DONE] = &IsimFile::ProcessGetIccidDone;
    memberFuncMap_[MSG_SIM_OBTAIN_IMPI_DONE] = &IsimFile::ProcessGetImpiDone;
    memberFuncMap_[MSG_SIM_OBTAIN_IST_DONE] = &IsimFile::ProcessGetIstDone;
}

bool IsimFile::ProcessGetImpiDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    bool isFileProcessResponse = true;
    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("ProcessGetImpiDone get exception");
        return isFileProcessResponse;
    }
    imsi_ = fd->resultData;
    TELEPHONY_LOGI("IsimFile::ProcessGetImpiDone success");
    return isFileProcessResponse;
}

bool IsimFile::ProcessGetIstDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    bool isFileProcessResponse = true;
    if (fd->exception != nullptr) {
        TELEPHONY_LOGE("ProcessGetIstDone get exception");
        return isFileProcessResponse;
    }
    ist_ = fd->resultData;
    TELEPHONY_LOGI("IsimFile::ProcessGetIstDone success");
    return isFileProcessResponse;
}

std::string IsimFile::ObtainIsimImpi()
{
    return impi_;
}
std::string IsimFile::ObtainIsimDomain()
{
    return domain_;
}
std::string* IsimFile::ObtainIsimImpu()
{
    return impu_;
}
std::string IsimFile::ObtainIsimIst()
{
    return ist_;
}
std::string* IsimFile::ObtainIsimPcscf()
{
    return pcscf_;
}

bool IsimFile::UpdateVoiceMail(const std::string &mailName, const std::string &mailNumber)
{
    // cdma not support
    return false;
}

int IsimFile::ObtainSpnCondition(bool roaming, const std::string &operatorNum)
{
    return 0;
}

std::string IsimFile::ObtainIsoCountryCode()
{
    return "";
}
IsimFile::~IsimFile() {}
} // namespace Telephony
} // namespace OHOS
