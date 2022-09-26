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

#include "icc_dialling_numbers_manager.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
constexpr static const int32_t WAIT_TIME_SECOND = 1;

IccDiallingNumbersManager::IccDiallingNumbersManager(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    std::shared_ptr<SimFileManager> simFileManager, std::shared_ptr<SimStateManager> simState)
    : AppExecFwk::EventHandler(runner), simFileManager_(simFileManager), simStateManager_(simState)
{}

void IccDiallingNumbersManager::Init()
{
    TELEPHONY_LOGI("IccDiallingNumbersManager::Init() started ");
    if (stateDiallingNumbers_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("IccDiallingNumbersManager::Init eventLoopDiallingNumbers_ started.");
        return;
    }

    eventLoopDiallingNumbers_ = AppExecFwk::EventRunner::Create("diallingNumbersCacheLoop");
    if (eventLoopDiallingNumbers_.get() == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager failed to create EventRunner");
        return;
    }

    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::Init SimFileManager null pointer");
        return;
    }

    diallingNumbersCache_ = std::make_shared<IccDiallingNumbersCache>(eventLoopDiallingNumbers_, simFileManager_);
    if (diallingNumbersCache_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::Init simFile create nullptr.");
        return;
    }

    eventLoopDiallingNumbers_->Run();
    stateDiallingNumbers_ = HandleRunningState::STATE_RUNNING;

    diallingNumbersCache_->Init();
    simFileManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    TELEPHONY_LOGI("IccDiallingNumbersManager::Init() end");
}

void IccDiallingNumbersManager::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    uint32_t id = event->GetInnerEventId();
    TELEPHONY_LOGI("IccDiallingNumbersManager ProcessEvent Id is %{public}d", id);
    switch (id) {
        case MSG_SIM_DIALLING_NUMBERS_GET_DONE:
            ProcessLoadDone(event);
            break;
        case MSG_SIM_DIALLING_NUMBERS_UPDATE_DONE:
            ProcessUpdateDone(event);
            break;
        case MSG_SIM_DIALLING_NUMBERS_WRITE_DONE:
            ProcessWriteDone(event);
            break;
        case MSG_SIM_DIALLING_NUMBERS_DELETE_DONE:
            ProcessDeleteDone(event);
            break;
        case RadioEvent::RADIO_SIM_RECORDS_LOADED:
            InitFdnCache();
            break;
        default:
            break;
    }
}

void IccDiallingNumbersManager::InitFdnCache()
{
    TELEPHONY_LOGI("IccDiallingNumbersManager::InitFdnCache start");
    std::thread initTask ([&]() {
        QueryIccDiallingNumbers(DiallingNumbersInfo::SIM_FDN);
    });
    initTask.detach();
}

void IccDiallingNumbersManager::ProcessLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("IccDiallingNumbersManager::ProcessLoadDone: start");
    std::unique_ptr<ResponseResult> object = event->GetUniqueObject<ResponseResult>();
    if (object != nullptr) {
        if (object->exception == nullptr) {
            std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
                std::static_pointer_cast<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(object->result);
            if (diallingNumberList != nullptr) {
                FillResults(diallingNumberList);
            } else {
                TELEPHONY_LOGE("ProcessDiallingNumberLoadDone: get null vectors!!!");
            }
        } else {
            TELEPHONY_LOGE("ProcessLoadDone: icc diallingnumbers get exception result");
        }
    } else {
        TELEPHONY_LOGE("ProcessDiallingNumberLoadDone: get null pointer!!!");
    }
    TELEPHONY_LOGI("IccDiallingNumbersManager::ProcessLoadDone: end");
    hasEventDone_ = true;
    processWait_.notify_all();
}

void IccDiallingNumbersManager::ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    hasEventDone_ = true;
    std::unique_ptr<ResponseResult> object = event->GetUniqueObject<ResponseResult>();
    if (object->exception != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> responseInfo =
            std::static_pointer_cast<HRilRadioResponseInfo>(object->exception);
        TELEPHONY_LOGE("IccDiallingNumbersManager::ProcessUpdateDone error %{public}d", responseInfo->error);
        hasEventDone_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("IccDiallingNumbersManager::ProcessUpdateDone: end");
    processWait_.notify_all();
}

void IccDiallingNumbersManager::ProcessWriteDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    hasEventDone_ = true;
    std::unique_ptr<ResponseResult> object = event->GetUniqueObject<ResponseResult>();
    if (object->exception != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> responseInfo =
            std::static_pointer_cast<HRilRadioResponseInfo>(object->exception);
        TELEPHONY_LOGE("IccDiallingNumbersManager::ProcessWriteDone error %{public}d", responseInfo->error);
        hasEventDone_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("IccDiallingNumbersManager::ProcessWriteDone: end");
    processWait_.notify_all();
}

void IccDiallingNumbersManager::ProcessDeleteDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    hasEventDone_ = true;
    std::unique_ptr<ResponseResult> object = event->GetUniqueObject<ResponseResult>();
    if (object->exception != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> responseInfo =
            std::static_pointer_cast<HRilRadioResponseInfo>(object->exception);
        TELEPHONY_LOGE("IccDiallingNumbersManager::ProcessDeleteDone error %{public}d", responseInfo->error);
        hasEventDone_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("IccDiallingNumbersManager::ProcessDeleteDone: end");
    processWait_.notify_all();
}

bool IccDiallingNumbersManager::UpdateIccDiallingNumbers(
    int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    std::unique_lock<std::mutex> lock(mtx_);
    if (!IsValidType(type) || diallingNumber == nullptr || !HasSimCard() ||
        !IsValidParam(type, diallingNumber)) {
        return false;
    }
    int index = diallingNumber->GetIndex();
    TELEPHONY_LOGI("UpdateIccDiallingNumbers start: %{public}d %{public}d", type, index);
    int fileId = GetFileIdForType(type);
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_SIM_DIALLING_NUMBERS_UPDATE_DONE);
    hasEventDone_ = false;
    diallingNumbersCache_->UpdateDiallingNumberToIcc(fileId, diallingNumber, index, false, response);
    while (!hasEventDone_) {
        TELEPHONY_LOGI("UpdateIccDiallingNumbers::wait(), response = false");
        if (processWait_.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    TELEPHONY_LOGI("IccDiallingNumbersManager::UpdateIccDiallingNumbers OK return %{public}d", hasEventDone_);
    return hasEventDone_;
}

bool IccDiallingNumbersManager::DelIccDiallingNumbers(
    int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    std::unique_lock<std::mutex> lock(mtx_);
    if (!IsValidType(type) || diallingNumber == nullptr || !HasSimCard() ||
        !IsValidParam(type, diallingNumber)) {
        return false;
    }
    int index = diallingNumber->GetIndex();
    TELEPHONY_LOGI("DelIccDiallingNumbers start: %{public}d %{public}d", type, index);
    int fileId = GetFileIdForType(type);
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_SIM_DIALLING_NUMBERS_DELETE_DONE);
    hasEventDone_ = false;
    diallingNumbersCache_->UpdateDiallingNumberToIcc(fileId, diallingNumber, index, true, response);
    while (!hasEventDone_) {
        TELEPHONY_LOGI("DelIccDiallingNumbers::wait(), response = false");
        if (processWait_.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    TELEPHONY_LOGI("IccDiallingNumbersManager::DelIccDiallingNumbers OK return %{public}d", hasEventDone_);
    return hasEventDone_;
}

bool IccDiallingNumbersManager::AddIccDiallingNumbers(
    int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    std::unique_lock<std::mutex> lock(mtx_);
    TELEPHONY_LOGI("AddIccDiallingNumbers start:%{public}d", type);
    if (!IsValidType(type) || diallingNumber == nullptr || !HasSimCard() ||
        !IsValidParam(type, diallingNumber)) {
        return false;
    }
    AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(MSG_SIM_DIALLING_NUMBERS_WRITE_DONE);
    int fileId = GetFileIdForType(type);
    hasEventDone_ = false;
    diallingNumbersCache_->UpdateDiallingNumberToIcc(fileId, diallingNumber, ADD_FLAG, false, response);
    while (!hasEventDone_) {
        TELEPHONY_LOGI("DelIccDiallingNumbers::wait(), response = false");
        if (processWait_.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    TELEPHONY_LOGI("IccDiallingNumbersManager::AddIccDiallingNumbers OK return %{public}d", hasEventDone_);
    return hasEventDone_;
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> IccDiallingNumbersManager::QueryIccDiallingNumbers(
    int type)
{
    std::unique_lock<std::mutex> lock(mtx_);
    ClearRecords();
    if (diallingNumbersCache_ == nullptr || !IsValidType(type) || !HasSimCard()) {
        TELEPHONY_LOGE("Cannot load DiallingNumbersInfo records. no sim inserted?");
        return diallingNumbersList_;
    }
    TELEPHONY_LOGI("QueryIccDiallingNumbers start:%{public}d", type);
    int fileId = GetFileIdForType(type);
    int extensionEf = diallingNumbersCache_->ExtendedElementFile(fileId);
    AppExecFwk::InnerEvent::Pointer event = BuildCallerInfo(MSG_SIM_DIALLING_NUMBERS_GET_DONE);
    hasEventDone_ = false;
    diallingNumbersCache_->ObtainAllDiallingNumberFiles(fileId, extensionEf, event);
    processWait_.wait(lock, [this] { return hasEventDone_ == true; });
    TELEPHONY_LOGI("IccDiallingNumbersManager::QueryIccDiallingNumbers: end");
    return diallingNumbersList_;
}

AppExecFwk::InnerEvent::Pointer IccDiallingNumbersManager::BuildCallerInfo(int eventId)
{
    std::unique_ptr<ResultObtain> object = std::make_unique<ResultObtain>();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

void IccDiallingNumbersManager::ClearRecords()
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> nullVector;
    diallingNumbersList_.swap(nullVector);
}

int IccDiallingNumbersManager::GetFileIdForType(int fileType)
{
    int fileId = 0;
    if (fileType == DiallingNumbersInfo::SIM_ADN) {
        fileId = ELEMENTARY_FILE_ADN; //  ELEMENTARY_FILE_PBR  for usim
    } else if (fileType == DiallingNumbersInfo::SIM_FDN) {
        fileId = ELEMENTARY_FILE_FDN;
    }
    return fileId;
}

void IccDiallingNumbersManager::FillResults(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &listInfo)
{
    TELEPHONY_LOGI("IccDiallingNumbersManager::FillResults  %{public}zu", listInfo->size());
    for (auto it = listInfo->begin(); it != listInfo->end(); it++) {
        std::shared_ptr<DiallingNumbersInfo> item = *it;
        if (!item->IsEmpty()) {
            diallingNumbersList_.push_back(item);
        }
    }
    TELEPHONY_LOGI("IccDiallingNumbersManager::FillResults end");
}

bool IccDiallingNumbersManager::IsValidType(int type)
{
    switch (type) {
        case DiallingNumbersInfo::SIM_ADN:
        case DiallingNumbersInfo::SIM_FDN:
            return true;
        default:
            return false;
    }
}

std::shared_ptr<IccDiallingNumbersManager> IccDiallingNumbersManager::CreateInstance(
    const std::shared_ptr<SimFileManager> &simFile, const std::shared_ptr<SimStateManager> &simState)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop =
        AppExecFwk::EventRunner::Create("diallingNumbersManagerLoop");
    if (eventLoop.get() == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager  failed to create EventRunner");
        return nullptr;
    }
    if (simFile == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::Init SimFileManager null pointer");
        return nullptr;
    }
    std::shared_ptr<IccDiallingNumbersManager> manager =
        std::make_shared<IccDiallingNumbersManager>(eventLoop, simFile, simState);
    if (manager == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersManager::Init manager create nullptr.");
        return nullptr;
    }
    eventLoop->Run();
    return manager;
}

bool IccDiallingNumbersManager::HasSimCard()
{
    return (simStateManager_ != nullptr) ? simStateManager_->HasSimCard() : false;
}

bool IccDiallingNumbersManager::IsValidParam(int type, const std::shared_ptr<DiallingNumbersInfo> &info)
{
    if (type == DiallingNumbersInfo::SIM_FDN) {
        return !(info->pin2_.empty());
    } else {
        return true;
    }
}

IccDiallingNumbersManager::~IccDiallingNumbersManager() {}
} // namespace Telephony
} // namespace OHOS
