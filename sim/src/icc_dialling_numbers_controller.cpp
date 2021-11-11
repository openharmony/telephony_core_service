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

#include "icc_dialling_numbers_controller.h"

namespace OHOS {
namespace Telephony {
IccDiallingNumbersController::IccDiallingNumbersController(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    std::shared_ptr<ISimFileManager> simFileManager)
    : AppExecFwk::EventHandler(runner), simFileManager_(simFileManager)
{}

void IccDiallingNumbersController::Init()
{
    TELEPHONY_LOGI("IccDiallingNumbersController::Init() started ");
    if (statePhoneBook_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("IccDiallingNumbersController::Init eventLoopPhoneBook_ started.");
        return;
    }

    eventLoopPhoneBook_ = AppExecFwk::EventRunner::Create("pbCacheLoop");
    if (eventLoopPhoneBook_.get() == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersController  failed to create EventRunner");
        return;
    }

    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersController::Init ISimFileManager null pointer");
        return;
    }

    phoneBookCache_ = std::make_shared<SimDiallingNumbersStation>(eventLoopPhoneBook_, simFileManager_);
    if (phoneBookCache_ == nullptr) {
        TELEPHONY_LOGE("IccDiallingNumbersController::Init simFile create nullptr.");
        return;
    }

    eventLoopPhoneBook_->Run();
    statePhoneBook_ = HandleRunningState::STATE_RUNNING;

    phoneBookCache_->Init();
    TELEPHONY_LOGI("IccDiallingNumbersController::Init() end");
}

void IccDiallingNumbersController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int id = 0;
    id = event->GetInnerEventId();
    TELEPHONY_LOGI("IccDiallingNumbersController ProcessEvent Id is %{public}d", id);
    switch (id) {
        case PHONE_BOOK_GET_COMPLETED:
            ProcessLoadDone(event);
            break;
        case PHONE_BOOK_UPDATE_COMPLETED:
            ProcessUpdateDone(event);
            break;
        case PHONE_BOOK_WRITE_COMPLETED:
            ProcessWriteDone(event);
            break;
        case PHONE_BOOK_DELETE_COMPLETED:
            ProcessDeleteDone(event);
            break;
        default:
            break;
    }
}

void IccDiallingNumbersController::ProcessLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("IccDiallingNumbersController::ProcessLoadDone: start");
    std::unique_ptr<StationResult> object = event->GetUniqueObject<StationResult>();
    if (object != nullptr) {
        if (object->exception == nullptr) {
            std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> diallingNumberList =
                std::static_pointer_cast<std::vector<std::shared_ptr<DiallingNumbersInfo>>>(object->result);
            if (diallingNumberList != nullptr) {
                FillResults(diallingNumberList);
            } else {
                TELEPHONY_LOGE("ProcessDiallingNumberLoadDone: get null vectors!!!");
                ClearRecords();
            }
        } else {
            TELEPHONY_LOGE("ProcessLoadDone: icc phonebook get exception result");
            ClearRecords();
        }
    } else {
        TELEPHONY_LOGE("ProcessDiallingNumberLoadDone: get null pointer!!!");
        ClearRecords();
    }

    SetCurAction(OBTAIN_PHONE_BOOK);
    processWait_.notify_one();
}

void IccDiallingNumbersController::ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    result_ = true;
    std::unique_ptr<StationResult> object = event->GetUniqueObject<StationResult>();
    if (object->exception != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> responseInfo =
            std::static_pointer_cast<HRilRadioResponseInfo>(object->exception);
        TELEPHONY_LOGE("IccDiallingNumbersController::ProcessUpdateDone error %{public}d", responseInfo->error);
        result_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("IccDiallingNumbersController::ProcessUpdateDone: end");
    SetCurAction(UPDATE_PHONE_BOOK);
    processWait_.notify_one();
}

void IccDiallingNumbersController::ProcessWriteDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    result_ = true;
    std::unique_ptr<StationResult> object = event->GetUniqueObject<StationResult>();
    if (object->exception != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> responseInfo =
            std::static_pointer_cast<HRilRadioResponseInfo>(object->exception);
        TELEPHONY_LOGE("IccDiallingNumbersController::ProcessWriteDone error %{public}d", responseInfo->error);
        result_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("IccDiallingNumbersController::ProcessWriteDone: end");
    SetCurAction(WRITE_PHONE_BOOK);
    processWait_.notify_one();
}

void IccDiallingNumbersController::ProcessDeleteDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    result_ = true;
    std::unique_ptr<StationResult> object = event->GetUniqueObject<StationResult>();
    if (object->exception != nullptr) {
        std::shared_ptr<HRilRadioResponseInfo> responseInfo =
            std::static_pointer_cast<HRilRadioResponseInfo>(object->exception);
        TELEPHONY_LOGE("IccDiallingNumbersController::ProcessDeleteDone error %{public}d", responseInfo->error);
        result_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("IccDiallingNumbersController::ProcessDeleteDone: end");
    SetCurAction(DELETE_PHONE_BOOK);
    processWait_.notify_one();
}

bool IccDiallingNumbersController::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (!IsValidType(type) || diallingNumber == nullptr) {
        return false;
    }
    result_ = false;
    int index = diallingNumber->GetRecId();
    TELEPHONY_LOGI("UpdateIccDiallingNumbers start: %{public}d", index);
    int fileId = GetFileIdForType(type);
    AppExecFwk::InnerEvent::Pointer response = CreatePointer(PHONE_BOOK_UPDATE_COMPLETED);
    phoneBookCache_->ChangeDiallingNumberForId(fileId, diallingNumber, index, "", response);

    std::unique_lock<std::mutex> lock(mtx_);
    processWait_.wait(lock, IccDiallingNumbersController::IsActionOn);
    SetCurAction(ACTION_READY);
    TELEPHONY_LOGI("IccDiallingNumbersController::UpdateIccDiallingNumbers OK return %{public}d", result_);
    return result_;
}

bool IccDiallingNumbersController::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (!IsValidType(type) || diallingNumber == nullptr) {
        return false;
    }
    result_ = false;
    int index = diallingNumber->GetRecId();
    TELEPHONY_LOGI("DelIccDiallingNumbers start: %{public}d %{public}d", type, index);
    int fileId = GetFileIdForType(type);
    AppExecFwk::InnerEvent::Pointer response = CreatePointer(PHONE_BOOK_DELETE_COMPLETED);
    std::string name = "";
    std::string number = "";
    std::shared_ptr<DiallingNumbersInfo> diallingNumberNull = std::make_shared<DiallingNumbersInfo>(fileId, index);
    diallingNumberNull->alphaTag_ = Str8ToStr16(name);
    diallingNumberNull->number_ = Str8ToStr16(number);
    phoneBookCache_->ChangeDiallingNumberForId(fileId, diallingNumberNull, index, "", response);

    std::unique_lock<std::mutex> lock(mtx_);
    processWait_.wait(lock, IccDiallingNumbersController::IsActionOn);
    SetCurAction(ACTION_READY);
    TELEPHONY_LOGI("IccDiallingNumbersController::DelIccDiallingNumbers OK return %{public}d", result_);
    return result_;
}

bool IccDiallingNumbersController::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    result_ = false;
    TELEPHONY_LOGI("AddIccDiallingNumbers start:%{public}d", type);
    if (!IsValidType(type) || diallingNumber == nullptr) {
        return false;
    }
    AppExecFwk::InnerEvent::Pointer response = CreatePointer(PHONE_BOOK_WRITE_COMPLETED);
    int fileId = GetFileIdForType(type);
    phoneBookCache_->ChangeDiallingNumberForId(fileId, diallingNumber, -1, "", response);

    std::unique_lock<std::mutex> lock(mtx_);
    processWait_.wait(lock, IccDiallingNumbersController::IsActionOn);
    SetCurAction(ACTION_READY);
    TELEPHONY_LOGI("IccDiallingNumbersController::AddIccDiallingNumbers OK return %{public}d", result_);
    return result_;
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> IccDiallingNumbersController::QueryIccDiallingNumbers(
    int slotId, int type)
{
    ClearRecords();
    if (phoneBookCache_ == nullptr || !IsValidType(type)) {
        TELEPHONY_LOGE("Cannot load DiallingNumbersInfo records. No icc card?");
        return phoneBookList_;
    }
    TELEPHONY_LOGI("QueryIccDiallingNumbers start!!");
    int fileId = GetFileIdForType(type);

    int extensionEf = phoneBookCache_->ExtendedElementFile(fileId);
    AppExecFwk::InnerEvent::Pointer event = CreatePointer(PHONE_BOOK_GET_COMPLETED);
    phoneBookCache_->ObtainAllDiallingNumberFiles(fileId, extensionEf, event);

    std::unique_lock<std::mutex> lock(mtx_);
    processWait_.wait(lock, IccDiallingNumbersController::IsActionOn);
    TELEPHONY_LOGI("IccDiallingNumbersController::QueryIccDiallingNumbers: end");
    SetCurAction(ACTION_READY);
    return phoneBookList_;
}

AppExecFwk::InnerEvent::Pointer IccDiallingNumbersController::CreatePointer(int eventId)
{
    std::unique_ptr<StationFetcher> object = std::make_unique<StationFetcher>();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

bool IccDiallingNumbersController::IsActionOn()
{
    return (g_CurCtrlAction == OBTAIN_PHONE_BOOK) || (g_CurCtrlAction == UPDATE_PHONE_BOOK) ||
        (g_CurCtrlAction == WRITE_PHONE_BOOK) || (g_CurCtrlAction == DELETE_PHONE_BOOK);
}

void IccDiallingNumbersController::SetCurAction(PhoneBook_Action_Type action)
{
    g_CurCtrlAction = action;
}

PhoneBook_Action_Type IccDiallingNumbersController::GetCurAction()
{
    return g_CurCtrlAction;
}

void IccDiallingNumbersController::ClearRecords()
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> nullVector;
    phoneBookList_.swap(nullVector);
}

int IccDiallingNumbersController::GetFileIdForType(int fileType)
{
    int fileId = 0;
    if (fileType == SimPhoneBook_Adn) {
        fileId = ELEMENTARY_FILE_ADN; //  ELEMENTARY_FILE_PBR  for usim
    } else if (fileType == SimPhoneBook_Fdn) {
        fileId = ELEMENTARY_FILE_FDN;
    }
    return fileId;
}

void IccDiallingNumbersController::FillResults(
    const std::shared_ptr<std::vector<std::shared_ptr<DiallingNumbersInfo>>> &listInfo)
{
    TELEPHONY_LOGI("IccDiallingNumbersController::ProcessLoadDone  %{public}zu", listInfo->size());
    for (auto it = listInfo->begin(); it != listInfo->end(); it++) {
        std::shared_ptr<DiallingNumbersInfo> item = *it;
        std::string &&name = Str16ToStr8(item->GetAlphaTag());
        std::string &&number = Str16ToStr8(item->GetNumber());
        TELEPHONY_LOGI("ppphonebooks item: %{public}s %{public}s", name.c_str(), number.c_str());
        if (!item->IsEmpty()) {
            phoneBookList_.push_back(item);
        }
    }
}

bool IccDiallingNumbersController::IsValidType(int type)
{
    switch (type) {
        case SimPhoneBook_Adn:
        case SimPhoneBook_Fdn:
            return true;
        default:
            return false;
    }
}

IccDiallingNumbersController::~IccDiallingNumbersController() {}
} // namespace Telephony
} // namespace OHOS
