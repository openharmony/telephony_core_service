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

#include "sim_sms_controller.h"

namespace OHOS {
namespace Telephony {
SimSmsController::SimSmsController(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : AppExecFwk::EventHandler(runner)
{}

void SimSmsController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int id = 0;
    id = event->GetInnerEventId();
    TELEPHONY_LOGI("SimSmsController ProcessEvent Id is %{public}d", id);
    switch (id) {
        case SIM_SMS_GET_COMPLETED:
            ProcessLoadDone(event);
            break;
        case SIM_SMS_UPDATE_COMPLETED:
            ProcessUpdateDone(event);
            break;
        case SIM_SMS_WRITE_COMPLETED:
            ProcessWriteDone(event);
            break;
        case SIM_SMS_DELETE_COMPLETED:
            ProcessDeleteDone(event);
            break;
        default:
            break;
    }
}

void SimSmsController::ProcessLoadDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("SimSmsController::ProcessLoadDone: start");
    std::unique_ptr<ControllerToFileMsg> fd = event->GetUniqueObject<ControllerToFileMsg>();
    if (fd != nullptr) {
        if (fd->exception != nullptr) {
            TELEPHONY_LOGE("ProcessLoadDone: get error result");
            std::vector<std::string> nullVector;
            smsList_.swap(nullVector);
        }
    } else {
        std::shared_ptr<MultiRecordResult> object = event->GetSharedObject<MultiRecordResult>();
        if (object != nullptr) {
            TELEPHONY_LOGI("SimSmsController::ProcessLoadDone: %{public}d", object->resultLength);
            if (object->exception == nullptr) {
                smsList_.assign(object->fileResults.begin(), object->fileResults.end());
            }
        } else {
            TELEPHONY_LOGE("ProcessLoadDone: get null pointer!!!");
        }
    }
    SetCurAction(OBTAIN_SMS);
    processWait_.notify_one();
}

void SimSmsController::ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    result_ = true;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("SimSmsController::ProcessUpdateDone error %{public}d", responseInfo->error);
        result_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("SimSmsController::ProcessUpdateDone: end");
    SetCurAction(UPDATE_SMS);
    processWait_.notify_one();
}

void SimSmsController::ProcessWriteDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    result_ = true;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("SimSmsController::ProcessWriteDone error %{public}d", responseInfo->error);
        result_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("SimSmsController::ProcessWriteDone: end");
    SetCurAction(WRITE_SMS);
    processWait_.notify_one();
}

void SimSmsController::ProcessDeleteDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    result_ = true;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("SimSmsController::ProcessDeleteDone error %{public}d", responseInfo->error);
        result_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("SimSmsController::ProcessDeleteDone: end");
    SetCurAction(DELETE_SMS);
    processWait_.notify_one();
}

bool SimSmsController::RenewSmsIcc(int index, int status, std::string &pduData, std::string &smsc)
{
    result_ = false;
    TELEPHONY_LOGI("RenewSmsIcc start: %{public}d", index);
    AppExecFwk::InnerEvent::Pointer response = CreatePointer(SIM_SMS_UPDATE_COMPLETED);
    rilManager_->UpdateSms(index, status, smsc, pduData, response);
    std::unique_lock<std::mutex> lock(mtx_);
    processWait_.wait(lock, SimSmsController::IsActionOn);
    SetCurAction(ACTION_NONE);
    TELEPHONY_LOGI("SimSmsController::RenewSmsIcc OK return %{public}d", result_);
    return result_;
}

bool SimSmsController::DelSmsIcc(int index)
{
    result_ = false;
    TELEPHONY_LOGI("DelSmsIcc start: %{public}d", index);
    if (PhoneTypeGsmOrNot()) {
        AppExecFwk::InnerEvent::Pointer response = CreatePointer(SIM_SMS_DELETE_COMPLETED);
        rilManager_->DeleteSms(index, response);
        std::unique_lock<std::mutex> lock(mtx_);
        processWait_.wait(lock, SimSmsController::IsActionOn);
        SetCurAction(ACTION_NONE);
        TELEPHONY_LOGI("SimSmsController::DelSmsIcc OK return %{public}d", result_);
        return result_;
    } else {
        TELEPHONY_LOGE("DeleteSimMessage cdma do not support temporary");
        return result_;
    }
}

bool SimSmsController::AddSmsToIcc(int status, std::string &pdu, std::string &smsc)
{
    result_ = false;
    TELEPHONY_LOGI("AddSmsToIcc start: %{public}d", status);
    if (PhoneTypeGsmOrNot()) {
        AppExecFwk::InnerEvent::Pointer response = CreatePointer(SIM_SMS_WRITE_COMPLETED);
        rilManager_->StorageSms(status, smsc, pdu, response);
    } else {
        TELEPHONY_LOGE("AddSmsToIcc cdma do not support temporary");
    }

    std::unique_lock<std::mutex> lock(mtx_);
    processWait_.wait(lock, SimSmsController::IsActionOn);
    SetCurAction(ACTION_NONE);
    TELEPHONY_LOGI("SimSmsController::AddSmsToIcc OK return %{public}d", result_);
    return result_;
}

void SimSmsController::Init() {}

std::vector<std::string> SimSmsController::ObtainAllSmsOfIcc()
{
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("Cannot load Sms records. No icc card?");
        std::vector<std::string> nullVector;
        smsList_.swap(nullVector);
        return smsList_;
    }
    TELEPHONY_LOGI("ObtainAllSmsOfIcc start!!");
    AppExecFwk::InnerEvent::Pointer event = CreatePointer(SIM_SMS_GET_COMPLETED);
    fileController_->ObtainAllLinearFixedFile(ELEMENTARY_FILE_SMS, event);

    std::unique_lock<std::mutex> lock(mtx_);
    processWait_.wait(lock, SimSmsController::IsActionOn);
    TELEPHONY_LOGI("SimSmsController::ObtainAllSmsOfIcc: end");
    SetCurAction(ACTION_NONE);
    return smsList_;
}

void SimSmsController::SetRilAndFileController(
    std::shared_ptr<Telephony::IRilManager> ril, std::shared_ptr<IccFileController> file)
{
    rilManager_ = ril;
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("SimSmsController rilmanager get null pointer");
    }
    fileController_ = file;
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("SimSmsController fileController get null pointer");
    }
}

AppExecFwk::InnerEvent::Pointer SimSmsController::CreatePointer(int eventId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

bool SimSmsController::IsActionOn()
{
    return (g_CurAction == OBTAIN_SMS) || (g_CurAction == UPDATE_SMS) || (g_CurAction == WRITE_SMS) ||
        (g_CurAction == DELETE_SMS);
}

void SimSmsController::SetCurAction(Action_Type action)
{
    g_CurAction = action;
}

Action_Type SimSmsController::GetCurAction()
{
    return g_CurAction;
}

bool SimSmsController::PhoneTypeGsmOrNot() const
{
    return true;
}

SimSmsController::~SimSmsController() {}
} // namespace Telephony
} // namespace OHOS
