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
std::mutex SimSmsController::mtx_;
constexpr static const int32_t WAIT_TIME_SECOND = 1;
constexpr static const int32_t WAIT_TIME_TEN_SECOND = 10;

SimSmsController::SimSmsController(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<SimStateManager> simStateManager)
    : AppExecFwk::EventHandler(runner), stateManager_(simStateManager)
{}

void SimSmsController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("SimSmsController ProcessEvent event is nullptr");
        return;
    }
    uint32_t id = event->GetInnerEventId();
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
    if (event == nullptr) {
        TELEPHONY_LOGE("SimSmsController ProcessLoadDone event is nullptr");
        return;
    }
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
            for (std::string str : object->fileResults) {
                TELEPHONY_LOGI("SimSmsController::ProcessLoadDone: %{public}s", str.c_str());
            }
        } else {
            TELEPHONY_LOGE("ProcessLoadDone: get null pointer!!!");
        }
    }
    loadDone_ = true;
    processWait_.notify_all();
}

void SimSmsController::ProcessUpdateDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("SimSmsController ProcessUpdateDone event is nullptr");
        return;
    }
    responseReady_ = true;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("SimSmsController::ProcessUpdateDone error %{public}d", responseInfo->error);
        responseReady_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("SimSmsController::ProcessUpdateDone: end");
    processWait_.notify_all();
}

void SimSmsController::ProcessWriteDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("SimSmsController ProcessWriteDone event is nullptr");
        return;
    }
    responseReady_ = true;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("SimSmsController::ProcessWriteDone error %{public}d", responseInfo->error);
        responseReady_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("SimSmsController::ProcessWriteDone: end");
    processWait_.notify_all();
}

void SimSmsController::ProcessDeleteDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("SimSmsController ProcessDeleteDone event is nullptr");
        return;
    }
    responseReady_ = true;
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = event->GetSharedObject<HRilRadioResponseInfo>();
    if (responseInfo != nullptr) {
        TELEPHONY_LOGE("SimSmsController::ProcessDeleteDone error %{public}d", responseInfo->error);
        responseReady_ = (responseInfo->error == HRilErrType::NONE);
    }
    TELEPHONY_LOGI("SimSmsController::ProcessDeleteDone: end");
    processWait_.notify_all();
}

bool SimSmsController::UpdateSmsIcc(int index, int status, std::string &pduData, std::string &smsc)
{
    std::unique_lock<std::mutex> lock(mtx_);
    bool isCDMA = IsCdmaCardType();
    TELEPHONY_LOGI("UpdateSmsIcc start: %{public}d, %{public}d", index, isCDMA);
    responseReady_ = false;
    if (!isCDMA) {
        AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(SIM_SMS_UPDATE_COMPLETED);
        SimMessageParam param {index, status, smsc, pduData};
        telRilManager_->UpdateSimMessage(slotId_, param, response);
    } else {
        AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(SIM_SMS_UPDATE_COMPLETED);
        CdmaSimMessageParam param {index, status, pduData};
        telRilManager_->UpdateCdmaSimMessage(slotId_, param, response);
    }
    while (!responseReady_) {
        TELEPHONY_LOGI("UpdateSmsIcc::wait(), response = false");
        if (processWait_.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    TELEPHONY_LOGI("SimSmsController::UpdateSmsIcc OK return %{public}d", responseReady_);
    return responseReady_;
}

bool SimSmsController::DelSmsIcc(int index)
{
    std::unique_lock<std::mutex> lock(mtx_);
    bool isCDMA = IsCdmaCardType();
    TELEPHONY_LOGI("DelSmsIcc start: %{public}d, %{public}d", index, isCDMA);
    responseReady_ = false;
    if (!isCDMA) {
        AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(SIM_SMS_DELETE_COMPLETED);
        telRilManager_->DelSimMessage(slotId_, index, response);
        TELEPHONY_LOGI("SimSmsController::DelSmsIcc OK return %{public}d", responseReady_);
    } else {
        AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(SIM_SMS_DELETE_COMPLETED);
        telRilManager_->DelCdmaSimMessage(slotId_, index, response);
        TELEPHONY_LOGI("SimSmsController::DelCdmaSimMessage OK return %{public}d", responseReady_);
    }
    while (!responseReady_) {
        TELEPHONY_LOGI("DelSmsIcc::wait(), response = false");
        if (processWait_.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    return responseReady_;
}

bool SimSmsController::AddSmsToIcc(int status, std::string &pdu, std::string &smsc)
{
    std::unique_lock<std::mutex> lock(mtx_);
    bool isCDMA = IsCdmaCardType();
    TELEPHONY_LOGI("AddSmsToIcc start: %{public}d, %{public}d", status, isCDMA);
    responseReady_ = false;
    if (!isCDMA) {
        AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(SIM_SMS_WRITE_COMPLETED);
        SimMessageParam param {0, status, smsc, pdu};
        telRilManager_->AddSimMessage(slotId_, param, response);
    } else {
        AppExecFwk::InnerEvent::Pointer response = BuildCallerInfo(SIM_SMS_WRITE_COMPLETED);
        telRilManager_->AddCdmaSimMessage(slotId_, status, pdu, response);
    }
    while (!responseReady_) {
        TELEPHONY_LOGI("AddSmsToIcc::wait(), response = false");
        if (processWait_.wait_for(lock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    TELEPHONY_LOGI("SimSmsController::AddSmsToIcc OK return %{public}d", responseReady_);
    return responseReady_;
}

void SimSmsController::Init(int slodId)
{
    slotId_ = slodId;
}

std::vector<std::string> SimSmsController::ObtainAllSmsOfIcc()
{
    std::unique_lock<std::mutex> lock(mtx_);
    std::shared_ptr<IccFileController> fileController = fileManager_->GetIccFileController();
    loadDone_ = false;
    if (fileController == nullptr) {
        TELEPHONY_LOGE("Cannot load Sms records. No icc card?");
        std::vector<std::string> nullVector;
        smsList_.swap(nullVector);
        return smsList_;
    }
    TELEPHONY_LOGI("ObtainAllSmsOfIcc start!!");
    AppExecFwk::InnerEvent::Pointer event = BuildCallerInfo(SIM_SMS_GET_COMPLETED);
    fileController->ObtainAllLinearFixedFile(ELEMENTARY_FILE_SMS, event);
    while (!loadDone_) {
        TELEPHONY_LOGI("ObtainAllSmsOfIcc::wait(), response = false");
        if (processWait_.wait_for(lock, std::chrono::seconds(WAIT_TIME_TEN_SECOND)) == std::cv_status::timeout) {
            break;
        }
    }
    TELEPHONY_LOGI("SimSmsController::ObtainAllSmsOfIcc: end");
    return smsList_;
}

void SimSmsController::SetRilAndFileManager(
    std::shared_ptr<Telephony::ITelRilManager> ril, std::shared_ptr<SimFileManager> fileMgr)
{
    telRilManager_ = ril;
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("SimSmsController rilmanager get null pointer");
    }
    fileManager_ = fileMgr;
    if (fileManager_ == nullptr) {
        TELEPHONY_LOGE("SimSmsController fileManager get null pointer");
    }
}

AppExecFwk::InnerEvent::Pointer SimSmsController::BuildCallerInfo(int eventId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

bool SimSmsController::IsCdmaCardType() const
{
    bool isCdmaType = false;
    if (stateManager_ != nullptr) {
        CardType type = stateManager_->GetCardType();
        TELEPHONY_LOGI("IsCdmaCardType card type id %{public}d", type);
        if (type == CardType::SINGLE_MODE_RUIM_CARD) {
            isCdmaType = true; // cdma
        }
    }
    TELEPHONY_LOGI("IsCdmaCardType result %{public}d", isCdmaType);
    return isCdmaType;
}

SimSmsController::~SimSmsController() {}
} // namespace Telephony
} // namespace OHOS
