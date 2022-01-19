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
#include "radio_cap_controller.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
std::mutex RadioCapController::ctx_;
std::condition_variable RadioCapController::cv_;

RadioCapController::RadioCapController(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
    const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : AppExecFwk::EventHandler(runner), telRilManager_(telRilManager)
{
    if (runner != nullptr) {
        runner->Run();
    }
    InitMemberFunc();
    responseReady_ = false;
    maxCount_ = SIM_SLOT_COUNT;
    for (int32_t i = 0; i < maxCount_; i++) {
        SimProtocolRequest protocol;
        protocol.slotId = i;
        protocol.phase = INVALID_VALUE;
        protocol.protocol = MIN_PROTOCOL;
        oldProtocol_.emplace_back(protocol);
        newProtocol_.emplace_back(protocol);
    }
    ResetResponse();
}

RadioCapController::~RadioCapController() {}

void RadioCapController::InitMemberFunc()
{
    memberFuncMap_[RadioCapControllerConstant::MSG_SIM_TIME_OUT_PROTOCOL] =
        &RadioCapController::ProcessProtocolTimeOutDone;
    memberFuncMap_[RadioCapControllerConstant::MSG_SIM_SET_RADIO_PROTOCOL] =
        &RadioCapController::ProcessSetRadioProtocolDone;
    memberFuncMap_[RadioCapControllerConstant::MSG_SIM_UPDATE_RADIO_PROTOCOL] =
        &RadioCapController::ProcessUpdateRadioProtocolDone;
    memberFuncMap_[RadioCapControllerConstant::MSG_SIM_TIME_OUT_ACTIVE] =
        &RadioCapController::ProcessActiveSimTimeOutDone;
    memberFuncMap_[RadioCapControllerConstant::MSG_SIM_SET_ACTIVE] =
        &RadioCapController::ProcessActiveSimToRilResponse;
}

void RadioCapController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("RadioCapController::ProcessEvent");
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioCapController start ProcessEvent but event is null!");
        return;
    }
    auto id = event->GetInnerEventId();
    TELEPHONY_LOGI("RadioCapController::ProcessEvent id = %{public}d", id);
    auto itFunc = memberFuncMap_.find(id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc == nullptr) {
            TELEPHONY_LOGE("RadioCapController::ProcessEvent can not find function");
            return;
        }
        (this->*memberFunc)(event);
    }
}

void RadioCapController::RadioCapControllerWait()
{
    responseReady_ = false;
}

void RadioCapController::RadioCapControllerContinue()
{
    responseReady_ = true;
}

bool RadioCapController::RadioCapControllerPoll()
{
    return responseReady_;
}

bool RadioCapController::SetRadioProtocol(int32_t slotId, int32_t protocol)
{
    TELEPHONY_LOGI(
        "RadioCapController::SetRadioProtocol slotId = %{public}d, protocol = %{public}d", slotId, protocol);
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("RadioCapController::SetRadioProtocol nullptr");
        radioProtocolResponse_ = false;
        EndCommunicate();
        return false;
    }
    localSlot_ = slotId;
    localProtocol_ = protocol;
    if (count_ == CLEAR) {
        SendEvent(MSG_SIM_TIME_OUT_PROTOCOL, SET_PROTOCOL_OUT_TIME, Priority::LOW);
    }
    auto event = AppExecFwk::InnerEvent::Get(RadioCapControllerConstant::MSG_SIM_SET_RADIO_PROTOCOL);
    event->SetOwner(shared_from_this());
    if (count_ >= maxCount_) {
        TELEPHONY_LOGI("RadioCapController::SetRadioProtocol success");
        radioProtocolResponse_ = true;
        EndCommunicate();
        return true;
    }
    oldProtocol_[count_].phase = SET_PROTOCOL;
    TELEPHONY_LOGI("RadioCapController:: telRilManager_ SetRadioProtocol");
    telRilManager_->SetRadioProtocol(slotId, oldProtocol_[count_], event);
    ClearProtocolCache(newProtocol_[count_]);
    newProtocol_[count_].slotId = count_;
    if (slotId == count_) {
        newProtocol_[count_].protocol = protocol;
    } else {
        newProtocol_[count_].protocol = MIN_PROTOCOL;
    }
    return true;
}

void RadioCapController::ProcessSetRadioProtocolDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("RadioCapController::ProcessSetRadioProtocolDone");
    std::shared_ptr<SimProtocolResponse> param = event->GetSharedObject<SimProtocolResponse>();
    if (param == nullptr) {
        TELEPHONY_LOGE("RadioCapController::ProcessSetRadioProtocolDone() fail");
        EndCommunicate();
        return;
    }
    if (param->result == FAILED) {
        TELEPHONY_LOGE("RadioCapController::ProcessSetRadioProtocolDone() result fail");
        EndCommunicate();
        return;
    }
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("RadioCapController::ProcessSetRadioProtocolDone nullptr");
        return;
    }
    auto newEvent = AppExecFwk::InnerEvent::Get(RadioCapControllerConstant::MSG_SIM_UPDATE_RADIO_PROTOCOL);
    newEvent->SetOwner(shared_from_this());
    newProtocol_[param->slotId].phase = UPDATE_PROTOCOL;
    TELEPHONY_LOGI("RadioCapController::send again = %{public}d %{public}d %{public}d", param->slotId,
        newProtocol_[param->slotId].phase, newProtocol_[param->slotId].protocol);
    telRilManager_->SetRadioProtocol(param->slotId, newProtocol_[param->slotId], newEvent);
}

void RadioCapController::ProcessUpdateRadioProtocolDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("RadioCapController::SetRadioProtocol() update event is nullptr");
        EndCommunicate();
        return;
    }
    std::shared_ptr<SimProtocolResponse> param = event->GetSharedObject<SimProtocolResponse>();
    if (param == nullptr) {
        TELEPHONY_LOGE("RadioCapController::SetRadioProtocol() update fail");
        EndCommunicate();
        return;
    }
    TELEPHONY_LOGI("RadioCapController::ProcessUpdateRadioProtocolDone = %{public}d + %{public}d",
        param->slotId, param->result);
    if (param->result == SUCCEED) {
        oldProtocol_ = newProtocol_;
    }
    bool opposite = param->result;
    if (opposite) { // 0 means success , 1 means failed
        TELEPHONY_LOGE("RadioCapController::ProcessUpdateRadioProtocolDone abort");
        EndCommunicate();
        return;
    }
    count_++;
    if (!SetRadioProtocol(localSlot_, localProtocol_)) {
        TELEPHONY_LOGE("RadioCapController::SetRadioProtocol() update event is nullptr");
        EndCommunicate();
    }
}

void RadioCapController::ProcessProtocolTimeOutDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    radioProtocolResponse_ = false;
    RadioCapControllerContinue();
    cv_.notify_all();
}

void RadioCapController::ProcessActiveSimTimeOutDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("RadioCapController::ProcessActiveSimTimeOutDone");
    activeResponse_ = 1;
    RadioCapControllerContinue();
    cv_.notify_all();
}

bool RadioCapController::GetRadioProtocolResponse()
{
    return radioProtocolResponse_;
}

void RadioCapController::ClearProtocolCache(SimProtocolRequest &simProtocolRequest)
{
    simProtocolRequest.phase = INVALID_VALUE;
    simProtocolRequest.protocol = INVALID_VALUE;
}

void RadioCapController::EndCommunicate()
{
    RemoveEvent(MSG_SIM_TIME_OUT_PROTOCOL);
    RadioCapControllerContinue();
    count_ = CLEAR;
    cv_.notify_all();
}

void RadioCapController::ResetResponse()
{
    radioProtocolResponse_ = false;
}

bool RadioCapController::SetActiveSimToRil(int32_t slotId, int32_t type, int32_t enable)
{
    TELEPHONY_LOGI("RadioCapController::SetActiveSim(), enable=%{public}d", enable);
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("RadioCapController::SetActiveSim nullptr");
        return false;
    }
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_SET_ACTIVE);
    event->SetOwner(shared_from_this());
    SendEvent(MSG_SIM_TIME_OUT_ACTIVE, SET_ACTIVE_OUT_TIME, Priority::LOW);
    telRilManager_->SetActiveSim(slotId, type, enable, event);
    return true;
}

void RadioCapController::ProcessActiveSimToRilResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("RadioCapController::GetSetActiveSimResult");
    int32_t result = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("RadioCapController::GetSetActiveSimResult() fail");
        RadioCapControllerContinue();
        cv_.notify_all();
        return;
    }
    if (param != nullptr) {
        result = static_cast<int32_t>(*param);
    } else {
        result = static_cast<int32_t>(response->error);
    }
    TELEPHONY_LOGI("RadioCapController::GetSetActiveSimResult(), activeResponse = %{public}d", result);
    activeResponse_ = result;
    RadioCapControllerContinue();
    cv_.notify_all();
}

int32_t RadioCapController::GetActiveSimToRilResult()
{
    RemoveEvent(MSG_SIM_TIME_OUT_ACTIVE);
    return activeResponse_;
}
} // namespace Telephony
} // namespace OHOS
