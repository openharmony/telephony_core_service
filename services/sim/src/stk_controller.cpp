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

#include "stk_controller.h"

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_publish_info.h"
#include "common_event_support.h"
#include "hril_types.h"
#include "radio_event.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const int32_t ICC_CARD_STATE_ABSENT = 0;
const int32_t ICC_CARD_STATE_PRESENT = 1;
const int32_t WAIT_TIME_SECOND = 2; // Set the timeout for sending the stk command
const std::string PARAM_SLOTID = "slotId";
const std::string PARAM_MSG_CMD = "msgCmd";
const std::string PARAM_CARD_STATUS = "cardStatus";
const std::string PARAM_ALPHA_STRING = "alphaString";
const std::string PARAM_REFRESH_RESULT = "refreshResult";
} // namespace

StkController::StkController(const std::weak_ptr<Telephony::ITelRilManager> &telRilManager,
    const std::weak_ptr<Telephony::SimStateManager> &simStateManager, int32_t slotId)
    : TelEventHandler("StkController"), telRilManager_(telRilManager), simStateManager_(simStateManager),
      slotId_(slotId)
{}

void StkController::Init()
{
    RegisterEvents();
}

void StkController::RegisterEvents()
{
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::RegisterEvents() telRilManager is nullptr", slotId_);
        return;
    }
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::RegisterEvents() simStateManager is nullptr", slotId_);
        return;
    }
    simStateManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_SESSION_END, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_PROACTIVE_COMMAND, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_ALPHA_NOTIFY, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_EVENT_NOTIFY, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_CALL_SETUP, nullptr);
    telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_ICC_REFRESH, nullptr);
}

void StkController::UnRegisterEvents()
{
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::UnRegisterEvents() telRilManager is nullptr", slotId_);
        return;
    }
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::UnRegisterEvents() simStateManager is nullptr", slotId_);
        return;
    }
    simStateManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_SESSION_END);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_PROACTIVE_COMMAND);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_ALPHA_NOTIFY);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_EVENT_NOTIFY);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_CALL_SETUP);
    telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_ICC_REFRESH);
}

void StkController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::ProcessEvent() event is nullptr", slotId_);
        return;
    }
    uint32_t id = event->GetInnerEventId();
    switch (id) {
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            OnIccStateChanged(event);
            break;
        case RadioEvent::RADIO_STK_SESSION_END:
            OnSendRilSessionEnd(event);
            break;
        case RadioEvent::RADIO_STK_PROACTIVE_COMMAND:
            OnSendRilProactiveCommand(event);
            break;
        case RadioEvent::RADIO_STK_ALPHA_NOTIFY:
            OnSendRilAlphaNotify(event);
            break;
        case RadioEvent::RADIO_STK_EVENT_NOTIFY:
            OnSendRilEventNotify(event);
            break;
        case RadioEvent::RADIO_STK_CALL_SETUP:
            TELEPHONY_LOGI("StkController[%{public}d]::ProcessEvent(),"
                " event notify command supplied all the information needed for set up call processing", slotId_);
            break;
        case RadioEvent::RADIO_ICC_REFRESH:
            OnIccRefresh(event);
            break;
        case RadioEvent::RADIO_STK_SEND_TERMINAL_RESPONSE:
            OnSendTerminalResponseResult(event);
            break;
        case RadioEvent::RADIO_STK_SEND_ENVELOPE:
            OnSendEnvelopeCmdResult(event);
            break;
        case RadioEvent::RADIO_STK_IS_READY:
            TELEPHONY_LOGI("StkController[%{public}d]::ProcessEvent() SimStkIsReady done", slotId_);
            break;
        case RadioEvent::RADIO_STK_SEND_CALL_SETUP_REQUEST_RESULT:
            OnSendCallSetupRequestResult(event);
            break;
        default:
            TELEPHONY_LOGE("StkController[%{public}d]::ProcessEvent() unknown event", slotId_);
            break;
    }
}

void StkController::OnIccStateChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnIccStateChanged() simStateManager is nullptr", slotId_);
        return;
    }
    int32_t newState = simStateManager->HasSimCard() ? ICC_CARD_STATE_PRESENT : ICC_CARD_STATE_ABSENT;
    int32_t oldState = iccCardState_;
    iccCardState_ = newState;
    TELEPHONY_LOGI("StkController[%{public}d]::OnIccStateChanged(), oldState: %{public}d newState: %{public}d",
        slotId_, oldState, newState);
    if (oldState == ICC_CARD_STATE_PRESENT && newState == ICC_CARD_STATE_ABSENT) {
        AAFwk::Want want;
        want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_CARD_STATE_CHANGED);
        want.SetParam(PARAM_SLOTID, slotId_);
        want.SetParam(PARAM_CARD_STATUS, iccCardState_);
        bool publishResult = PublishStkEvent(want);
        TELEPHONY_LOGI("StkController[%{public}d]::OnIccStateChanged() publishResult = %{public}d",
            slotId_, publishResult);
    } else if (oldState == ICC_CARD_STATE_ABSENT && newState == ICC_CARD_STATE_PRESENT) {
        TELEPHONY_LOGI("StkController[%{public}d]::OnIccStateChanged(), call SimStkIsReady()", slotId_);
        auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_IS_READY);
        if (event == nullptr) {
            TELEPHONY_LOGE("StkController[%{public}d]::OnIccStateChanged() event is nullptr", slotId_);
            return;
        }
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager == nullptr) {
            TELEPHONY_LOGE("StkController[%{public}d]::OnIccStateChanged() telRilManager is nullptr", slotId_);
            return;
        }
        telRilManager->SimStkIsReady(slotId_, event);
    }
}

void StkController::OnSendRilSessionEnd(const AppExecFwk::InnerEvent::Pointer &event) const
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_SESSION_END);
    want.SetParam(PARAM_SLOTID, slotId_);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendRilSessionEnd() publishResult = %{public}d",
        slotId_, publishResult);
}

void StkController::OnSendRilProactiveCommand(const AppExecFwk::InnerEvent::Pointer &event) const
{
    auto stkData = event->GetSharedObject<std::string>();
    if (stkData == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendRilProactiveCommand() stkData is nullptr", slotId_);
        return;
    }
    std::string cmdData = (std::string)*stkData;
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_COMMAND);
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_MSG_CMD, cmdData);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendRilProactiveCommand() stkData = %{public}s "
        "publishResult = %{public}d", slotId_, cmdData.c_str(), publishResult);
}

void StkController::OnSendRilAlphaNotify(const AppExecFwk::InnerEvent::Pointer &event) const
{
    auto alphaData = event->GetSharedObject<std::string>();
    if (alphaData == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendRilAlphaNotify() alphaData is nullptr", slotId_);
        return;
    }
    std::string cmdData = (std::string)*alphaData;
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_ALPHA_IDENTIFIER);
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_ALPHA_STRING, cmdData);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendRilAlphaNotify() alphaData = %{public}s "
        "publishResult = %{public}d", slotId_, cmdData.c_str(), publishResult);
}

void StkController::OnSendRilEventNotify(const AppExecFwk::InnerEvent::Pointer &event) const
{
    auto eventData = event->GetSharedObject<std::string>();
    if (eventData == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendRilEventNotify() eventData is nullptr", slotId_);
        return;
    }
    std::string cmdData = (std::string)*eventData;
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_COMMAND);
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_MSG_CMD, cmdData);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendRilEventNotify() eventData = %{public}s "
        "publishResult = %{public}d", slotId_, cmdData.c_str(), publishResult);
}

void StkController::OnIccRefresh(const AppExecFwk::InnerEvent::Pointer &event) const
{
    auto refreshResult = event->GetSharedObject<int32_t>();
    if (refreshResult == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnIccRefresh() refreshResult is nullptr", slotId_);
        return;
    }
    int32_t result = (int32_t)*refreshResult;
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_STK_CARD_STATE_CHANGED);
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_CARD_STATUS, ICC_CARD_STATE_PRESENT);
    want.SetParam(PARAM_REFRESH_RESULT, result);
    bool publishResult = PublishStkEvent(want);
    TELEPHONY_LOGI("StkController[%{public}d]::OnIccRefresh() refresh result = %{public}d publishResult = %{public}d",
        slotId_, result, publishResult);
}

bool StkController::PublishStkEvent(const AAFwk::Want &want) const
{
    EventFwk::CommonEventData data(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    return EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
}

int32_t StkController::SendTerminalResponseCmd(const std::string &strCmd)
{
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_TERMINAL_RESPONSE);
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendTerminalResponseCmd() event is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    event->SetOwner(shared_from_this());
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendTerminalResponseCmd() telRilManager is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::unique_lock<std::mutex> terminalResponselock(stkMutex_);
    terminalResponseResult_ = 0;
    responseFinished_ = false;
    telRilManager->SendTerminalResponseCmd(slotId_, strCmd, event);
    while (!responseFinished_) {
        TELEPHONY_LOGI("StkController[%{public}d]::SendTerminalResponseCmd() wait for the response to finish", slotId_);
        if (stkCv_.wait_for(terminalResponselock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            TELEPHONY_LOGE("StkController[%{public}d]::SendTerminalResponseCmd() wait timeout", slotId_);
            break;
        }
    }
    if (!responseFinished_) {
        TELEPHONY_LOGE("ril cmd fail");
        return TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t StkController::SendEnvelopeCmd(const std::string &strCmd)
{
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_ENVELOPE);
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendEnvelopeCmd() event is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    event->SetOwner(shared_from_this());
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendEnvelopeCmd() telRilManager is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::unique_lock<std::mutex> envelopelock(stkMutex_);
    envelopeResponseResult_ = 0;
    responseFinished_ = false;
    telRilManager->SendEnvelopeCmd(slotId_, strCmd, event);
    while (!responseFinished_) {
        TELEPHONY_LOGI("StkController[%{public}d]::SendEnvelopeCmd() wait for the response to finish", slotId_);
        if (stkCv_.wait_for(envelopelock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            TELEPHONY_LOGE("StkController[%{public}d]::SendEnvelopeCmd() wait timeout", slotId_);
            break;
        }
    }
    if (!responseFinished_) {
        TELEPHONY_LOGE("ril cmd fail");
        return TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

int32_t StkController::SendCallSetupRequestResult(bool accept)
{
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_STK_SEND_CALL_SETUP_REQUEST_RESULT);
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendCallSetupRequestResult() event is nullptr", slotId_);
        return TELEPHONY_ERR_FAIL;
    }
    event->SetOwner(shared_from_this());
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::SendCallSetupRequestResult() telRilManager is nullptr", slotId_);
        return TELEPHONY_ERR_FAIL;
    }

    std::unique_lock<std::mutex> callSetupRequestlock(stkMutex_);
    callSetupResponseResult_ = TELEPHONY_ERR_FAIL;
    responseFinished_ = false;
    telRilManager->SendCallSetupRequestResult(slotId_, accept, event);
    while (!responseFinished_) {
        TELEPHONY_LOGI(
            "StkController[%{public}d]::SendCallSetupRequestResult() wait for the response to finish", slotId_);
        if (stkCv_.wait_for(callSetupRequestlock, std::chrono::seconds(WAIT_TIME_SECOND)) == std::cv_status::timeout) {
            TELEPHONY_LOGE("StkController[%{public}d]::SendCallSetupRequestResult() wait timeout", slotId_);
            responseFinished_ = true;
        }
    }
    return callSetupResponseResult_;
}

void StkController::OnSendTerminalResponseResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendTerminalResponseResult() event is nullptr", slotId_);
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if (response == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendTerminalResponseResult() response is nullptr", slotId_);
        return;
    }
    terminalResponseResult_ = response->error == HRilErrType::NONE;
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendTerminalResponseResult(), result = %{public}d",
        slotId_, terminalResponseResult_);
    responseFinished_ = true;
    stkCv_.notify_one();
}

void StkController::OnSendEnvelopeCmdResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendEnvelopeCmdResult() event is nullptr", slotId_);
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if (response == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendEnvelopeCmdResult() response is nullptr", slotId_);
        return;
    }
    envelopeResponseResult_ = response->error == HRilErrType::NONE;
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendEnvelopeCmdResult(), result = %{public}d",
        slotId_, envelopeResponseResult_);
    responseFinished_ = true;
    stkCv_.notify_one();
}

void StkController::OnSendCallSetupRequestResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendCallSetupRequestResult() event is nullptr", slotId_);
        return;
    }
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if (response == nullptr) {
        TELEPHONY_LOGE("StkController[%{public}d]::OnSendCallSetupRequestResult() response is nullptr", slotId_);
        return;
    }
    callSetupResponseResult_ = response->error == HRilErrType::NONE ? TELEPHONY_ERR_SUCCESS : TELEPHONY_ERR_FAIL;
    TELEPHONY_LOGI("StkController[%{public}d]::OnSendCallSetupRequestResult(), result = %{public}d",
        slotId_, callSetupResponseResult_);
    responseFinished_ = true;
    stkCv_.notify_one();
}
} // namespace Telephony
} // namespace OHOS
