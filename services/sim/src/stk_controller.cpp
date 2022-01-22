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
#include "telephony_log_wrapper.h"
#include "common_event_data.h"
#include "common_event_publish_info.h"
#include "common_event_manager.h"
#include "hril_types.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
StkController::StkController(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner) : AppExecFwk::EventHandler(runner)
{
    TELEPHONY_LOGI("StkController::StkController()");
    iccCardState_ = ICC_CARD_STATE_ABSENT;
}

StkController::~StkController()
{
    UnRegisterEvents();
}

void StkController::Init(int slotId)
{
    TELEPHONY_LOGI("StkController::Init() started ");
    slotId_ = slotId;
    RegisterEvents();
    TELEPHONY_LOGI("StkController::Init() end");
}

void StkController::RegisterEvents()
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("StkController:: RegisterEvents TelRilManager is null");
        return;
    }
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("StkController:: RegisterEvents SimStateManager is null");
        return;
    }
    TELEPHONY_LOGI("StkController:: RegisterEvent start");
    simStateManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    telRilManager_->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_SESSION_END, nullptr);
    telRilManager_->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_PROACTIVE_COMMAND, nullptr);
    telRilManager_->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_ALPHA_NOTIFY, nullptr);
    TELEPHONY_LOGI("StkController:: RegisterEvent end");
}

void StkController::UnRegisterEvents()
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("StkController:: UnRegisterEvents TelRilManager is null");
        return;
    }
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("StkController:: UnRegisterEvents SimStateManager is null");
        return;
    }
    TELEPHONY_LOGI("StkController:: UnRegisterEvent start");
    simStateManager_->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    telRilManager_->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_SESSION_END);
    telRilManager_->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_PROACTIVE_COMMAND);
    telRilManager_->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STK_ALPHA_NOTIFY);
    TELEPHONY_LOGI("StkController:: UnRegisterEvent end");
}

void StkController::SetRilAndSimStateManager(std::shared_ptr<Telephony::ITelRilManager> ril,
    const std::shared_ptr<Telephony::SimStateManager> simstateMgr)
{
    telRilManager_ = ril;
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("StkController set NULL TelRilManager!!");
    }
    simStateManager_ = simstateMgr;
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("StkController set NULL SimStateManager!!");
    }
}

bool StkController::OnsendRilSessionEnd(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("StkController::OnsendRilSessionEnd(), publish to STK APP.");

    AAFwk::Want want;
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetAction(ACTION_SESSION_END);
    int32_t eventCode = 1;
    std::string eventData("OnsendRilSessionEnd");
    return PublishStkEvent(want, eventCode, eventData);
}

bool StkController::OnsendRilProactiveCommand(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("StkController::OnsendRilProactiveCommand(), publish to STK APP.");

    if (event == nullptr) {
        TELEPHONY_LOGE("StkController::OnsendRilProactiveCommand(), event nullptr!!!!!!");
        return false;
    }

    auto stkData = event->GetSharedObject<std::string>();
    if (stkData == nullptr) {
        TELEPHONY_LOGE("StkController::OnsendRilProactiveCommand(), event nullptr!!!!!!");
        return false;
    }

    AAFwk::Want want;
    EventFwk::CommonEventData data;
    std::string cmdData = (std::string)*stkData;
    TELEPHONY_LOGI("StkController::OnsendRilProactiveCommand() command data package = %{public}s\n", cmdData.c_str());
    // want
    want.SetParam(PARAM_SLOTID, slotId_);
    want.SetParam(PARAM_MSG_CMD, cmdData);
    want.SetAction(ACTION_STK_COMMAND);

    // event code and event data
    int32_t eventCode = EVENT_CODE;
    std::string eventData("OnsendRilProactiveCommand");

    bool publishResult = PublishStkEvent(want, eventCode, eventData);
    TELEPHONY_LOGI("StkController::ProacitveCommand end\npublishResult = %{public}d\n", publishResult);

    return true;
}

bool StkController::OnsendRilAlphaNotify(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("StkController::OnsendRilAlphaNotify(), publish to STK APP.");
    return false;
}

bool StkController::OnIccStateChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("StkController::OnIccStateChanged(), publish to STK APP.");
    bool hasCard = simStateManager_->HasSimCard();
    TELEPHONY_LOGI("StkController::OnIccStateChanged(), hasCard: %{public}d\n", hasCard);
    int32_t newState = hasCard ? ICC_CARD_STATE_PRESENT : ICC_CARD_STATE_ABSENT;
    int32_t oldState = iccCardState_;
    iccCardState_ = newState;
    if ((oldState == ICC_CARD_STATE_PRESENT) && (newState == ICC_CARD_STATE_ABSENT)) {
        AAFwk::Want want;
        EventFwk::CommonEventData data;
        // want
        want.SetParam(PARAM_SLOTID, slotId_);
        want.SetParam(PARAM_CARD_STATUS, newState);
        want.SetAction(ACTION_CARD_STATUS_INFORM);

        // event code and event data
        int32_t eventCode = EVENT_CODE;
        std::string eventData("OnIccStateChanged");

        bool publishResult = PublishStkEvent(want, eventCode, eventData);
        TELEPHONY_LOGI("StkController::OnIccStateChanged end ### publishResult = %{public}d\n", publishResult);
    } else if ((oldState == ICC_CARD_STATE_ABSENT) && (newState == ICC_CARD_STATE_PRESENT)) {
        TELEPHONY_LOGI("StkController::OnIccStateChanged(), call SimStkIsReady()");
        auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_STK_IS_READY);
        event->SetOwner(shared_from_this());
        telRilManager_->SimStkIsReady(slotId_, event);
    }
    return true;
}

bool StkController::PublishStkEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData)
{
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetCode(eventCode);
    data.SetData(eventData);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("StkController::PublishStkEvent end###publishResult = %{public}d\n", publishResult);
    return publishResult;
}

void StkController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int id = 0;
    id = event->GetInnerEventId();
    TELEPHONY_LOGI("StkController ProcessEvent Id is %{public}d", id);
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    switch (id) {
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            OnIccStateChanged(event);
            break;
        case RadioEvent::RADIO_STK_SESSION_END:
            OnsendRilSessionEnd(event);
            break;
        case RadioEvent::RADIO_STK_PROACTIVE_COMMAND:
            OnsendRilProactiveCommand(event);
            break;
        case RadioEvent::RADIO_STK_ALPHA_NOTIFY:
            OnsendRilAlphaNotify(event);
            break;
        case MSG_SIM_STK_TERMINAL_RESPONSE:
            TELEPHONY_LOGI("StkController::SendTerminalResponseCmd done.");
            GetTerminalResponseResult(event);
            break;
        case MSG_SIM_STK_ENVELOPE:
            TELEPHONY_LOGI("StkController::SendEnvelopeCmd done.");
            GetEnvelopeCmdResult(event);
            break;
        case MSG_SIM_STK_IS_READY:
            TELEPHONY_LOGI("StkController::SimStkIsReady done.");
            break;
        default:
            TELEPHONY_LOGI("StkController::ProcessEvent(), unknown event");
            break;
    }
}

bool StkController::SendTerminalResponseCmd(int32_t slotId, const std::string &strCmd)
{
    TELEPHONY_LOGI("StkController::SendTerminalResponseCmd");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_STK_TERMINAL_RESPONSE);
    event->SetOwner(shared_from_this());
    std::unique_lock<std::mutex> lck(ctx_);
    responseReady_ = false;

    if (telRilManager_ != nullptr) {
        telRilManager_->SendTerminalResponseCmd(slotId_, strCmd, event);
    }
    while (!responseReady_) {
        TELEPHONY_LOGI("StkController::wait(), response = false");
        cv_.wait(lck);
    }
    return terminalResponse_;
}

bool StkController::SendEnvelopeCmd(int32_t slotId, const std::string &strCmd)
{
    TELEPHONY_LOGI("StkController::SendEnvelopeCmd");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_STK_ENVELOPE);
    event->SetOwner(shared_from_this());
    std::unique_lock<std::mutex> lck(ctx_);
    responseReady_ = false;
    if (telRilManager_ != nullptr) {
        telRilManager_->SendEnvelopeCmd(slotId, strCmd, event);
    }
    while (!responseReady_) {
        TELEPHONY_LOGI("StkController::wait(), response = false");
        cv_.wait(lck);
    }
    return envelopeResponse_;
}

void StkController::GetTerminalResponseResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("StkController::GetTerminalResponseResult");
    int32_t result = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("StkController::GetTerminalResponseResult() fail");
        return;
    }
    if (param) {
        result = static_cast<int32_t>(*param);
    } else {
        result = static_cast<int32_t>(response->error);
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGI("StkController::GetTerminalResponseResult(), error = %{public}d", result);
    terminalResponse_ = result ? false : true;
    responseReady_ = true;
    cv_.notify_one();
}

void StkController::GetEnvelopeCmdResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("StkController::GetEnvelopeCmdResult");
    int32_t result = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("StkController::GetEnvelopeCmdResult() fail");
        return;
    }
    if (param) {
        result = static_cast<int32_t>(*param);
    } else {
        result = static_cast<int32_t>(response->error);
    }
    std::unique_lock<std::mutex> lck(ctx_);
    TELEPHONY_LOGI("StkController::GetEnvelopeCmdResult(), error = %{public}d", result);
    envelopeResponse_ = result ? false : true;
    responseReady_ = true;
    cv_.notify_one();
}
} // namespace Telephony
} // namespace OHOS
