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

#include "sim_state_handle.h"
#include "inner_event.h"
#include "hilog/log.h"
#include "telephony_log.h"
#include "hril_sim_parcel.h"
#include "sim_constant.h"
#include "sim_state_manager.h"

using namespace OHOS::EventFwk;
namespace OHOS {
namespace SIM {
SimStateHandle::SimStateHandle(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, const std::weak_ptr<SimStateManager> &simStateManager)
    : AppExecFwk::EventHandler(runner), simStateManager_(simStateManager)
{
    TELEPHONY_INFO_LOG("SimStateHandle::SimStateHandle()");
}

void SimStateHandle::Init()
{
    rilManager_ = PhoneManager ::GetInstance().phone_[1]->rilManager_;
    if (rilManager_ != nullptr) {
        TELEPHONY_INFO_LOG("SimStateHandle::SimStateHandle RegisterEvent start");
        rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_ICC_STATUS_CHANGED, nullptr);
        rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_SMS_ON_SIM, nullptr);
        rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_ICC_REFRESH, nullptr);
    } else {
        TELEPHONY_INFO_LOG("SimStateHandle::SimStateHandle get ril_Manager fail");
        return;
    }
    // a sim card state;
    iccState_.resize(SIM_CARD_NUM);
    externalState_.resize(SIM_CARD_NUM);
}

bool SimStateHandle::HasSimCard(int slotId)
{
    TELEPHONY_INFO_LOG("SimStateHandle::HasSimCard(), mIccState_ = %{public}d", iccState_[slotId].cardState_);
    bool has = false;
    if (iccState_[slotId].cardState_ != ICC_CARD_ABSENT) {
        has = true;
    }
    TELEPHONY_INFO_LOG("SimStateHandle::HasSimCard(), has = %{public}d", has);
    return has;
}

int SimStateHandle::GetSimState(int slotId)
{
    TELEPHONY_INFO_LOG("SimStateHandle::GetSimState(), mExternalState_ = %{public}d ", externalState_[slotId]);
    return externalState_[slotId];
}

void SimStateHandle::ProcessIccCardState(IccState &ar, int index)
{
    TELEPHONY_INFO_LOG("SimStateHandle::ProcessIccCardState");
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    simStateManager->TestSimStateManager();
    // 1、Update current cardState
    iccState_[index].cardState_ = ar.cardState_;
    UpdateAppInfo(ar, index);
    UpdateIccState(ar, index);
    simStateManager->NotifyIccStateChanged();
}

void SimStateHandle::UpdateAppInfo(IccState &ar, int index)
{
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    iccState_[index].contentIndexOfGU_ = ar.contentIndexOfGU_;
    iccState_[index].contentIndexOfCdma_ = ar.contentIndexOfCdma_;
    iccState_[index].contentIndexOfIms_ = ar.contentIndexOfIms_;
    iccState_[index].pinState_ = ar.pinState_;
    iccState_[index].iccContentNum_ = ar.iccContentNum_;
}

void SimStateHandle::UpdateIccState(IccState &ar, int index)
{
    TELEPHONY_INFO_LOG("SimStateHandle::UpdateIccState() ");
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    int32_t iccStatus = ar.iccStatus_;
    int32_t cardState = ar.cardState_;
    TELEPHONY_INFO_LOG("SimStateHandle::UpdateIccState(), iccStatus=%{public}d ", iccStatus);
    if (cardState == ICC_CARD_ABSENT) {
        PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_ABSENT, "");
        return;
    }
    switch (iccStatus) {
        case ICC_CONTENT_READY:
            externalState_[index] = EX_READY;
            TELEPHONY_INFO_LOG("SimStateHandle::UpdateIccState(), EX_READY ");
            simStateManager->NotifyIccReady();
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_READY, "");
            break;
        case ICC_CONTENT_PIN:
            externalState_[index] = EX_PIN_LOCKED;
            TELEPHONY_INFO_LOG("SimStateHandle::UpdateIccState(), EX_PIN_LOCKED ");
            break;
        case ICC_CONTENT_PUK:
            externalState_[index] = EX_PUK_LOCKED;
            TELEPHONY_INFO_LOG("SimStateHandle::UpdateIccState(), EX_PUK_LOCKED ");
            break;
        case ICC_CONTENT_SIMLOCK:
            externalState_[index] = EX_NETWORK_LOCKED;
            TELEPHONY_INFO_LOG("SimStateHandle::UpdateIccState(), EX_NETWORK_LOCKED ");
            break;
        case ICC_CONTENT_DETECTED:
            ObtainIccStatus();
            break;
        case ICC_CONTENT_UNKNOWN:
            externalState_[index] = EX_UNKNOWN;
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_NOT_READY, "");
            TELEPHONY_INFO_LOG("SimStateHandle::UpdateIccState(), EX_APPSTATE_UNKNOWN[1] ");
            break;
        default:
            externalState_[index] = EX_UNKNOWN;
            TELEPHONY_INFO_LOG("SimStateHandle::UpdateIccState(), EX_APPSTATE_UNKNOWN[2] ");
            break;
    }
}

SimStateHandle::~SimStateHandle() {}

void SimStateHandle::ObtainIccStatus()
{
    static int delayCnt = 0;
    sleep(1);
    TELEPHONY_INFO_LOG("SimStateHandle::ObtainIccStatus(), delayCnt = %{public}d", delayCnt++);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_ICC_STATUS_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->GetSimStatus(event); // get sim card state
}

void SimStateHandle::GetSimCardData(const AppExecFwk::InnerEvent::Pointer &event, int phoneId)
{
    TELEPHONY_INFO_LOG("SimStateHandle::GetSimCardData");
    CardStatusInfo *param = event->GetSharedObject<CardStatusInfo>().get();
    if (param == nullptr) {
        TELEPHONY_INFO_LOG("SimStateHandle::GetSimCardData() fail");
        return;
    }

    IccState iccState;
    iccState.cardState_ = param->cardState;
    iccState.iccType_ = param->iccType;
    iccState.iccStatus_ = param->iccStatus;
    iccState.pinState_ = param->pinState;
    iccState.contentIndexOfGU_ = param->contentIndexOfGU;
    iccState.contentIndexOfCdma_ = param->contentIndexOfCdma;
    iccState.contentIndexOfIms_ = param->contentIndexOfIms;
    iccState.iccContentNum_ = param->iccContentNum;
    iccState.iccContent_.resize(iccState.iccContentNum_);
    for (int index = 0; index < param->iccContentNum; index++) {
        iccState.iccContent_[index].SimLockSubState_ = param->iccContentInfo[index].SimLockSubState;
        iccState.iccContent_[index].aid_ = param->iccContentInfo[index].aid;
        iccState.iccContent_[index].iccTag_ = param->iccContentInfo[index].iccTag;
        iccState.iccContent_[index].substitueOfPin1_ = param->iccContentInfo[index].substitueOfPin1;
        iccState.iccContent_[index].stateOfPin1_ = param->iccContentInfo[index].stateOfPin1;
        iccState.iccContent_[index].stateOfPin2_ = param->iccContentInfo[index].stateOfPin2;
        TELEPHONY_INFO_LOG("SimStateHandle, iccContent_[%{public}d].SimLockSubState_ = %{public}d", index,
            iccState.iccContent_[index].SimLockSubState_);
        TELEPHONY_INFO_LOG("SimStateHandle, iccContent_[%{public}d].aid_ = %{public}s", index,
            iccState.iccContent_[index].aid_.c_str());
        TELEPHONY_INFO_LOG("SimStateHandle, iccContent_[%{public}d].iccTag_ = %{public}s", index,
            iccState.iccContent_[index].iccTag_.c_str());
        TELEPHONY_INFO_LOG("SimStateHandle, iccContent_[%{public}d].substitueOfPin1_ = %{public}d", index,
            iccState.iccContent_[index].substitueOfPin1_);
        TELEPHONY_INFO_LOG("SimStateHandle, iccContent_[%{public}d].stateOfPin1_ = %{public}d", index,
            iccState.iccContent_[index].stateOfPin1_);
        TELEPHONY_INFO_LOG("SimStateHandle, iccContent_[%{public}d].stateOfPin2_ = %{public}d", index,
            iccState.iccContent_[index].stateOfPin2_);
    }
    ProcessIccCardState(iccState, phoneId);
}

void SimStateHandle::GetSmsData(const AppExecFwk::InnerEvent::Pointer &event, int phoneId)
{
    int *param = event->GetSharedObject<int>().get();
    if (param != nullptr) {
        TELEPHONY_INFO_LOG("SimStateHandle::GetSmsData(), param = %{public}d", *param);
    }
}

bool SimStateHandle::PublishSimStateEvent(std::string event, int eventCode, std::string eventData)
{
    Want want;
    want.SetAction(event);
    CommonEventData data;
    data.SetWant(want);
    data.SetCode(eventCode);
    data.SetData(eventData);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_INFO_LOG("SimStateHandle::PublishSimStateEvent result : %{public}d", publishResult);
    return publishResult;
}

void SimStateHandle::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int eventId = event->GetInnerEventId();
    int phoneId = 1;
    TELEPHONY_INFO_LOG("SimStateHandle::ProcessEvent(), eventId = %{public}d", eventId);
    switch (eventId) {
        case ObserverHandler::RADIO_ICC_STATUS_CHANGED:
            TELEPHONY_INFO_LOG("SimStateHandle::ProcessEvent(), RADIO_ICC_STATUS_CHANGED");
            ObtainIccStatus();
            break;
        case ObserverHandler::RADIO_STATE_CHANGED:
            TELEPHONY_INFO_LOG("SimStateHandle::ProcessEvent(), RADIO_STATE_CHANGED");
            break;
        case MSG_SIM_GET_ICC_STATUS_DONE:
            TELEPHONY_INFO_LOG("SimStateHandle::ProcessEvent(), MSG_SIM_GET_ICC_STATUS_DONE");
            GetSimCardData(event, phoneId);
            break;
        case ObserverHandler::RADIO_ICC_REFRESH:
            TELEPHONY_INFO_LOG("SimStateHandle::ProcessEvent(), RADIO_ICC_REFRESH");
            break;
        default:
            TELEPHONY_INFO_LOG("SimStateHandle::ProcessEvent(), unknown event");
            break;
    }
}
} // namespace SIM
} // namespace OHOS
