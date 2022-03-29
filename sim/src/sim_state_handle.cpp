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

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "inner_event.h"
#include "system_ability_definition.h"

#include "hril_sim_parcel.h"
#include "sim_constant.h"
#include "sim_state_manager.h"
#include "telephony_log_wrapper.h"

using namespace OHOS::EventFwk;
namespace OHOS {
namespace Telephony {
SimStateHandle::SimStateHandle(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, const std::weak_ptr<SimStateManager> &simStateManager)
    : AppExecFwk::EventHandler(runner), simStateManager_(simStateManager)
{
    TELEPHONY_LOGD("SimStateHandle::SimStateHandle()");
}

void SimStateHandle::Init()
{
    ConnectService();
    rilManager_ = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetRilManager();
    if (rilManager_ != nullptr) {
        TELEPHONY_LOGD("SimStateHandle::SimStateHandle RegisterEvent start");
        rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_SIM_STATE_CHANGE, nullptr);
        rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_STATE_CHANGED, nullptr);
    } else {
        TELEPHONY_LOGE("SimStateHandle::SimStateHandle get ril_Manager fail");
        return;
    }
    // a sim card state;
    iccState_.resize(SIM_CARD_NUM);
    externalState_.resize(SIM_CARD_NUM);
}

bool SimStateHandle::HasSimCard(int slotId)
{
    bool has = false;
    if (iccState_[slotId].simStatus_ != ICC_CARD_ABSENT) {
        has = true;
    }
    TELEPHONY_LOGD("SimStateHandle::HasSimCard(), has = %{public}d", has);
    return has;
}

int SimStateHandle::GetSimState(int slotId)
{
    return externalState_[slotId];
}

void SimStateHandle::UnlockPin(std::string pin, int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::UnlockPin1()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PIN_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->EnterSimPin(pin, event);
}

void SimStateHandle::UnlockPuk(std::string newPin, std::string puk, int32_t phoneId)
{
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PUK_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->UnlockSimPin(puk, newPin, event);
}

void SimStateHandle::AlterPin(std::string newPin, std::string oldPin, int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::ChangePin1()");
    int32_t length = newPin.size();
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHANGE_PIN_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->ChangeSimPassword(FAC_PIN_LOCK, oldPin, newPin, length, event);
}

void SimStateHandle::UnlockRemain(int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::UnlockRemain()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_REMAIN_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->GetSimPinInputTimes(event);
}

void SimStateHandle::SetLockState(std::string pin, int32_t enable, int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::SetLockState()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_ENABLE_PIN_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->SetSimLock(FAC_PIN_LOCK, enable, pin, event);
}

void SimStateHandle::GetLockState(int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::GetLockState()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHECK_PIN_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->GetSimLockStatus(FAC_PIN_LOCK, event);
}

void SimStateHandle::ProcessIccCardState(IccState &ar, int index)
{
    TELEPHONY_LOGD("SimStateHandle::ProcessIccCardState");
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    // 1、Update current cardState
    iccState_[index].simStatus_ = ar.simStatus_;
    UpdateIccState(ar, index);
    if (simStateManager != nullptr) {
        simStateManager->NotifyIccStateChanged();
    }
}

void SimStateHandle::UpdateIccState(IccState &ar, int index)
{
    TELEPHONY_LOGD("SimStateHandle::UpdateIccState() ");
    std::u16string reason = u"";
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    int32_t simType = ar.simType_;
    int32_t simState = ar.simStatus_;
    TELEPHONY_LOGD(
        "SimStateHandle::UpdateIccState(), iccStatus=%{public}d, simType = %{public}d", simState, simType);
    switch (simState) {
        case ICC_CARD_ABSENT:
            externalState_[index] = EX_ABSENT;
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_ABSENT, "");
            break;
        case ICC_CONTENT_READY:
            externalState_[index] = EX_READY;
            TELEPHONY_LOGD("SimStateHandle::UpdateIccState(), EX_READY ");
            simStateManager->NotifyIccReady();
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_READY, "");
            break;
        case ICC_CONTENT_PIN:
            externalState_[index] = EX_PIN_LOCKED;
            TELEPHONY_LOGD("SimStateHandle::UpdateIccState(), EX_PIN_LOCKED ");
            simStateManager->NotifyIccLock();
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_PIN, "");
            break;
        case ICC_CONTENT_PUK:
            externalState_[index] = EX_PUK_LOCKED;
            TELEPHONY_LOGD("SimStateHandle::UpdateIccState(), EX_PUK_LOCKED ");
            simStateManager->NotifyIccLock();
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_PUK, "");
            break;
        case ICC_CONTENT_SIMLOCK:
            externalState_[index] = EX_SIMLOCK;
            TELEPHONY_LOGD("SimStateHandle::UpdateIccState(), EX_SIMLOCK ");
            simStateManager->NotifyIccSimLock();
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_SIMLOCK, "");
            break;
        case ICC_CONTENT_UNKNOWN:
            externalState_[index] = EX_UNKNOWN;
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_NOT_READY, "");
            TELEPHONY_LOGD("SimStateHandle::UpdateIccState(), EX_APPSTATE_UNKNOWN[1] ");
            break;
        default:
            externalState_[index] = EX_UNKNOWN;
            TELEPHONY_LOGD("SimStateHandle::UpdateIccState(), EX_APPSTATE_UNKNOWN[2] ");
            break;
    }
    if (telephonyStateNotify_ != nullptr) {
        telephonyStateNotify_->UpdateSimState(index, externalState_[index], reason);
    }
}

SimStateHandle::~SimStateHandle() {}

void SimStateHandle::ObtainIccStatus()
{
    TELEPHONY_LOGD("SimStateHandle::ObtainIccStatus()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_ICC_STATUS_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->GetSimStatus(event); // get sim card state
}

void SimStateHandle::ObtainRealtimeIccStatus()
{
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_REALTIME_ICC_STATUS_DONE);
    event->SetOwner(shared_from_this());
    rilManager_->GetSimStatus(event); // get sim card state
}

void SimStateHandle::GetSimCardData(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::GetSimCardData");
    int32_t error = 0;
    IccState iccState;
    std::shared_ptr<CardStatusInfo> param = event->GetSharedObject<CardStatusInfo>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSimCardData() fail");
        return;
    }
    if (param) {
        iccState.simType_ = param->simType;
        iccState.simStatus_ = param->simState;
        TELEPHONY_LOGD("SimStateHandle::GetSimCardData(), simType_ = %{public}d", iccState.simType_);
        TELEPHONY_LOGD("SimStateHandle::GetSimCardData(), simStatus_ = %{public}d", iccState.simStatus_);
    } else {
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGD("SimStateHandle::GetSimCardData(), error = %{public}d", error);
    }
    ProcessIccCardState(iccState, phoneId);
}

void SimStateHandle::GetSimLockState(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::GetSimLockState");
    int32_t error = 0;
    std::shared_ptr<int32_t> param = event->GetSharedObject<int32_t>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSimLockState() fail");
        return;
    }
    if (param) {
        TELEPHONY_LOGD("SimStateHandle::GetSimLockState(), param = %{public}d", *param);
        unlockRespon_.lockState = *param;
    } else {
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGD("SimStateHandle::GetSimLockState(), error = %{public}d", error);
    }
}

void SimStateHandle::GetSetLockResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::GetSetLockResult");
    int32_t iccUnlockResponse = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSetLockResult() fail");
        return;
    }
    if (param) {
        iccUnlockResponse = static_cast<int32_t>(*param);
    } else {
        iccUnlockResponse = static_cast<int32_t>(response->error);
    }
    unlockRespon_.result = iccUnlockResponse;
    TELEPHONY_LOGD("SimStateHandle::GetSetLockResult(), iccUnlockResponse = %{public}d", iccUnlockResponse);
}

void SimStateHandle::GetUnlockReult(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::GetUnlockResult");
    int32_t iccUnlockResponse = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSimUnlockResult() fail");
        return;
    }
    if (param) {
        iccUnlockResponse = static_cast<int32_t>(*param);
    } else {
        iccUnlockResponse = static_cast<int32_t>(response->error);
    }
    unlockRespon_.result = iccUnlockResponse;
    TELEPHONY_LOGD("SimStateHandle::GetSimUnlockResponse(), iccUnlockResponse = %{public}d", iccUnlockResponse);
}

void SimStateHandle::GetUnlockRemain(const AppExecFwk::InnerEvent::Pointer &event, int32_t phoneId)
{
    TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain");
    SimPinInputTimes iccRemain;
    int32_t error = 0;
    std::shared_ptr<SimPinInputTimes> param = event->GetSharedObject<SimPinInputTimes>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetUnlockRemain() fail");
        return;
    }
    if (param) {
        iccRemain.serial = param->serial;
        iccRemain.code = param->code;
        iccRemain.times = param->times;
        iccRemain.pukTimes = param->pukTimes;
        iccRemain.pinTimes = param->pinTimes;
        iccRemain.puk2Times = param->puk2Times;
        iccRemain.pin2Times = param->pin2Times;
        TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain(), serial = %{public}d", iccRemain.serial);
        TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain(), codeType = %{public}s", iccRemain.code.c_str());
        TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain(), currentTimes = %{public}d", iccRemain.times);
        TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain(), pukTimes = %{public}d", iccRemain.pukTimes);
        TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain(), pinTimes = %{public}d", iccRemain.pinTimes);
        TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain(), puk2Times = %{public}d", iccRemain.puk2Times);
        TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain(), pin2Times = %{public}d", iccRemain.pin2Times);
        unlockRespon_.remain = iccRemain.times;
        unlockRespon_.pinRemain = iccRemain.pinTimes;
    } else {
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGD("SimStateHandle::GetUnlockRemain(), error = %{public}d", error);
    }
}

UnlockData SimStateHandle::GetUnlockData()
{
    return unlockRespon_;
}

void SimStateHandle::SyncCmdResponse()
{
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    std::unique_lock<std::mutex> lck(simStateManager->ctx_);
    simStateManager->responseReady_ = true;
    TELEPHONY_LOGD(
        "SimStateHandle::SyncCmdResponse(), responseReady_ = %{public}d", simStateManager->responseReady_);
    simStateManager->cv_.notify_one();
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
    TELEPHONY_LOGD("SimStateHandle::PublishSimStateEvent result : %{public}d", publishResult);
    return publishResult;
}

void SimStateHandle::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int eventId = event->GetInnerEventId();
    int phoneId = CUR_VALID_PHONEID;
    TELEPHONY_LOGD("SimStateHandle::ProcessEvent(), eventId = %{public}d", eventId);
    switch (eventId) {
        case ObserverHandler::RADIO_STATE_CHANGED:
        case ObserverHandler::RADIO_SIM_STATE_CHANGE:
            ObtainIccStatus();
            break;
        case MSG_SIM_GET_ICC_STATUS_DONE:
            GetSimCardData(event, phoneId);
            break;
        case MSG_SIM_UNLOCK_PIN_DONE:
        case MSG_SIM_UNLOCK_PUK_DONE:
        case MSG_SIM_CHANGE_PIN_DONE:
            GetUnlockReult(event, phoneId);
            SyncCmdResponse();
            break;
        case MSG_SIM_UNLOCK_REMAIN_DONE:
            GetUnlockRemain(event, phoneId);
            SyncCmdResponse();
            break;
        case MSG_SIM_ENABLE_PIN_DONE:
            GetSetLockResult(event, phoneId);
            SyncCmdResponse();
            break;
        case MSG_SIM_CHECK_PIN_DONE:
            GetSimLockState(event, phoneId);
            SyncCmdResponse();
            break;
        case MSG_SIM_GET_REALTIME_ICC_STATUS_DONE:
            GetSimCardData(event, phoneId);
            SyncCmdResponse();
            break;
        default:
            TELEPHONY_LOGD("SimStateHandle::ProcessEvent(), unknown event");
            break;
    }
}

bool SimStateHandle::ConnectService()
{
    auto systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::ConnectService() GetSystemAbilityManager() null\n");
        return false;
    }

    sptr<IRemoteObject> object = systemManager->GetSystemAbility(TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID);

    if (object != nullptr) {
        TELEPHONY_LOGD("SimStateHandle::ConnectService() IRemoteObject not null\n");
        telephonyStateNotify_ = iface_cast<ITelephonyStateNotify>(object);
    }

    if (telephonyStateNotify_ == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::ConnectService() telephonyStateNotify_ null\n");
        return false;
    }
    TELEPHONY_LOGD("SimStateHandle::ConnectService() success\n");
    return true;
}
} // namespace Telephony
} // namespace OHOS
