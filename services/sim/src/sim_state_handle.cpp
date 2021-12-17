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
#include "hilog/log.h"
#include "hril_sim_parcel.h"
#include "sim_constant.h"
#include "sim_state_manager.h"
#include "telephony_log_wrapper.h"

using namespace OHOS::EventFwk;
namespace OHOS {
namespace Telephony {
std::mutex SimStateManager::ctx_;
bool SimStateManager::responseReady_ = false;
std::condition_variable SimStateManager::cv_;

SimStateHandle::SimStateHandle(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, const std::weak_ptr<SimStateManager> &simStateManager)
    : AppExecFwk::EventHandler(runner), simStateManager_(simStateManager)
{
    TELEPHONY_LOGI("SimStateHandle::SimStateHandle()");
}

void SimStateHandle::Init()
{
    ConnectService();
    if (telRilManager_ != nullptr) {
        TELEPHONY_LOGI("SimStateHandle::SimStateHandle RegisterEvent start");
        telRilManager_->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_STATE_CHANGE, nullptr);
        telRilManager_->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_STATE_CHANGED, nullptr);
    } else {
        TELEPHONY_LOGE("SimStateHandle::SimStateHandle get ril_Manager fail");
        return;
    }
    // a sim card state;
    iccState_.resize(SIM_CARD_NUM);
    externalState_.resize(SIM_CARD_NUM);
    observerHandler_ = std::make_unique<ObserverHandler>();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::failed to create new ObserverHandler");
        return;
    }
}

bool SimStateHandle::HasSimCard(int slotId)
{
    bool has = false;
    if (iccState_.size() <= slotId) {
        TELEPHONY_LOGE("SimStateHandle::HasSimCard Invalid slotId");
        return has;
    }
    if (iccState_[slotId].simState_ != ICC_CARD_ABSENT) {
        has = true;
    }
    TELEPHONY_LOGI("SimStateHandle::HasSimCard(), has = %{public}d", has);
    return has;
}

SimState SimStateHandle::GetSimState(int slotId)
{
    return externalState_[slotId];
}

void SimStateHandle::UnlockPin(int32_t slotId, std::string pin)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPin1()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PIN_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->UnlockPin(pin, event);
}

void SimStateHandle::UnlockPuk(int32_t slotId, std::string newPin, std::string puk)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPuk1()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PUK_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->UnlockPuk(puk, newPin, event);
}

void SimStateHandle::AlterPin(int32_t slotId, std::string newPin, std::string oldPin)
{
    TELEPHONY_LOGI("SimStateHandle::AlterPin()");
    int32_t length = newPin.size();
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHANGE_PIN_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->ChangeSimPassword(FAC_PIN_LOCK, oldPin, newPin, length, event);
}

void SimStateHandle::UnlockPin2(int32_t slotId, std::string pin2)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPin2()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PIN2_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->UnlockPin2(pin2, event);
}

void SimStateHandle::UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPuk2()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PUK2_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->UnlockPuk2(puk2, newPin2, event);
}

void SimStateHandle::AlterPin2(int32_t slotId, std::string newPin2, std::string oldPin2)
{
    TELEPHONY_LOGI("SimStateHandle::AlterPin2()");
    int32_t length = newPin2.size();
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHANGE_PIN2_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->ChangeSimPassword(FDN_PIN_LOCK, oldPin2, newPin2, length, event);
}

void SimStateHandle::UnlockRemain(int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockRemain()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_REMAIN_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->GetSimPinInputTimes(event);
}

void SimStateHandle::SetLockState(int32_t slotId, std::string pin, int32_t enable)
{
    TELEPHONY_LOGI("SimStateHandle::SetLockState()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_ENABLE_PIN_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->SetSimLock(FAC_PIN_LOCK, enable, pin, event);
}

void SimStateHandle::SetActiveSim(int32_t slotId, int32_t type, int32_t enable)
{
    TELEPHONY_LOGI("SimStateHandle::SetActiveSim(), enable=%{public}d", enable);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_SET_ACTIVE_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->SetActiveSim(type, enable, event);
}

void SimStateHandle::SetRilManager(std::shared_ptr<Telephony::ITelRilManager> telRilManager)
{
    telRilManager_ = telRilManager;
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("SimStateHandle set NULL TelRilManager!!");
    }
}

void SimStateHandle::GetLockState(int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetLockState()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHECK_PIN_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->GetSimLockStatus(FAC_PIN_LOCK, event);
}

void SimStateHandle::ProcessIccCardState(IccState &ar, int slotId)
{
    TELEPHONY_LOGI("SimStateHandle::ProcessIccCardState");
    // 1、Update current cardState
    iccState_[slotId].simState_ = ar.simState_;
    UpdateIccState(ar, slotId);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_CHANGE);
    }
}

void SimStateHandle::UpdateIccState(IccState &ar, int slotId)
{
    TELEPHONY_LOGI("SimStateHandle::UpdateIccState() ");
    LockReason reason = LockReason::SIM_NONE;
    int32_t simType = ar.simType_;
    int32_t simState = ar.simState_;
    TELEPHONY_LOGI(
        "SimStateHandle::UpdateIccState(), iccStatus=%{public}d, simType = %{public}d", simState, simType);
    switch (simState) {
        case ICC_CARD_ABSENT:
            externalState_[slotId] = SimState::SIM_STATE_NOT_PRESENT;
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_ABSENT, "");
            break;
        case ICC_CONTENT_READY:
            externalState_[slotId] = SimState::SIM_STATE_READY;
            observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_READY);
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_READY, "");
            break;
        case ICC_CONTENT_PIN:
            externalState_[slotId] = SimState::SIM_STATE_LOCKED;
            reason = LockReason::SIM_PIN;
            observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_LOCKED);
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_PIN, "");
            break;
        case ICC_CONTENT_PUK:
            externalState_[slotId] = SimState::SIM_STATE_LOCKED;
            reason = LockReason::SIM_PUK;
            observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_LOCKED);
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_PUK, "");
            break;
        case ICC_CONTENT_SIMLOCK:
            externalState_[slotId] = SimState::SIM_STATE_LOCKED;
            observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_SIMLOCK);
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_SIMLOCK, "");
            break;
        case ICC_CONTENT_UNKNOWN:
            externalState_[slotId] = SimState::SIM_STATE_UNKNOWN;
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_NOT_READY, "");
            break;
        default:
            externalState_[slotId] = SimState::SIM_STATE_UNKNOWN;
            break;
    }
    TELEPHONY_LOGI("SimStateHandle::UpdateIccState ready to notify");
    if (telephonyStateNotify_ != nullptr) {
        TELEPHONY_LOGI("SimStateHandle::UpdateIccState notify to TelephonyStateNotify");
        telephonyStateNotify_->UpdateSimState(slotId, externalState_[slotId], reason);
    }
}

SimStateHandle::~SimStateHandle()
{
    if (telRilManager_ != nullptr) {
        telRilManager_->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_STATE_CHANGE);
        telRilManager_->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_STATE_CHANGED);
    }
}

void SimStateHandle::ObtainIccStatus()
{
    TELEPHONY_LOGI("SimStateHandle::ObtainIccStatus()");
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_ICC_STATUS_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->GetSimStatus(event); // get sim card state
}

void SimStateHandle::ObtainRealtimeIccStatus()
{
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_REALTIME_ICC_STATUS_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->GetSimStatus(event); // get sim card state
}

void SimStateHandle::GetSimCardData(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetSimCardData");
    int32_t error = 0;
    IccState iccState;
    std::shared_ptr<CardStatusInfo> param = event->GetSharedObject<CardStatusInfo>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSimCardData() fail");
        return;
    }
    if (param != nullptr) {
        iccState.simType_ = param->simType;
        iccState.simState_ = param->simState;
        TELEPHONY_LOGI("SimStateHandle::GetSimCardData(), simType_ = %{public}d", iccState.simType_);
        TELEPHONY_LOGI("SimStateHandle::GetSimCardData(), simState_ = %{public}d", iccState.simState_);
    } else {
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGI("SimStateHandle::GetSimCardData(), error = %{public}d", error);
    }
    ProcessIccCardState(iccState, slotId);
}

void SimStateHandle::GetSimLockState(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetSimLockState");
    int32_t error = 0;
    std::shared_ptr<int32_t> param = event->GetSharedObject<int32_t>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSimLockState() fail");
        return;
    }
    if (param != nullptr) {
        TELEPHONY_LOGI("SimStateHandle::GetSimLockState(), param = %{public}d", *param);
        unlockRespon_.lockState = *param;
    } else {
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGI("SimStateHandle::GetSimLockState(), error = %{public}d", error);
    }
}

void SimStateHandle::GetSetLockResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetSetLockResult");
    int32_t iccUnlockResponse = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSetLockResult() fail");
        return;
    }
    if (param != nullptr) {
        iccUnlockResponse = static_cast<int32_t>(*param);
    } else {
        iccUnlockResponse = static_cast<int32_t>(response->error);
    }
    unlockRespon_.result = iccUnlockResponse;
    TELEPHONY_LOGI("SimStateHandle::GetSetLockResult(), iccUnlockResponse = %{public}d", iccUnlockResponse);
}

void SimStateHandle::GetSetActiveSimResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetSetActiveSimResult");
    int32_t result = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSetActiveSimResult() fail");
        return;
    }
    if (param != nullptr) {
        result = static_cast<int32_t>(*param);
    } else {
        result = static_cast<int32_t>(response->error);
    }
    TELEPHONY_LOGI("SimStateHandle::GetSetActiveSimResult(), activeResponse = %{public}d", result);
    activeRespon_ = result;
}

void SimStateHandle::GetUnlockReult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetUnlockResult");
    int32_t iccUnlockResponse = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSimUnlockResult() fail");
        return;
    }
    if (param != nullptr) {
        iccUnlockResponse = static_cast<int32_t>(*param);
    } else {
        iccUnlockResponse = static_cast<int32_t>(response->error);
    }
    unlockRespon_.result = iccUnlockResponse;
    TELEPHONY_LOGI("SimStateHandle::GetSimUnlockResponse(), iccUnlockResponse = %{public}d", iccUnlockResponse);
}

void SimStateHandle::GetUnlockRemain(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain");
    SimPinInputTimes iccRemain;
    int32_t error = 0;
    std::shared_ptr<SimPinInputTimes> param = event->GetSharedObject<SimPinInputTimes>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetUnlockRemain() fail");
        return;
    }
    if (param != nullptr) {
        iccRemain.serial = param->serial;
        iccRemain.code = param->code;
        iccRemain.times = param->times;
        iccRemain.pukTimes = param->pukTimes;
        iccRemain.pinTimes = param->pinTimes;
        iccRemain.puk2Times = param->puk2Times;
        iccRemain.pin2Times = param->pin2Times;
        TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain(), serial = %{public}d", iccRemain.serial);
        TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain(), codeType = %{public}s", iccRemain.code.c_str());
        TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain(), currentTimes = %{public}d", iccRemain.times);
        TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain(), pukTimes = %{public}d", iccRemain.pukTimes);
        TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain(), pinTimes = %{public}d", iccRemain.pinTimes);
        TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain(), puk2Times = %{public}d", iccRemain.puk2Times);
        TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain(), pin2Times = %{public}d", iccRemain.pin2Times);
        unlockRespon_.remain = iccRemain.times;
        unlockRespon_.pinRemain = iccRemain.pinTimes;
        unlockRespon_.pin2Remain = iccRemain.pin2Times;
        unlockRespon_.puk2Remain = iccRemain.puk2Times;
    } else {
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain(), error = %{public}d", error);
    }
}

UnlockData SimStateHandle::GetUnlockData()
{
    return unlockRespon_;
}

int32_t SimStateHandle::GetActiveSimResult()
{
    return activeRespon_;
}

void SimStateHandle::SyncCmdResponse()
{
    std::shared_ptr<SimStateManager> simStateManager = simStateManager_.lock();
    std::unique_lock<std::mutex> lck(SimStateManager::ctx_);
    SimStateManager::responseReady_ = true;
    TELEPHONY_LOGI(
        "SimStateHandle::SyncCmdResponse(), responseReady_ = %{public}d", SimStateManager::responseReady_);
    SimStateManager::cv_.notify_one();
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
    TELEPHONY_LOGI("SimStateHandle::PublishSimStateEvent result : %{public}d", publishResult);
    return publishResult;
}

void SimStateHandle::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int eventId = event->GetInnerEventId();
    int slotId = CoreManager::DEFAULT_SLOT_ID;
    TELEPHONY_LOGI("SimStateHandle::ProcessEvent(), eventId = %{public}d", eventId);
    switch (eventId) {
        case ObserverHandler::RADIO_STATE_CHANGED:
        case ObserverHandler::RADIO_SIM_STATE_CHANGE:
            ObtainIccStatus();
            break;
        case MSG_SIM_GET_ICC_STATUS_DONE:
            GetSimCardData(event, slotId);
            break;
        case MSG_SIM_UNLOCK_PIN_DONE:
        case MSG_SIM_UNLOCK_PUK_DONE:
        case MSG_SIM_CHANGE_PIN_DONE:
        case MSG_SIM_UNLOCK_PIN2_DONE:
        case MSG_SIM_UNLOCK_PUK2_DONE:
        case MSG_SIM_CHANGE_PIN2_DONE:
            GetUnlockReult(event, slotId);
            SyncCmdResponse();
            break;
        case MSG_SIM_UNLOCK_REMAIN_DONE:
        case MSG_SIM_UNLOCK_PIN2_REMAIN_DONE:
            GetUnlockRemain(event, slotId);
            SyncCmdResponse();
            break;
        case MSG_SIM_ENABLE_PIN_DONE:
            GetSetLockResult(event, slotId);
            SyncCmdResponse();
            break;
        case MSG_SIM_CHECK_PIN_DONE:
            GetSimLockState(event, slotId);
            SyncCmdResponse();
            break;
        case MSG_SIM_GET_REALTIME_ICC_STATUS_DONE:
            GetSimCardData(event, slotId);
            SyncCmdResponse();
            break;
        case MSG_SIM_SET_ACTIVE_DONE:
            GetSetActiveSimResult(event, slotId);
            SyncCmdResponse();
            break;
        default:
            TELEPHONY_LOGI("SimStateHandle::ProcessEvent(), unknown event");
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
        TELEPHONY_LOGI("SimStateHandle::ConnectService() IRemoteObject not null\n");
        telephonyStateNotify_ = iface_cast<ITelephonyStateNotify>(object);
    }

    if (telephonyStateNotify_ == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::ConnectService() telephonyStateNotify_ null\n");
        return false;
    }
    TELEPHONY_LOGI("SimStateHandle::ConnectService() success\n");
    return true;
}

void SimStateHandle::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    switch (what) {
        case ObserverHandler::RADIO_SIM_STATE_CHANGE:
            TELEPHONY_LOGI("SimStateHandle::RegisterIccStateChanged()");
            observerHandler_->RegObserver(ObserverHandler::RADIO_SIM_STATE_CHANGE, handler);
            break;
        case ObserverHandler::RADIO_SIM_STATE_READY:
            TELEPHONY_LOGI("SimStateHandle::RegisterIccReady()");
            observerHandler_->RegObserver(ObserverHandler::RADIO_SIM_STATE_READY, handler);
            break;
        case ObserverHandler::RADIO_SIM_STATE_LOCKED:
            TELEPHONY_LOGI("SimStateHandle::RegisterIccLocked()");
            observerHandler_->RegObserver(ObserverHandler::RADIO_SIM_STATE_LOCKED, handler);
            break;
        case ObserverHandler::RADIO_SIM_STATE_SIMLOCK:
            TELEPHONY_LOGI("SimStateHandle::RegisterIccSimLock()");
            observerHandler_->RegObserver(ObserverHandler::RADIO_SIM_STATE_SIMLOCK, handler);
            break;
        default:
            TELEPHONY_LOGI("SimStateHandle RegisterCoreNotify do default");
            break;
    }
}

void SimStateHandle::UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    switch (what) {
        case ObserverHandler::RADIO_SIM_STATE_CHANGE:
            TELEPHONY_LOGI("SimStateHandle::UnregisterIccStateChanged()");
            observerHandler_->Remove(ObserverHandler::RADIO_SIM_STATE_CHANGE, handler);
            break;
        case ObserverHandler::RADIO_SIM_STATE_READY:
            TELEPHONY_LOGI("SimStateHandle::UnregisterIccReady()");
            observerHandler_->Remove(ObserverHandler::RADIO_SIM_STATE_READY, handler);
            break;
        case ObserverHandler::RADIO_SIM_STATE_LOCKED:
            TELEPHONY_LOGI("SimStateHandle::UnregisterIccLocked()");
            observerHandler_->Remove(ObserverHandler::RADIO_SIM_STATE_LOCKED, handler);
            break;
        case ObserverHandler::RADIO_SIM_STATE_SIMLOCK:
            TELEPHONY_LOGI("SimStateHandle::UnregisterIccSimLock()");
            observerHandler_->Remove(ObserverHandler::RADIO_SIM_STATE_SIMLOCK, handler);
            break;
        default:
            TELEPHONY_LOGI("SimStateHandle UnRegisterCoreNotify do default");
            break;
    }
}
} // namespace Telephony
} // namespace OHOS
