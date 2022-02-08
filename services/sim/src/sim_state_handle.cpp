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
#include "radio_event.h"
#include "sim_constant.h"
#include "sim_state_manager.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"
#include "common_event_support.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "telephony_state_registry_client.h"

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

void SimStateHandle::Init(int32_t slotId)
{
    slotId_ = slotId;
    TELEPHONY_LOGI("SimStateHandle::HasSimCard(), slotId_ = %{public}d", slotId_);
    ConnectService();
    if (telRilManager_ != nullptr) {
        TELEPHONY_LOGI("SimStateHandle::SimStateHandle RegisterEvent start");
        telRilManager_->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE, nullptr);
        telRilManager_->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STATE_CHANGED, nullptr);
    } else {
        TELEPHONY_LOGE("SimStateHandle::SimStateHandle get ril_Manager fail");
        return;
    }
    observerHandler_ = std::make_unique<ObserverHandler>();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::failed to create new ObserverHandler");
        return;
    }
    externalState_ = SimState::SIM_STATE_UNKNOWN;
    externalType_ = CardType::UNKNOWN_CARD;
}

bool SimStateHandle::HasSimCard()
{
    bool has = false;
    if (iccState_.simStatus_ != ICC_CARD_ABSENT) {
        has = true;
    }
    TELEPHONY_LOGI("SimStateHandle::HasSimCard(), has = %{public}d", has);
    return has;
}

SimState SimStateHandle::GetSimState()
{
    return externalState_;
}

CardType SimStateHandle::GetCardType()
{
    TELEPHONY_LOGI(
        "SimStateHandle::GetCardType() externalType_=%{public}d", static_cast<int32_t>(externalType_));
    return externalType_;
}

void SimStateHandle::UnlockPin(int32_t slotId, std::string pin)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPin1() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PIN_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->UnlockPin(slotId, pin, event);
}

void SimStateHandle::UnlockPuk(int32_t slotId, std::string newPin, std::string puk)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPuk1() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PUK_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->UnlockPuk(slotId, puk, newPin, event);
}

void SimStateHandle::AlterPin(int32_t slotId, std::string newPin, std::string oldPin)
{
    TELEPHONY_LOGI("SimStateHandle::AlterPin() slotId = %{public}d", slotId);
    int32_t length = newPin.size();
    SimPasswordParam simPinPassword;
    simPinPassword.passwordLength = length;
    simPinPassword.fac = FAC_PIN_LOCK;
    simPinPassword.oldPassword = oldPin;
    simPinPassword.newPassword = newPin;
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHANGE_PIN_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->ChangeSimPassword(slotId, simPinPassword, event);
}

void SimStateHandle::UnlockPin2(int32_t slotId, std::string pin2)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPin2() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PIN2_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->UnlockPin2(slotId, pin2, event);
}

void SimStateHandle::UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPuk2() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PUK2_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->UnlockPuk2(slotId, puk2, newPin2, event);
}

void SimStateHandle::AlterPin2(int32_t slotId, std::string newPin2, std::string oldPin2)
{
    TELEPHONY_LOGI("SimStateHandle::AlterPin2() slotId = %{public}d", slotId);
    int32_t length = newPin2.size();
    SimPasswordParam simPin2Password;
    simPin2Password.passwordLength = length;
    simPin2Password.fac = FDN_PIN_LOCK;
    simPin2Password.oldPassword = oldPin2;
    simPin2Password.newPassword = newPin2;
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHANGE_PIN2_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->ChangeSimPassword(slotId, simPin2Password, event);
}

void SimStateHandle::UnlockRemain(int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockRemain() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_REMAIN_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->GetSimPinInputTimes(slotId, event);
}

void SimStateHandle::SetLockState(int32_t slotId, const LockInfo &options)
{
    TELEPHONY_LOGI("SimStateHandle::SetLockState() slotId = %{public}d", slotId);
    SimLockParam simLock;
    simLock.mode = static_cast<int32_t>(options.lockState);
    simLock.passwd = Str16ToStr8(options.password);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_ENABLE_PIN_DONE);
    event->SetOwner(shared_from_this());
    if (LockType::PIN_LOCK == options.lockType) {
        simLock.fac = FAC_PIN_LOCK;
    } else {
        simLock.fac = FDN_PIN2_LOCK;
    }
    telRilManager_->SetSimLock(slotId, simLock, event);
}

void SimStateHandle::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockSimLock() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_SIMLOCK_DONE);
    event->SetOwner(shared_from_this());
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("SimStateHandle telRilManager_ is nullptr!!");
        return;
    }
    int32_t lockType = static_cast<int32_t>(lockInfo.lockType);
    telRilManager_->UnlockSimLock(slotId, lockType, Str16ToStr8(lockInfo.password), event);
}

void SimStateHandle::SetRilManager(std::shared_ptr<Telephony::ITelRilManager> telRilManager)
{
    telRilManager_ = telRilManager;
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("SimStateHandle set NULL TelRilManager!!");
    }
}

void SimStateHandle::GetLockState(int32_t slotId, LockType lockType)
{
    TELEPHONY_LOGI("SimStateHandle::GetLockState() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHECK_PIN_DONE);
    event->SetOwner(shared_from_this());
    if (LockType::PIN_LOCK == lockType) {
        telRilManager_->GetSimLockStatus(slotId, FAC_PIN_LOCK, event);
    } else {
        telRilManager_->GetSimLockStatus(slotId, FDN_PIN2_LOCK, event);
    }
}

void SimStateHandle::ProcessIccCardState(IccState &ar, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::ProcessIccCardState slotId = %{public}d", slotId);
    LockReason reason = LockReason::SIM_NONE;
    const int32_t newSimType = ar.simType_;
    const int32_t newSimStatus = ar.simStatus_;
    iccState_ = ar;
    TELEPHONY_LOGI("SimStateHandle::ProcessIccCardState SimType[%{public}d], SimStatus[%{public}d]", newSimType,
        newSimStatus);
    if (oldSimType_ != newSimType) {
        CardTypeEscape(newSimType, slotId);
        oldSimType_ = newSimType;
    }
    if (oldSimStatus_ != newSimStatus) {
        SimStateEscape(newSimStatus, slotId, reason);
        oldSimStatus_ = newSimStatus;
        TELEPHONY_LOGI(
            "will to NotifyIccStateChanged at newSimStatus[%{public}d] observerHandler_ is nullptr[%{public}d] ",
            newSimStatus, (observerHandler_ == nullptr));
        if (observerHandler_ != nullptr) {
            observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_CHANGE);
        }
        DelayedRefSingleton<TelephonyStateRegistryClient>::GetInstance().UpdateSimState(
            slotId, externalType_, externalState_, reason);
    }
}

SimStateHandle::~SimStateHandle()
{
    if (telRilManager_ != nullptr) {
        telRilManager_->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
        telRilManager_->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STATE_CHANGED);
    }
}

void SimStateHandle::ObtainIccStatus(int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::ObtainIccStatus() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_ICC_STATUS_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->GetSimStatus(slotId, event); // get sim card state
}

void SimStateHandle::ObtainRealtimeIccStatus(int32_t slotId)
{
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_REALTIME_ICC_STATUS_DONE);
    event->SetOwner(shared_from_this());
    telRilManager_->GetSimStatus(slotId, event); // get sim card state
}

void SimStateHandle::GetSimCardData(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetSimCardData slotId = %{public}d", slotId);
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
        iccState.simStatus_ = param->simState;
        TELEPHONY_LOGI("SimStateHandle::GetSimCardData(), simType_ = %{public}d", iccState.simType_);
        TELEPHONY_LOGI("SimStateHandle::GetSimCardData(), simStatus_ = %{public}d", iccState.simStatus_);
    } else {
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGI("SimStateHandle::GetSimCardData(), error = %{public}d", error);
    }
    ProcessIccCardState(iccState, slotId);
}

void SimStateHandle::GetSimLockState(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetSimLockState slotId = %{public}d", slotId);
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
        unlockRespon_.lockState = static_cast<int32_t>(LockState::LOCK_ERROR);
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGI("SimStateHandle::GetSimLockState(), error = %{public}d", error);
    }
    TELEPHONY_LOGI("SimStateHandle::GetSimLockState(), lockState = %{public}d", unlockRespon_.lockState);
}

void SimStateHandle::GetSetLockResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetSetLockResult slotId = %{public}d", slotId);
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

void SimStateHandle::GetUnlockReult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetUnlockResult slotId = %{public}d", slotId);
    int32_t iccUnlockResponse = 0;
    std::shared_ptr<HRilErrType> param = event->GetSharedObject<HRilErrType>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSimUnlockResult() fail");
        return;
    }
    if (param != nullptr) {
        iccUnlockResponse = static_cast<int32_t>(*param);
        TELEPHONY_LOGE("SimStateHandle::GetUnlockReult param is true");
    } else {
        TELEPHONY_LOGE("SimStateHandle::GetUnlockReult param is null");
        iccUnlockResponse = static_cast<int32_t>(response->error);
    }
    unlockRespon_.result = iccUnlockResponse;
    TELEPHONY_LOGI("SimStateHandle::GetSimUnlockResponse(), iccUnlockResponse = %{public}d", iccUnlockResponse);
}

void SimStateHandle::GetUnlockSimLockResult(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetUnlockSimLockResult slotId = %{public}d", slotId);
    std::shared_ptr<LockStatusResp> param = event->GetSharedObject<LockStatusResp>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetUnlockSimLockResult() fail");
        return;
    }
    if (param != nullptr) {
        TELEPHONY_LOGI("SimStateHandle::GetUnlockSimLockResult param is true");
        simlockRespon_.result = param->result;
        simlockRespon_.remain = param->remain;
    } else {
        TELEPHONY_LOGE("SimStateHandle::GetUnlockSimLockResult param is null");
        simlockRespon_.result = static_cast<int32_t>(response->error);
    }
}

void SimStateHandle::GetUnlockRemain(const AppExecFwk::InnerEvent::Pointer &event, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::GetUnlockRemain slotId = %{public}d", slotId);
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

LockStatusResponse SimStateHandle::GetSimlockResponse()
{
    return simlockRespon_;
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

bool SimStateHandle::PublishSimStateEvent(std::string event, int32_t eventCode, std::string eventData)
{
    AAFwk::Want want;
    want.SetAction(event);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetCode(eventCode);
    data.SetData(eventData);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("SimStateHandle::PublishSimStateEvent result : %{public}d", publishResult);
    return publishResult;
}

void SimStateHandle::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int eventId = event->GetInnerEventId();
    TELEPHONY_LOGI("SimStateHandle::ProcessEvent(), eventId = %{public}d", eventId);
    TELEPHONY_LOGI("SimStateHandle::ProcessEvent(), slotId_ = %{public}d", slotId_);
    switch (eventId) {
        case RadioEvent::RADIO_STATE_CHANGED:
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            ObtainIccStatus(slotId_);
            break;
        case MSG_SIM_GET_ICC_STATUS_DONE:
            GetSimCardData(event, slotId_);
            break;
        case MSG_SIM_UNLOCK_PIN_DONE:
        case MSG_SIM_UNLOCK_PUK_DONE:
        case MSG_SIM_CHANGE_PIN_DONE:
        case MSG_SIM_UNLOCK_PIN2_DONE:
        case MSG_SIM_UNLOCK_PUK2_DONE:
        case MSG_SIM_CHANGE_PIN2_DONE:
            GetUnlockReult(event, slotId_);
            SyncCmdResponse();
            break;
        case MSG_SIM_UNLOCK_SIMLOCK_DONE:
            GetUnlockSimLockResult(event, slotId_);
            SyncCmdResponse();
            break;
        case MSG_SIM_UNLOCK_REMAIN_DONE:
        case MSG_SIM_UNLOCK_PIN2_REMAIN_DONE:
            GetUnlockRemain(event, slotId_);
            SyncCmdResponse();
            break;
        case MSG_SIM_ENABLE_PIN_DONE:
            GetSetLockResult(event, slotId_);
            SyncCmdResponse();
            break;
        case MSG_SIM_CHECK_PIN_DONE:
            GetSimLockState(event, slotId_);
            SyncCmdResponse();
            break;
        case MSG_SIM_GET_REALTIME_ICC_STATUS_DONE:
            GetSimCardData(event, slotId_);
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
    if (object == nullptr) {
        TELEPHONY_LOGI("SimStateHandle::ConnectService() faild\n");
        return false;
    }
    TELEPHONY_LOGI("SimStateHandle::ConnectService() success\n");
    return true;
}

bool SimStateHandle::IsIccReady()
{
    return externalState_ == SimState::SIM_STATE_READY;
}

void SimStateHandle::SimStateEscape(
    int32_t simState, int slotId, LockReason &reason)
{
    switch (simState) {
        case ICC_CARD_ABSENT:
            externalState_ = SimState::SIM_STATE_NOT_PRESENT;
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_ABSENT, "");
            break;
        case ICC_CONTENT_READY:
            externalState_ = SimState::SIM_STATE_READY;
            observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_READY);
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_READY, "");
            break;
        case ICC_CONTENT_PIN:
            externalState_ = SimState::SIM_STATE_LOCKED;
            reason = LockReason::SIM_PIN;
            observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_LOCKED);
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_PIN, "");
            break;
        case ICC_CONTENT_PUK:
            externalState_ = SimState::SIM_STATE_LOCKED;
            reason = LockReason::SIM_PUK;
            observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_LOCKED);
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_PUK, "");
            break;
        default:
            SimLockStateEscape(simState, slotId, reason);
            break;
    }
}

void SimStateHandle::SimLockStateEscape(
    int32_t simState, int slotId, LockReason &reason)
{
    bool isSimLockState = true;
    switch (simState) {
        case ICC_CONTENT_PH_NET_PIN:
            reason = LockReason::SIM_PN_PIN;
            break;
        case ICC_CONTENT_PH_NET_PUK:
            reason = LockReason::SIM_PN_PUK;
            break;
        case ICC_CONTENT_PH_NET_SUB_PIN:
            reason = LockReason::SIM_PU_PIN;
            break;
        case ICC_CONTENT_PH_NET_SUB_PUK:
            reason = LockReason::SIM_PU_PUK;
            break;
        case ICC_CONTENT_PH_SP_PIN:
            reason = LockReason::SIM_PP_PIN;
            break;
        case ICC_CONTENT_PH_SP_PUK:
            reason = LockReason::SIM_PP_PUK;
            break;
        case ICC_CONTENT_UNKNOWN:
        default:
            isSimLockState = false;
            externalState_ = SimState::SIM_STATE_UNKNOWN;
            PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_NOT_READY, "");
            break;
    }
    if (isSimLockState) {
        NotifySimLock(slotId);
    }
}

void SimStateHandle::NotifySimLock(int slotId)
{
    externalState_ = SimState::SIM_STATE_LOCKED;
    observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_SIMLOCK);
    PublishSimStateEvent(SIM_STATE_ACTION, ICC_STATE_SIMLOCK, "");
}

void SimStateHandle::CardTypeEscape(int32_t simType, int slotId)
{
    CardType cardTypeStorage = externalType_;
    TELEPHONY_LOGI("SimStateHandle::CardTypeEscape() simType=%{public}d, slotId = %{public}d", simType, slotId);
    switch (simType) {
        case ICC_UNKNOWN_TYPE:
            externalType_ = CardType::UNKNOWN_CARD;
            break;
        case ICC_SIM_TYPE:
            externalType_ = CardType::SINGLE_MODE_SIM_CARD;
            break;
        case ICC_USIM_TYPE:
            externalType_ = CardType::SINGLE_MODE_USIM_CARD;
            break;
        case ICC_RUIM_TYPE:
            externalType_ = CardType::SINGLE_MODE_RUIM_CARD;
            break;
        case ICC_CG_TYPE:
            externalType_ = CardType::DUAL_MODE_CG_CARD;
            break;
        case ICC_DUAL_MODE_ROAMING_TYPE:
            externalType_ = CardType::CT_NATIONAL_ROAMING_CARD;
            break;
        case ICC_UNICOM_DUAL_MODE_TYPE:
            externalType_ = CardType::CU_DUAL_MODE_CARD;
            break;
        case ICC_4G_LTE_TYPE:
            externalType_ = CardType::DUAL_MODE_TELECOM_LTE_CARD;
            break;
        case ICC_UG_TYPE:
            externalType_ = CardType::DUAL_MODE_UG_CARD;
            break;
        case ICC_IMS_TYPE:
            externalType_ = CardType::SINGLE_MODE_ISIM_CARD;
            break;
        default:
            externalType_ = CardType::UNKNOWN_CARD;
            break;
    }
    if (externalType_ != cardTypeStorage) {
        TELEPHONY_LOGI("will to NotifyIccCardTypeChange at oldSimType[%{public}d] != newSimType[%{public}d]",
            cardTypeStorage, externalType_);
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CARD_TYPE_CHANGE);
    } else {
        TELEPHONY_LOGI("do not NotifyIccCardTypeChange at oldSimType[%{public}d] == newSimType[%{public}d]",
            cardTypeStorage, externalType_);
    }
}

void SimStateHandle::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    switch (what) {
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            TELEPHONY_LOGI("SimStateHandle::RegisterIccStateChanged()");
            observerHandler_->RegObserver(RadioEvent::RADIO_SIM_STATE_CHANGE, handler);
            break;
        case RadioEvent::RADIO_SIM_STATE_READY:
            TELEPHONY_LOGI("SimStateHandle::RegisterIccReady()");
            observerHandler_->RegObserver(RadioEvent::RADIO_SIM_STATE_READY, handler);
            if (IsIccReady()) {
                TELEPHONY_LOGI("SimStateHandle::RegisterIccReady() OK send");
                observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_READY);
            }
            break;
        case RadioEvent::RADIO_SIM_STATE_LOCKED:
            TELEPHONY_LOGI("SimStateHandle::RegisterIccLocked()");
            observerHandler_->RegObserver(RadioEvent::RADIO_SIM_STATE_LOCKED, handler);
            break;
        case RadioEvent::RADIO_SIM_STATE_SIMLOCK:
            TELEPHONY_LOGI("SimStateHandle::RegisterIccSimLock()");
            observerHandler_->RegObserver(RadioEvent::RADIO_SIM_STATE_SIMLOCK, handler);
            break;
        case RadioEvent::RADIO_CARD_TYPE_CHANGE:
            TELEPHONY_LOGI("SimStateHandle::RegisterCardTypeChange()");
            observerHandler_->RegObserver(RadioEvent::RADIO_CARD_TYPE_CHANGE, handler);
            break;
        default:
            TELEPHONY_LOGI("SimStateHandle RegisterCoreNotify do default");
            break;
    }
}

void SimStateHandle::UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    switch (what) {
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            TELEPHONY_LOGI("SimStateHandle::UnregisterIccStateChanged()");
            observerHandler_->Remove(RadioEvent::RADIO_SIM_STATE_CHANGE, handler);
            break;
        case RadioEvent::RADIO_SIM_STATE_READY:
            TELEPHONY_LOGI("SimStateHandle::UnregisterIccReady()");
            observerHandler_->Remove(RadioEvent::RADIO_SIM_STATE_READY, handler);
            break;
        case RadioEvent::RADIO_SIM_STATE_LOCKED:
            TELEPHONY_LOGI("SimStateHandle::UnregisterIccLocked()");
            observerHandler_->Remove(RadioEvent::RADIO_SIM_STATE_LOCKED, handler);
            break;
        case RadioEvent::RADIO_SIM_STATE_SIMLOCK:
            TELEPHONY_LOGI("SimStateHandle::UnregisterIccSimLock()");
            observerHandler_->Remove(RadioEvent::RADIO_SIM_STATE_SIMLOCK, handler);
            break;
        case RadioEvent::RADIO_CARD_TYPE_CHANGE:
            TELEPHONY_LOGI("SimStateHandle::RegisterCardTypeChange()");
            observerHandler_->Remove(RadioEvent::RADIO_CARD_TYPE_CHANGE, handler);
            break;
        default:
            TELEPHONY_LOGI("SimStateHandle UnRegisterCoreNotify do default");
            break;
    }
}
} // namespace Telephony
} // namespace OHOS
