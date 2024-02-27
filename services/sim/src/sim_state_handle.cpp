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

#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_service_hisysevent.h"
#include "hilog/log.h"
#include "hril_sim_parcel.h"
#include "if_system_ability_manager.h"
#include "inner_event.h"
#include "iservice_registry.h"
#include "radio_event.h"
#include "satellite_service_client.h"
#include "sim_constant.h"
#include "sim_state_manager.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "telephony_log_wrapper.h"
#include "telephony_state_registry_client.h"
#include "telephony_types.h"

using namespace OHOS::EventFwk;
namespace OHOS {
namespace Telephony {
std::mutex SimStateManager::ctx_;
bool SimStateManager::responseReady_ = false;
std::condition_variable SimStateManager::cv_;
const std::map<uint32_t, SimStateHandle::Func> SimStateHandle::memberFuncMap_ = {
    { MSG_SIM_UNLOCK_PIN_DONE, &SimStateHandle::GetUnlockResult },
    { MSG_SIM_UNLOCK_PUK_DONE, &SimStateHandle::GetUnlockResult },
    { MSG_SIM_CHANGE_PIN_DONE, &SimStateHandle::GetUnlockResult },
    { MSG_SIM_UNLOCK_PIN2_DONE, &SimStateHandle::GetUnlockResult },
    { MSG_SIM_UNLOCK_PUK2_DONE, &SimStateHandle::GetUnlockResult },
    { MSG_SIM_CHANGE_PIN2_DONE, &SimStateHandle::GetUnlockResult },
    { MSG_SIM_UNLOCK_SIMLOCK_DONE, &SimStateHandle::GetUnlockSimLockResult },
    { MSG_SIM_ENABLE_PIN_DONE, &SimStateHandle::GetSetLockResult },
    { MSG_SIM_CHECK_PIN_DONE, &SimStateHandle::GetSimLockState },
    { MSG_SIM_GET_REALTIME_ICC_STATUS_DONE, &SimStateHandle::GetSimCardData },
    { MSG_SIM_AUTHENTICATION_DONE, &SimStateHandle::GetSimAuthenticationResult },
    { MSG_SIM_SEND_NCFG_OPER_INFO_DONE, &SimStateHandle::GetSendSimMatchedOperatorInfoResult },
};

SimStateHandle::SimStateHandle(const std::weak_ptr<SimStateManager> &simStateManager)
    : TelEventHandler("SimStateHandle"), simStateManager_(simStateManager)
{
    TELEPHONY_LOGI("SimStateHandle::SimStateHandle()");
}

void SimStateHandle::Init(int32_t slotId)
{
    slotId_ = slotId;
    TELEPHONY_LOGI("SimStateHandle::HasSimCard(), slotId_ = %{public}d", slotId_);
    ConnectService();
    if (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED)) {
        std::shared_ptr<SatelliteServiceClient> satelliteClient =
            DelayedSingleton<SatelliteServiceClient>::GetInstance();
        satelliteClient->AddSimHandler(slotId_, std::static_pointer_cast<TelEventHandler>(shared_from_this()));
    }
    auto telRilManager = telRilManager_.lock();
    if (telRilManager != nullptr) {
        TELEPHONY_LOGI("SimStateHandle::SimStateHandle RegisterEvent start");
        telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE, nullptr);
        telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STATE_CHANGED, nullptr);
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
    CoreServiceHiSysEvent::WriteSimStateBehaviorEvent(slotId, static_cast<int32_t>(externalState_));
    externalType_ = CardType::UNKNOWN_CARD;
}

int32_t SimStateHandle::IsSatelliteSupported()
{
    char satelliteSupported[SYSPARA_SIZE] = { 0 };
    GetParameter(TEL_SATELLITE_SUPPORTED, SATELLITE_DEFAULT_VALUE, satelliteSupported, SYSPARA_SIZE);
    TELEPHONY_LOGI("satelliteSupported is %{public}s", satelliteSupported);
    return std::atoi(satelliteSupported);
}

bool SimStateHandle::HasSimCard()
{
    bool has = false;
    if (iccState_.simStatus_ != ICC_CARD_ABSENT) {
        has = true;
    }
    TELEPHONY_LOGD("SimStateHandle::HasSimCard(), has = %{public}d", has);
    return has;
}

SimState SimStateHandle::GetSimState()
{
    return externalState_;
}

CardType SimStateHandle::GetCardType()
{
    TELEPHONY_LOGD("SimStateHandle::GetCardType() externalType_=%{public}d", static_cast<int32_t>(externalType_));
    return externalType_;
}

void SimStateHandle::UnlockPin(int32_t slotId, const std::string &pin)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPin1() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PIN_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->UnlockPin(slotId, pin, event);
}

void SimStateHandle::UnlockPuk(int32_t slotId, const std::string &newPin, const std::string &puk)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPuk1() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PUK_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->UnlockPuk(slotId, puk, newPin, event);
}

void SimStateHandle::AlterPin(int32_t slotId, const std::string &newPin, const std::string &oldPin)
{
    TELEPHONY_LOGI("SimStateHandle::AlterPin() slotId = %{public}d", slotId);
    int32_t length = (int32_t)newPin.size();
    SimPasswordParam simPinPassword;
    simPinPassword.passwordLength = length;
    simPinPassword.fac = FAC_PIN_LOCK;
    simPinPassword.oldPassword = oldPin;
    simPinPassword.newPassword = newPin;
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHANGE_PIN_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->ChangeSimPassword(slotId, simPinPassword, event);
}

void SimStateHandle::UnlockPin2(int32_t slotId, const std::string &pin2)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPin2() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PIN2_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->UnlockPin2(slotId, pin2, event);
}

void SimStateHandle::UnlockPuk2(int32_t slotId, const std::string &newPin2, const std::string &puk2)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockPuk2() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_PUK2_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->UnlockPuk2(slotId, puk2, newPin2, event);
}

void SimStateHandle::AlterPin2(int32_t slotId, const std::string &newPin2, const std::string &oldPin2)
{
    TELEPHONY_LOGI("SimStateHandle::AlterPin2() slotId = %{public}d", slotId);
    int32_t length = (int32_t)newPin2.size();
    SimPasswordParam simPin2Password;
    simPin2Password.passwordLength = length;
    simPin2Password.fac = FDN_PIN_LOCK;
    simPin2Password.oldPassword = oldPin2;
    simPin2Password.newPassword = newPin2;
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHANGE_PIN2_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->ChangeSimPassword(slotId, simPin2Password, event);
}

void SimStateHandle::SetLockState(int32_t slotId, const LockInfo &options)
{
    TELEPHONY_LOGI("SimStateHandle::SetLockState() slotId = %{public}d", slotId);
    SimLockParam simLock;
    simLock.mode = static_cast<int32_t>(options.lockState);
    simLock.passwd = Str16ToStr8(options.password);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_ENABLE_PIN_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    if (LockType::PIN_LOCK == options.lockType) {
        simLock.fac = FAC_PIN_LOCK;
    } else {
        simLock.fac = FDN_PIN2_LOCK;
    }
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->SetSimLock(slotId, simLock, event);
}

void SimStateHandle::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo)
{
    TELEPHONY_LOGI("SimStateHandle::UnlockSimLock() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_UNLOCK_SIMLOCK_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("SimStateHandle telRilManager is nullptr!!");
        return;
    }
    int32_t lockType = static_cast<int32_t>(lockInfo.lockType);
    telRilManager->UnlockSimLock(slotId, lockType, Str16ToStr8(lockInfo.password), event);
}

void SimStateHandle::SetRilManager(std::weak_ptr<Telephony::ITelRilManager> telRilManager)
{
    telRilManager_ = telRilManager;
    auto telRilManagerNew = telRilManager_.lock();
    if (telRilManagerNew == nullptr) {
        TELEPHONY_LOGE("SimStateHandle set NULL TelRilManager!!");
    }
}

void SimStateHandle::GetLockState(int32_t slotId, LockType lockType)
{
    TELEPHONY_LOGI("SimStateHandle::GetLockState() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_CHECK_PIN_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    if (LockType::PIN_LOCK == lockType) {
        telRilManager->GetSimLockStatus(slotId, FAC_PIN_LOCK, event);
    } else {
        telRilManager->GetSimLockStatus(slotId, FDN_PIN2_LOCK, event);
    }
}

void SimStateHandle::ProcessIccCardState(IccState &ar, int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::ProcessIccCardState slotId = %{public}d", slotId);
    LockReason reason = LockReason::SIM_NONE;
    const int32_t newSimType = ar.simType_;
    const int32_t newSimStatus = ar.simStatus_;
    iccState_ = ar;
    TELEPHONY_LOGI(
        "SimStateHandle::ProcessIccCardState SimType[%{public}d], SimStatus[%{public}d]", newSimType, newSimStatus);
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
            observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_CHANGE, slotId);
        }
        DelayedRefSingleton<TelephonyStateRegistryClient>::GetInstance().UpdateSimState(
            slotId, externalType_, externalState_, reason);
    }
}

void SimStateHandle::UnInit()
{
    auto telRilManager = telRilManager_.lock();
    if (telRilManager != nullptr) {
        telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
        telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STATE_CHANGED);
    }
    if (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED) &&
        satelliteCallback_ != nullptr) {
        std::shared_ptr<SatelliteServiceClient> satelliteClient =
            DelayedSingleton<SatelliteServiceClient>::GetInstance();
        satelliteClient->UnRegisterCoreNotify(slotId_, RadioEvent::RADIO_SIM_STATE_CHANGE);
    }
}

void SimStateHandle::RegisterSatelliteCallback()
{
    satelliteCallback_ =
        std::make_unique<SatelliteCoreCallback>(std::static_pointer_cast<TelEventHandler>(shared_from_this()))
            .release();
    std::shared_ptr<SatelliteServiceClient> satelliteClient = DelayedSingleton<SatelliteServiceClient>::GetInstance();
    satelliteClient->RegisterCoreNotify(slotId_, RadioEvent::RADIO_SIM_STATE_CHANGE, satelliteCallback_);
}

void SimStateHandle::UnregisterSatelliteCallback()
{
    if (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED)) {
        satelliteCallback_ = nullptr;
    }
}

void SimStateHandle::ObtainIccStatus(int32_t slotId)
{
    TELEPHONY_LOGI("SimStateHandle::ObtainIccStatus() slotId = %{public}d", slotId);
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_ICC_STATUS_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->GetSimStatus(slotId, event); // get sim card state
}

void SimStateHandle::ObtainRealtimeIccStatus(int32_t slotId)
{
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_GET_REALTIME_ICC_STATUS_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("telRilManager is nullptr!");
        return;
    }
    telRilManager->GetSimStatus(slotId, event); // get sim card state
}

int32_t SimStateHandle::SimAuthentication(int32_t slotId, AuthType authType, const std::string &authData)
{
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_AUTHENTICATION_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return SIM_AUTH_FAIL;
    }
    event->SetOwner(shared_from_this());
    SimAuthenticationRequestInfo requireInfo;
    requireInfo.serial = static_cast<int32_t>(authType);
    requireInfo.aid = GetAidByCardType(externalType_);
    requireInfo.authData = authData;
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::SimAuthentication() telRilManager is nullptr!!");
        return SIM_AUTH_FAIL;
    }
    return telRilManager->SimAuthentication(slotId, requireInfo, event);
}

void SimStateHandle::SendSimMatchedOperatorInfo(
    int32_t slotId, int32_t state, const std::string &operName, const std::string &operKey)
{
    auto event = AppExecFwk::InnerEvent::Get(MSG_SIM_SEND_NCFG_OPER_INFO_DONE);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    event->SetOwner(shared_from_this());
    NcfgOperatorInfo requireInfo;
    requireInfo.state = state;
    requireInfo.operName = operName;
    requireInfo.operKey = operKey;
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::SendSimMatchedOperatorInfo() telRilManager is nullptr!!");
        return;
    }
    telRilManager->SendSimMatchedOperatorInfo(slotId, requireInfo, event);
}

std::string SimStateHandle::GetAidByCardType(CardType type)
{
    switch (type) {
        case CardType::SINGLE_MODE_RUIM_CARD:
            return CDMA_FAKE_AID;
        case CardType::SINGLE_MODE_SIM_CARD:
            [[fallthrough]]; // fall_through
        case CardType::DUAL_MODE_CG_CARD:
            [[fallthrough]]; // fall_through
        case CardType::CT_NATIONAL_ROAMING_CARD:
            [[fallthrough]]; // fall_through
        case CardType::CU_DUAL_MODE_CARD:
            [[fallthrough]]; // fall_through
        case CardType::DUAL_MODE_TELECOM_LTE_CARD:
            [[fallthrough]]; // fall_through
        case CardType::DUAL_MODE_UG_CARD:
            return GSM_FAKE_AID;
        default:
            break;
    }
    return USIM_AID;
}

void SimStateHandle::GetSimCardData(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGD("SimStateHandle::GetSimCardData slotId = %{public}d", slotId);
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
        TELEPHONY_LOGI("SimStateHandle::GetSimCardData(), slot%{public}d, type = %{public}d, status = %{public}d",
            slotId, iccState.simType_, iccState.simStatus_);
    } else {
        error = static_cast<int32_t>(response->error);
        TELEPHONY_LOGI("SimStateHandle::GetSimCardData(), slot%{public}d, error = %{public}d", slotId, error);
        return;
    }
    ProcessIccCardState(iccState, slotId);
}

void SimStateHandle::GetSimLockState(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event)
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

void SimStateHandle::GetSetLockResult(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("SimStateHandle::GetSetLockResult slotId = %{public}d", slotId);
    std::shared_ptr<LockStatusResp> param = event->GetSharedObject<LockStatusResp>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSetLockResult() fail");
        return;
    }
    if (param != nullptr) {
        unlockRespon_.result = param->result;
        unlockRespon_.remain = param->remain;
        TELEPHONY_LOGI("SimStateHandle::GetSetLockResult result = %{public}d, remain = %{public}d",
            unlockRespon_.result, unlockRespon_.remain);
    } else {
        unlockRespon_.result = static_cast<int32_t>(response->error);
    }
    TELEPHONY_LOGI("SimStateHandle::GetSetLockResult(), iccUnlockResponse = %{public}d", unlockRespon_.result);
}

void SimStateHandle::GetUnlockResult(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("SimStateHandle::GetUnlockResult slotId = %{public}d", slotId);
    std::shared_ptr<LockStatusResp> param = event->GetSharedObject<LockStatusResp>();
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if ((param == nullptr) && (response == nullptr)) {
        TELEPHONY_LOGE("SimStateHandle::GetSimUnlockResult() fail");
        return;
    }
    if (param != nullptr) {
        unlockRespon_.result = param->result;
        unlockRespon_.remain = param->remain;
        TELEPHONY_LOGE("SimStateHandle::GetUnlockReult result:%{public}d, remain:%{public}d",
            param->result, param->remain);
    } else {
        TELEPHONY_LOGE("SimStateHandle::GetUnlockResult param is null");
        unlockRespon_.result = static_cast<int32_t>(response->error);
    }
    TELEPHONY_LOGI("SimStateHandle::GetSimUnlockResponse(), iccUnlockResponse = %{public}d", unlockRespon_.result);
}

void SimStateHandle::GetUnlockSimLockResult(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event)
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

void SimStateHandle::GetSimAuthenticationResult(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("SimStateHandle::GetSimAuthenticationResult slotId = %{public}d", slotId);
    auto response = event->GetSharedObject<IccIoResultInfo>();
    if (response == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::GetSimAuthenticationResult() fail");
        return;
    }
    simAuthRespon_.sw1 = response->sw1;
    simAuthRespon_.sw2 = response->sw2;
    simAuthRespon_.response = response->response;
}

void SimStateHandle::GetSendSimMatchedOperatorInfoResult(
    int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("SimStateHandle::GetSendSimMatchedOperatorInfoResult slotId = %{public}d", slotId);
    std::shared_ptr<HRilRadioResponseInfo> response = event->GetSharedObject<HRilRadioResponseInfo>();
    if (response == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::GetSendSimMatchedOperatorInfoResult() fail");
        return;
    }
    sendSimMatchedOperatorInfoResult_ = static_cast<int32_t>(response->error);
}

SimAuthenticationResponse SimStateHandle::GetSimAuthenticationResponse()
{
    return simAuthRespon_;
}

int32_t SimStateHandle::GetSendSimMatchedOperatorInfoResponse()
{
    return sendSimMatchedOperatorInfoResult_;
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
    std::unique_lock<std::mutex> lck(SimStateManager::ctx_);
    SimStateManager::responseReady_ = true;
    TELEPHONY_LOGI("SimStateHandle::SyncCmdResponse(), responseReady_ = %{public}d", SimStateManager::responseReady_);
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
    publishInfo.SetOrdered(false);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("SimStateHandle::PublishSimStateEvent result : %{public}d", publishResult);
    return publishResult;
}

void SimStateHandle::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    uint32_t eventId = event->GetInnerEventId();
    TELEPHONY_LOGD("SimStateHandle::ProcessEvent(), eventId = %{public}d, slotId_ = %{public}d", eventId, slotId_);
    auto itFunc = memberFuncMap_.find(eventId);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(slotId_, event);
        }
        SyncCmdResponse();
        return;
    }

    switch (eventId) {
        case RadioEvent::RADIO_STATE_CHANGED:
            if (IsRadioStateUnavailable(event)) {
                break;
            }
            [[fallthrough]]; // fall_through
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            ObtainIccStatus(slotId_);
            break;
        case MSG_SIM_GET_ICC_STATUS_DONE:
            GetSimCardData(slotId_, event);
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
        TELEPHONY_LOGE("SimStateHandle::ConnectService() GetSystemAbilityManager null");
        return false;
    }
    sptr<IRemoteObject> object = systemManager->GetSystemAbility(TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID);
    if (object == nullptr) {
        TELEPHONY_LOGE("SimStateHandle::ConnectService faild");
        return false;
    }
    TELEPHONY_LOGI("SimStateHandle::ConnectService success");
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
            PublishSimStateEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_ABSENT, "");
            break;
        case ICC_CONTENT_READY:
            externalState_ = SimState::SIM_STATE_READY;
            observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_READY);
            PublishSimStateEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_READY, "");
            break;
        case ICC_CONTENT_PIN:
            externalState_ = SimState::SIM_STATE_LOCKED;
            reason = LockReason::SIM_PIN;
            observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_LOCKED);
            PublishSimStateEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_PIN, "");
            break;
        case ICC_CONTENT_PUK:
            externalState_ = SimState::SIM_STATE_LOCKED;
            reason = LockReason::SIM_PUK;
            observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_LOCKED);
            PublishSimStateEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_PUK, "");
            break;
        default:
            SimLockStateEscape(simState, slotId, reason);
            break;
    }
    CoreServiceHiSysEvent::WriteSimStateBehaviorEvent(slotId, static_cast<int32_t>(externalState_));
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
            [[fallthrough]]; // fall_through
        default:
            isSimLockState = false;
            externalState_ = SimState::SIM_STATE_UNKNOWN;
            CoreServiceHiSysEvent::WriteSimStateBehaviorEvent(slotId, static_cast<int32_t>(externalState_));
            PublishSimStateEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED,
                ICC_STATE_NOT_READY, "");
            break;
    }
    if (isSimLockState) {
        NotifySimLock(slotId);
    }
}

void SimStateHandle::NotifySimLock(int slotId)
{
    externalState_ = SimState::SIM_STATE_LOCKED;
    CoreServiceHiSysEvent::WriteSimStateBehaviorEvent(slotId, static_cast<int32_t>(externalState_));
    observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_SIMLOCK);
    PublishSimStateEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_SIMLOCK, "");
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
            if (IsIccReady() && handler != nullptr) {
                TELEPHONY_LOGI("SimStateHandle::RegisterIccReady() OK send");
                TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_SIM_STATE_READY);
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

bool SimStateHandle::IsRadioStateUnavailable(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<HRilInt32Parcel> object = event->GetSharedObject<HRilInt32Parcel>();
    if (object == nullptr) {
        TELEPHONY_LOGE("object is nullptr!");
        return false;
    }
    int32_t radioState = object->data;
    if (radioState == ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE) {
        TELEPHONY_LOGI("received radio unavailable");
        IccState iccState;
        iccState.simType_ = ICC_UNKNOWN_TYPE;
        iccState.simStatus_ = ICC_CONTENT_UNKNOWN;
        ProcessIccCardState(iccState, slotId_);
        return true;
    }
    return false;
}
} // namespace Telephony
} // namespace OHOS
