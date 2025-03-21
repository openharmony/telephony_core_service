/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "tel_ril_manager.h"

#include <iservice_registry.h>
#include <iservmgr_hdi.h>
#include <unistd.h>

#include "radio_event.h"
#include "tel_ril_callback.h"
#include "telephony_errors.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
namespace OHOS {
namespace Telephony {
namespace {
constexpr const char *RIL_INTERFACE_SERVICE_NAME = "ril_service";
constexpr int32_t STATUS_OK = 0;
} // namespace
TelRilManager::TelRilManager() {}

bool TelRilManager::OnInit()
{
    CreatTelRilHandler();
    for (int32_t slotId = SIM_SLOT_0; slotId < SIM_SLOT_COUNT; slotId++) {
        InitTelModule(slotId);
    }
    int32_t res = res = RegisterHdfStatusListener();
    TELEPHONY_LOGI("TelRilManager, OnInit successfully! register hdf status is %{public}d", res);
    return true;
}

bool TelRilManager::DeInit()
{
    if (!UnRegisterHdfStatusListener()) {
        TELEPHONY_LOGE("TelRilManager::DeInit, Unregister hdf status listener failed!");
        return false;
    }
    TELEPHONY_LOGI("TelRilManager, deInit successfully!");
    return true;
}

bool TelRilManager::ConnectRilInterface()
{
    std::lock_guard<shared_mutex> lock(mutex_);
    rilInterface_ = HDI::Ril::V1_4::IRil::Get();
    if (rilInterface_ == nullptr) {
        TELEPHONY_LOGE("TelRilManager not find RilInterfaceService");
        return false;
    }
    rilInterface_->SetCallback1_4(new TelRilCallback(shared_from_this()));
    return true;
}

void TelRilManager::CreatTelRilHandler(void)
{
    handler_ = std::make_shared<TelRilHandler>();
    handler_->OnInit();
}

void TelRilManager::ReduceRunningLock()
{
    if (handler_ == nullptr) {
        TELEPHONY_LOGE("handler_ is null");
        return;
    }
    handler_->ReduceRunningLock(TelRilHandler::NORMAL_RUNNING_LOCK);
}

void TelRilManager::ReleaseRunningLock()
{
    if (handler_ == nullptr) {
        TELEPHONY_LOGE("handler_ is null");
        return;
    }
    handler_->ReleaseRunningLock(TelRilHandler::NORMAL_RUNNING_LOCK);
}

void TelRilManager::SendAckAndLock(void)
{
    if (handler_ != nullptr) {
        handler_->ApplyRunningLock(TelRilHandler::ACK_RUNNING_LOCK);
    }
    std::shared_lock<shared_mutex> lock(mutex_);
    if (rilInterface_ == nullptr) {
        TELEPHONY_LOGE("rilInterface_ is null");
        return;
    }
    rilInterface_->SendRilAck();
}

void TelRilManager::InitTelModule(int32_t slotId)
{
    std::lock_guard<shared_mutex> telRilMutex(telRilMutex_);
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    observerHandler_.push_back(observerHandler);
    std::shared_lock<shared_mutex> lock(mutex_);
    telRilSms_.push_back(std::make_shared<TelRilSms>(slotId, rilInterface_, observerHandler_[slotId], handler_));
    telRilSim_.push_back(std::make_shared<TelRilSim>(slotId, rilInterface_, observerHandler_[slotId], handler_));
    telRilCall_.push_back(std::make_shared<TelRilCall>(slotId, rilInterface_, observerHandler_[slotId], handler_));
    telRilData_.push_back(std::make_shared<TelRilData>(slotId, rilInterface_, observerHandler_[slotId], handler_));
    telRilModem_.push_back(std::make_shared<TelRilModem>(slotId, rilInterface_, observerHandler_[slotId], handler_));
    telRilNetwork_.push_back(
        std::make_shared<TelRilNetwork>(slotId, rilInterface_, observerHandler_[slotId], handler_));
}

int32_t TelRilManager::InitTelExtraModule(int32_t slotId)
{
    TELEPHONY_LOGI("InitTelExtraModule, slotId:%{public}d", slotId);
    if (slotId != SIM_SLOT_2) {
        return TELEPHONY_ERROR;
    }
    if (telRilCall_.size() == MAX_SLOT_COUNT) {
        TELEPHONY_LOGI("InitTelExtraModule, slotId = %{public}d, has been inited, return.", slotId);
        return TELEPHONY_SUCCESS;
    }
    InitTelModule(slotId);
    ResetRilInterfaceBySlotId(slotId);
    return TELEPHONY_SUCCESS;
}

std::shared_ptr<TelRilSms> TelRilManager::GetTelRilSms(int32_t slotId)
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    if (slotId < 0 || static_cast<size_t>(slotId) >= telRilSms_.size()) {
        TELEPHONY_LOGE("telRilSms_ slotId is valid");
        return nullptr;
    }
    return telRilSms_[slotId];
}

std::shared_ptr<TelRilSim> TelRilManager::GetTelRilSim(int32_t slotId)
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    if (slotId < 0 || static_cast<size_t>(slotId) >= telRilSim_.size()) {
        TELEPHONY_LOGE("telRilSim_ slotId is valid");
        return nullptr;
    }
    return telRilSim_[slotId];
}

int32_t TelRilManager::GetTelRilSimSize()
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    int32_t size = static_cast<int32_t>(telRilSim_.size());
    return size;
}

std::shared_ptr<TelRilCall> TelRilManager::GetTelRilCall(int32_t slotId)
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    if (slotId < 0 || static_cast<size_t>(slotId) >= telRilCall_.size()) {
        TELEPHONY_LOGE("telRilCall_ slotId is valid");
        return nullptr;
    }
    return telRilCall_[slotId];
}

std::shared_ptr<TelRilData> TelRilManager::GetTelRilData(int32_t slotId)
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    if (slotId < 0 || static_cast<size_t>(slotId) >= telRilData_.size()) {
        TELEPHONY_LOGE("telRilData_ slotId is valid");
        return nullptr;
    }
    return telRilData_[slotId];
}

std::shared_ptr<TelRilNetwork> TelRilManager::GetTelRilNetwork(int32_t slotId)
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    if (slotId < 0 || static_cast<size_t>(slotId) >= telRilNetwork_.size()) {
        TELEPHONY_LOGE("telRilNetwork_ slotId is valid");
        return nullptr;
    }
    return telRilNetwork_[slotId];
}

std::shared_ptr<TelRilModem> TelRilManager::GetTelRilModem(int32_t slotId)
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    if (slotId < 0 || static_cast<size_t>(slotId) >= telRilModem_.size()) {
        TELEPHONY_LOGE("telRilModem_ slotId is valid");
        return nullptr;
    }
    return telRilModem_[slotId];
}

int32_t TelRilManager::GetTelRilModemSize()
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    int32_t size = static_cast<int32_t>(telRilModem_.size());
    return size;
}

std::shared_ptr<ObserverHandler> TelRilManager::GetObserverHandler(int32_t slotId)
{
    std::shared_lock<shared_mutex> telRilMutex(telRilMutex_);
    if (slotId < 0 || static_cast<size_t>(slotId) >= observerHandler_.size()) {
        TELEPHONY_LOGE("observerHandler_ slotId %{public}d is valid", slotId);
        return nullptr;
    }
    return observerHandler_[slotId];
}

bool TelRilManager::ResetRilInterface(void)
{
    int32_t size = static_cast<int32_t>(telRilCall_.size());
    TELEPHONY_LOGI("ResetRilInterface size: %{public}d", size);
    for (int32_t slotId = 0; slotId < size; slotId++) {
        ResetRilInterfaceBySlotId(slotId);
    }
    return true;
}

void TelRilManager::ResetRilInterfaceBySlotId(int32_t slotId)
{
    std::shared_lock<shared_mutex> lock(mutex_);
    if (GetTelRilSms(slotId) != nullptr) {
        GetTelRilSms(slotId)->ResetRilInterface(rilInterface_);
    }
    if (GetTelRilSim(slotId) != nullptr) {
        GetTelRilSim(slotId)->ResetRilInterface(rilInterface_);
    }
    if (GetTelRilCall(slotId) != nullptr) {
        GetTelRilCall(slotId)->ResetRilInterface(rilInterface_);
    }
    if (GetTelRilData(slotId) != nullptr) {
        GetTelRilData(slotId)->ResetRilInterface(rilInterface_);
    }
    if (GetTelRilModem(slotId) != nullptr) {
        GetTelRilModem(slotId)->ResetRilInterface(rilInterface_);
    }
    if (GetTelRilNetwork(slotId) != nullptr) {
        GetTelRilNetwork(slotId)->ResetRilInterface(rilInterface_);
    }
}

int32_t TelRilManager::RegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int32_t what, int32_t *obj)
{
    std::lock_guard<shared_mutex> lock(mutex_);
    std::shared_ptr<ObserverHandler> observerHandler = GetObserverHandler(slotId);
    if (observerHandler != nullptr) {
        switch (what) {
            case RadioEvent::RADIO_ICC_STATUS_CHANGED:
                observerHandler->RegObserver(what, observerCallBack);
                observerHandler->NotifyObserver(RadioEvent::RADIO_ICC_STATUS_CHANGED);
                break;
            case RadioEvent::RADIO_OFF:
                observerHandler->RegObserver(what, observerCallBack);
                if (GetTelRilModem(slotId) == nullptr) {
                    TELEPHONY_LOGE("telRilModem_ slotId is valid");
                    return TELEPHONY_ERR_LOCAL_PTR_NULL;
                }
                if (GetTelRilModem(slotId)->radioState_ == CORE_SERVICE_POWER_OFF ||
                    CORE_SERVICE_POWER_NOT_AVAILABLE == GetTelRilModem(slotId)->radioState_) {
                    observerHandler->NotifyObserver(what);
                }
                break;
            case RadioEvent::RADIO_STATE_CHANGED:
                {
                    observerHandler->RegObserver(what, observerCallBack);
                    if (GetTelRilModem(slotId) == nullptr) {
                        TELEPHONY_LOGE("telRilModem_ slotId is valid");
                        return TELEPHONY_ERR_LOCAL_PTR_NULL;
                    }
                    auto state = static_cast<int32_t>(GetTelRilModem(slotId)->radioState_);
                    TelEventHandler::SendTelEvent(observerCallBack, what, std::make_shared<Int32Parcel>(state));
                }
                break;
            default:
                TELEPHONY_LOGD("RegisterCoreNotify default what:%{public}d, slotId:%{public}d", what, slotId);
                observerHandler->RegObserver(what, observerCallBack);
                break;
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilManager::UnRegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int32_t what)
{
    std::lock_guard<shared_mutex> lock(mutex_);
    std::shared_ptr<ObserverHandler> observerHandler = GetObserverHandler(slotId);
    if (observerHandler != nullptr) {
        observerHandler->Remove(what, observerCallBack);
    } else {
        TELEPHONY_LOGE("observerHandler_ is null");
    }
    return TELEPHONY_ERR_SUCCESS;
}

/*********************** TelRilModem start **************************/
int32_t TelRilManager::SetRadioState(
    int32_t slotId, int32_t fun, int32_t rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilModem", GetTelRilModem(slotId), &TelRilModem::SetRadioState, fun, rst);
}

int32_t TelRilManager::GetRadioState(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilModem", GetTelRilModem(slotId), &TelRilModem::GetRadioState);
}

int32_t TelRilManager::ShutDown(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilModem", GetTelRilModem(slotId), &TelRilModem::ShutDown);
}

int32_t TelRilManager::GetVoiceRadioTechnology(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilModem", GetTelRilModem(slotId), &TelRilModem::GetVoiceRadioTechnology);
}

int32_t TelRilManager::GetImei(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilModem", GetTelRilModem(slotId), &TelRilModem::GetImei);
}

int32_t TelRilManager::GetImeiSv(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilModem", GetTelRilModem(slotId), &TelRilModem::GetImeiSv);
}

int32_t TelRilManager::GetMeid(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilModem", GetTelRilModem(slotId), &TelRilModem::GetMeid);
}

int32_t TelRilManager::GetBasebandVersion(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilModem", GetTelRilModem(slotId), &TelRilModem::GetBasebandVersion);
}

/*********************** TelRilModem end ***************************/
/*********************** TelRilCall start **************************/
int32_t TelRilManager::Dial(
    int32_t slotId, std::string address, int32_t clirMode, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::Dial, address, clirMode);
}

int32_t TelRilManager::Reject(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::Reject);
}

int32_t TelRilManager::HoldCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::HoldCall);
}

int32_t TelRilManager::UnHoldCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::UnHoldCall);
}

int32_t TelRilManager::SwitchCall(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SwitchCall);
}

int32_t TelRilManager::Hangup(int32_t slotId, int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::Hangup, gsmIndex);
}

int32_t TelRilManager::Answer(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::Answer);
}

int32_t TelRilManager::CombineConference(
    int32_t slotId, int32_t callType, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::CombineConference, callType);
}

int32_t TelRilManager::SeparateConference(
    int32_t slotId, int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SeparateConference, callIndex, callType);
}

int32_t TelRilManager::CallSupplement(int32_t slotId, int32_t type, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::CallSupplement, type);
}

int32_t TelRilManager::GetCallList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetCallList);
}

int32_t TelRilManager::GetCallWaiting(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetCallWaiting);
}

int32_t TelRilManager::SetCallWaiting(
    int32_t slotId, const int32_t activate, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetCallWaiting, activate);
}

int32_t TelRilManager::GetCallTransferInfo(
    int32_t slotId, const int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetCallTransferInfo, reason);
}

int32_t TelRilManager::SetCallTransferInfo(
    int32_t slotId, const CallTransferParam &callTransfer, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetCallTransferInfo,
        callTransfer.reason, callTransfer.mode, callTransfer.number, callTransfer.classx);
}

int32_t TelRilManager::GetClip(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetClip);
}

int32_t TelRilManager::SetClip(int32_t slotId, const int32_t action, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetClip, action);
}

int32_t TelRilManager::GetClir(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetClir);
}

int32_t TelRilManager::SetClir(int32_t slotId, const int32_t action, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetClir, action);
}

int32_t TelRilManager::GetCallRestriction(
    int32_t slotId, std::string fac, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetCallRestriction, fac);
}

int32_t TelRilManager::SetCallRestriction(
    int32_t slotId, const CallRestrictionParam &callRestriction, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetCallRestriction,
        callRestriction.fac, callRestriction.mode, callRestriction.password);
}

int32_t TelRilManager::SetBarringPassword(int32_t slotId, const char *oldPassword,
    const char *newPassword, const std::string &restrictionType, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetBarringPassword,
        restrictionType, oldPassword, newPassword);
}

int32_t TelRilManager::SendDtmf(
    int32_t slotId, const DtmfParam &dtmfParam, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SendDtmfString, dtmfParam.sDTMFCode,
        dtmfParam.index, dtmfParam.switchOn, dtmfParam.switchOff);
}

int32_t TelRilManager::SendDtmf(
    int32_t slotId, char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SendDtmf, cDTMFCode, index);
}

int32_t TelRilManager::StartDtmf(
    int32_t slotId, char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::StartDtmf, cDTMFCode, index);
}

int32_t TelRilManager::StopDtmf(int32_t slotId, int32_t index, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::StopDtmf, index);
}

int32_t TelRilManager::SetCallPreferenceMode(
    int32_t slotId, const int32_t mode, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetCallPreferenceMode, mode);
}

int32_t TelRilManager::GetCallPreferenceMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetCallPreferenceMode);
}

int32_t TelRilManager::SetUssd(int32_t slotId, const std::string str, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetUssd, str);
}

int32_t TelRilManager::GetUssd(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetUssd);
}

int32_t TelRilManager::SetMute(int32_t slotId, const int32_t mute, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetMute, mute);
}

int32_t TelRilManager::GetMute(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetMute);
}

int32_t TelRilManager::GetEmergencyCallList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetEmergencyCallList);
}

int32_t TelRilManager::SetEmergencyCallList(
    int32_t slotId, const std::vector<EmergencyCall> &eccVec, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGD("SetEmergencyCallList start");
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetEmergencyCallList, eccVec);
}

int32_t TelRilManager::GetCallFailReason(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetCallFailReason);
}

int32_t TelRilManager::CloseUnFinishedUssd(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::CloseUnFinishedUssd);
}

int32_t TelRilManager::SetVoNRSwitch(
    int32_t slotId, const int32_t state, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetVoNRSwitch, state);
}

/*********************** TelRilCall end ****************************/
/*********************** TelRilData start **************************/
int32_t TelRilManager::SetInitApnInfo(
    int32_t slotId, const DataProfile &dataProfile, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::SetInitApnInfo, dataProfile);
}

int32_t TelRilManager::ActivatePdpContext(
    int32_t slotId, const ActivateDataParam &activateData, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::ActivatePdpContext,
        activateData.radioTechnology, activateData.dataProfile, activateData.isRoaming, activateData.allowRoaming);
}

int32_t TelRilManager::DeactivatePdpContext(
    int32_t slotId, int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::DeactivatePdpContext, cid, reason);
}

int32_t TelRilManager::GetPdpContextList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::GetPdpContextList);
}

int32_t TelRilManager::SetLinkBandwidthReportingRule(
    int32_t slotId, LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilData", GetTelRilData(slotId), &TelRilData::SetLinkBandwidthReportingRule, linkBandwidth);
}

int32_t TelRilManager::GetLinkBandwidthInfo(
    int32_t slotId, const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::GetLinkBandwidthInfo, cid);
}

int32_t TelRilManager::SetDataPermitted(
    int32_t slotId, int32_t dataPermitted, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::SetDataPermitted, dataPermitted);
}

int32_t TelRilManager::GetLinkCapability(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::GetLinkCapability);
}

int32_t TelRilManager::CleanAllConnections(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::CleanAllConnections);
}

int32_t TelRilManager::SendUrspDecodeResult(int32_t slotId, std::vector<uint8_t> buffer,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId),
        &TelRilData::SendUrspDecodeResult, buffer);
}
 
int32_t TelRilManager::SendUePolicySectionIdentifier(int32_t slotId,
    std::vector<uint8_t> buffer, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId),
        &TelRilData::SendUePolicySectionIdentifier, buffer);
}

int32_t TelRilManager::SendImsRsdList(int32_t slotId,
    std::vector<uint8_t> buffer, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::SendImsRsdList, buffer);
}

int32_t TelRilManager::GetNetworkSliceAllowedNssai(int32_t slotId,
    std::vector<uint8_t> buffer, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId),
        &TelRilData::GetNetworkSliceAllowedNssai, buffer);
}

int32_t TelRilManager::GetNetworkSliceEhplmn(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilData", GetTelRilData(slotId), &TelRilData::GetNetworkSliceEhplmn);
}

/*********************** TelRilData end ****************************/
/*********************** TelRilNetwork start ***********************/
int32_t TelRilManager::GetSignalStrength(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetSignalStrength);
}

int32_t TelRilManager::GetCsRegStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetCsRegStatus);
}

int32_t TelRilManager::GetPsRegStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetPsRegStatus);
}

int32_t TelRilManager::GetOperatorInfo(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetOperatorInfo);
}

int32_t TelRilManager::GetNetworkSearchInformation(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetNetworkSearchInformation);
}

int32_t TelRilManager::GetNetworkSelectionMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetNetworkSelectionMode);
}

int32_t TelRilManager::SetNetworkSelectionMode(
    int32_t slotId, int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::SetNetworkSelectionMode,
        automaticFlag, oper);
}

int32_t TelRilManager::GetPreferredNetwork(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetPreferredNetwork);
}

int32_t TelRilManager::SetPreferredNetwork(
    int32_t slotId, int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::SetPreferredNetwork, preferredNetworkType);
}

int32_t TelRilManager::GetNeighboringCellInfoList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetNeighboringCellInfoList);
}

int32_t TelRilManager::GetCurrentCellInfo(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetCurrentCellInfo);
}

int32_t TelRilManager::GetPhysicalChannelConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetPhysicalChannelConfig);
}

int32_t TelRilManager::SetLocateUpdates(
    int32_t slotId, RegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::SetLocateUpdates, mode);
}

int32_t TelRilManager::SetNotificationFilter(
    int32_t slotId, int32_t newFilter, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::SetNotificationFilter, newFilter);
}

int32_t TelRilManager::SetDeviceState(
    int32_t slotId, int32_t deviceStateType, bool deviceStateOn, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::SetDeviceState,
        deviceStateType, deviceStateOn);
}

int32_t TelRilManager::SetNrOptionMode(int32_t slotId, int32_t mode, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::SetNrOptionMode, mode);
}

int32_t TelRilManager::GetNrOptionMode(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetNrOptionMode);
}

int32_t TelRilManager::GetRrcConnectionState(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetRrcConnectionState);
}

int32_t TelRilManager::GetNrSsbId(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetNrSsbId);
}

/*********************** TelRilNetwork end ****************************/
/*********************** TelRilSms start ******************************/
int32_t TelRilManager::SendGsmSms(
    int32_t slotId, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::SendGsmSms, smscPdu, pdu);
}

int32_t TelRilManager::SendCdmaSms(int32_t slotId, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::SendCdmaSms, pdu);
}

int32_t TelRilManager::AddSimMessage(
    int32_t slotId, const SimMessageParam &simMessage, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::AddSimMessage, simMessage.status,
        simMessage.smscPdu, simMessage.pdu);
}

int32_t TelRilManager::DelSimMessage(int32_t slotId, int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::DelSimMessage, gsmIndex);
}

int32_t TelRilManager::UpdateSimMessage(
    int32_t slotId, const SimMessageParam &simMessage, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::UpdateSimMessage, simMessage.gsmIndex,
        simMessage.status, simMessage.smscPdu, simMessage.pdu);
}

int32_t TelRilManager::GetSmscAddr(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::GetSmscAddr);
}

int32_t TelRilManager::GetCdmaCBConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::GetCdmaCBConfig);
}

int32_t TelRilManager::SetSmscAddr(
    int32_t slotId, int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::SetSmscAddr, tosca, address);
}

int32_t TelRilManager::SetCBConfig(
    int32_t slotId, const CBConfigParam &cbConfig, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::SetCBConfig, cbConfig.mode,
        cbConfig.idList, cbConfig.dcsList);
}

int32_t TelRilManager::SetCdmaCBConfig(
    int32_t slotId, CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::SetCdmaCBConfig, cdmaCBConfigInfoList);
}

int32_t TelRilManager::GetCBConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::GetCBConfig);
}

int32_t TelRilManager::SendSmsMoreMode(
    int32_t slotId, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::SendSmsMoreMode, smscPdu, pdu);
}

int32_t TelRilManager::SendSmsAck(
    int32_t slotId, bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::SendSmsAck, success, cause);
}

int32_t TelRilManager::AddCdmaSimMessage(
    int32_t slotId, int32_t status, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::AddCdmaSimMessage, status, pdu);
}

int32_t TelRilManager::DelCdmaSimMessage(
    int32_t slotId, int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::DelCdmaSimMessage, cdmaIndex);
}

int32_t TelRilManager::UpdateCdmaSimMessage(
    int32_t slotId, const CdmaSimMessageParam &cdmaSimMsg, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::UpdateCdmaSimMessage,
        cdmaSimMsg.cdmaIndex, cdmaSimMsg.status, cdmaSimMsg.pdu);
}

/*********************** TelRilSms end ********************************/
/*********************** TelRilSim start ******************************/
int32_t TelRilManager::GetSimStatus(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::GetSimStatus);
}

int32_t TelRilManager::GetSimIO(int32_t slotId, SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::GetSimIO, data);
}

int32_t TelRilManager::GetImsi(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::GetImsi);
}

int32_t TelRilManager::GetSimLockStatus(
    int32_t slotId, std::string fac, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::GetSimLockStatus, fac);
}

int32_t TelRilManager::SetSimLock(
    int32_t slotId, const SimLockParam &simLock, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SetSimLock, simLock.fac, simLock.mode, simLock.passwd);
}

int32_t TelRilManager::ChangeSimPassword(
    int32_t slotId, const SimPasswordParam &simPassword, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::ChangeSimPassword, simPassword.fac,
        simPassword.oldPassword, simPassword.newPassword, simPassword.passwordLength);
}

int32_t TelRilManager::UnlockPin(
    int32_t slotId, const std::string &pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockPin, pin);
}

int32_t TelRilManager::UnlockPuk(
    int32_t slotId, const std::string &puk, const std::string &pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockPuk, puk, pin);
}

int32_t TelRilManager::UnlockPin2(
    int32_t slotId, const std::string &pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockPin2, pin2);
}

int32_t TelRilManager::UnlockPuk2(
    int32_t slotId, const std::string &puk2, const std::string &pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockPuk2, puk2, pin2);
}

int32_t TelRilManager::SetActiveSim(
    int32_t slotId, int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SetActiveSim, index, enable);
}

int32_t TelRilManager::SendTerminalResponseCmd(
    int32_t slotId, const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimStkSendTerminalResponse, strCmd);
}

int32_t TelRilManager::SendEnvelopeCmd(
    int32_t slotId, const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimStkSendEnvelope, strCmd);
}

int32_t TelRilManager::SendCallSetupRequestResult(
    int32_t slotId, bool accept, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimStkSendCallSetupRequestResult, accept);
}

int32_t TelRilManager::SimStkIsReady(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimStkIsReady);
}

int32_t TelRilManager::SimOpenLogicalChannel(
    int32_t slotId, const std::string &appID, const int32_t p2, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimOpenLogicalChannel, appID.substr(0), p2);
}

int32_t TelRilManager::SimCloseLogicalChannel(
    int32_t slotId, const int32_t channelId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimCloseLogicalChannel, channelId);
}

int32_t TelRilManager::SimTransmitApduLogicalChannel(
    int32_t slotId, const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimTransmitApduLogicalChannel, reqInfo);
}

int32_t TelRilManager::SimTransmitApduBasicChannel(
    int32_t slotId, const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimTransmitApduBasicChannel, reqInfo);
}

int32_t TelRilManager::SimAuthentication(
    int32_t slotId, const SimAuthenticationRequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimAuthentication, reqInfo);
}

int32_t TelRilManager::UnlockSimLock(
    int32_t slotId, int32_t lockType, std::string password, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockSimLock, lockType, password);
}

int32_t TelRilManager::SendSimMatchedOperatorInfo(
    int32_t slotId, const NcfgOperatorInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SendSimMatchedOperatorInfo, reqInfo);
}

int32_t TelRilManager::GetRadioProtocol(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::GetRadioProtocol);
}

int32_t TelRilManager::SetRadioProtocol(
    int32_t slotId, RadioProtocol radioProtocol, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SetRadioProtocol, radioProtocol);
}
/*********************** TelRilSim end ********************************/

void TelRilManager::HandleRilInterfaceStatusCallback(const OHOS::HDI::ServiceManager::V1_0::ServiceStatus &status)
{
    TELEPHONY_LOGD("TelRilManager::HandleRilInterfaceCallback, service name %{public}s %{public}d",
        status.serviceName.c_str(), status.status);
    if (status.serviceName != std::string(RIL_INTERFACE_SERVICE_NAME)) {
        return;
    }
    if (status.deviceClass != DEVICE_CLASS_DEFAULT) {
        TELEPHONY_LOGE("TelRilManager::HandleRilInterfaceCallback, deviceClass mismatch");
        return;
    }
    if (status.status == SERVIE_STATUS_START) {
        if (!ReConnectRilInterface()) {
            TELEPHONY_LOGE("TelRilManager::HandleRilInterfaceCallback, ReConnectRilAdapterService fail");
            return;
        }
        TELEPHONY_LOGI("TelRilManager::HandleRilInterfaceCallback, reconnect riladapter service success");
        int32_t size = GetTelRilSimSize();
        for (int32_t slotId = SIM_SLOT_0; slotId < size; slotId++) {
            if (GetTelRilSim(slotId) != nullptr) {
                GetTelRilSim(slotId)->SimStateUpdated();
                TELEPHONY_LOGI("TelRilManager::HandleRilInterfaceCallback, reconnect riladapter update simstate");
            }
        }
        return;
    }
    if (status.status == SERVIE_STATUS_STOP) {
        if (!DisConnectRilInterface()) {
            TELEPHONY_LOGE("TelRilManager::HandleRilInterfaceCallback, DisConnectRilAdapterService fail");
            return;
        }
        int32_t size = GetTelRilModemSize();
        TELEPHONY_LOGI("TelRilManager::HandleRilInterfaceCallback, size:%{public}d", size);
        for (int32_t slotId = SIM_SLOT_0; slotId < size; slotId++) {
            if (GetTelRilModem(slotId) != nullptr) {
                GetTelRilModem(slotId)->OnRilAdapterHostDied();
            }
        }
        ReleaseRunningLock();
        TELEPHONY_LOGI("TelRilManager::HandleRilInterfaceCallback, disconnect riladapter service successfully!");
        return;
    }
}

bool TelRilManager::RegisterHdfStatusListener()
{
    if (servMgr_ == nullptr) {
        servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
        if (servMgr_ == nullptr) {
            TELEPHONY_LOGE("TelRilManager::RegisterHdfStatusListener, servMgr_ is nullptr");
            return false;
        }
    }

    hdfListener_ = new HdfServiceStatusListener(
        HdfServiceStatusListener::StatusCallback([wp = std::weak_ptr<TelRilManager>(shared_from_this())]
            (const OHOS::HDI::ServiceManager::V1_0::ServiceStatus &status) {
            auto telRilManager = wp.lock();
            if (telRilManager == nullptr) {
                return;
            }
            telRilManager->HandleRilInterfaceStatusCallback(status);
        }));

    int status = servMgr_->RegisterServiceStatusListener(hdfListener_, DEVICE_CLASS_DEFAULT);
    if (status != STATUS_OK) {
        TELEPHONY_LOGE("TelRilManager::RegisterHdfStatusListener, register failed!");
        return false;
    }
    return true;
}

bool TelRilManager::UnRegisterHdfStatusListener()
{
    if (servMgr_ == nullptr) {
        servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
        if (servMgr_ == nullptr) {
            TELEPHONY_LOGE("TelRilManager::UnRegisterHdfStatusListener, servmgr_ is nullptr");
            return false;
        }
    }
    if (hdfListener_ == nullptr) {
        TELEPHONY_LOGE("TelRilManager::UnRegisterHdfStatusListener, hdfListener_ is nullptr");
        return false;
    }

    int status = servMgr_->UnregisterServiceStatusListener(hdfListener_);
    if (status != STATUS_OK) {
        TELEPHONY_LOGE("TelRilManager::UnRegisterHdfStatusListener, unregister failed!");
        return false;
    }

    TELEPHONY_LOGD("TelRilManager::UnRegisterHdfStatusListener, unregister successfully!");
    return true;
}

bool TelRilManager::ReConnectRilInterface()
{
    if (rilInterface_ != nullptr) {
        TELEPHONY_LOGI("TelRilManager::ReConnectRilInterface has been successfully connected!");
        return true;
    }

    if (!ConnectRilInterface()) {
        TELEPHONY_LOGE("TelRilManager::ReConnectRilInterface, Connect riladapter service failed!");
        return false;
    }

    if (!ResetRilInterface()) {
        TELEPHONY_LOGE("TelRilManager::ReConnectRilInterface, Reset remote object failed!");
        return false;
    }
    TELEPHONY_LOGD("TelRilManager::ReConnectRilInterface, Connect riladapter service successfully!");
    return true;
}

bool TelRilManager::DisConnectRilInterface()
{
    std::unique_lock<shared_mutex> lock(mutex_);
    if (rilInterface_ == nullptr) {
        TELEPHONY_LOGD("TelRilManager::DisConnectRilInterface has been successfully disconnected!");
        return true;
    }
    rilInterface_ = nullptr;
    lock.unlock();
    if (!ResetRilInterface()) {
        TELEPHONY_LOGE("TelRilManager::DisConnectRilInterface, Reset remote object failed!");
        return false;
    }
    TELEPHONY_LOGD("TelRilManager::DisConnectRilInterface, disconnect riladapter service successfully");
    return true;
}
} // namespace Telephony
} // namespace OHOS
