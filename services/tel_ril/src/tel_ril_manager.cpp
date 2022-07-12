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

#include "hdf_death_recipient.h"
#include "radio_event.h"
#include "telephony_errors.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
namespace OHOS {
namespace Telephony {
const std::string RIL_ADAPTER_SERVICE_NAME = "cellular_radio1";
constexpr int32_t RIL_ADAPTER_ERROR = 29189;
TelRilManager::TelRilManager() : IPCObjectStub(std::u16string(HRIL_INTERFACE_TOKEN)) {}

int32_t TelRilManager::SetCellularRadioIndication()
{
    if (rilAdapterRemoteObj_ == nullptr) {
        TELEPHONY_LOGE("hdf remote object doesn't exist.");
        return RIL_ADAPTER_ERROR;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteRemoteObject(telRilCallback_);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    return rilAdapterRemoteObj_->SendRequest(HRIL_ADAPTER_RADIO_INDICATION, data, reply, option);
}

int32_t TelRilManager::SetCellularRadioResponse()
{
    if (rilAdapterRemoteObj_ == nullptr) {
        TELEPHONY_LOGE("hdf remote object doesn't exist.");
        return RIL_ADAPTER_ERROR;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteRemoteObject(telRilCallback_);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    return rilAdapterRemoteObj_->SendRequest(HRIL_ADAPTER_RADIO_RESPONSE, data, reply, option);
}

int32_t TelRilManager::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, OHOS::MessageOption &option)
{
    auto selfToken = TelRilManager::GetObjectDescriptor();
    auto reqToken = data.ReadInterfaceToken();
    if (selfToken != reqToken) {
        TELEPHONY_LOGE("descriptor checked fail, code is %{public}d.", code);
        return CORE_SERVICE_ERROR;
    }
    HRilResponseTypes responseType = HRIL_RESPONSE_NOTICE;
    int32_t slotId = DEFAULT_SIM_SLOT_ID;

    const uint8_t *spBuffer = data.ReadUnpadBuffer(sizeof(HRilResponseHeadInfo));
    const HRilResponseHeadInfo *headInfo = reinterpret_cast<const HRilResponseHeadInfo *>(spBuffer);
    if (headInfo != nullptr) {
        slotId = headInfo->slotId;
        responseType = headInfo->type;
    } else {
        TELEPHONY_LOGW("TelRilManager code:%{public}d, headInfo parsed is failed.", code);
    }
    TELEPHONY_LOGI("TelRilManager OnRemoteRequest code:%{public}d, slotId:%{public}d, type:%{public}d",
        code, slotId, responseType);
    if ((slotId < 0) || (slotId > static_cast<int32_t>(telRilCall_.size()))) {
        TELEPHONY_LOGE("TelRilManager slotId is invalid:%{public}d", slotId);
        return CORE_SERVICE_ERROR;
    }
    if ((responseType == HRIL_RESPONSE_REQUEST_MUST_ACK) || (responseType == HRIL_RESPONSE_NOTICE_MUST_ACK)) {
        SendAckAndLock();
    }
    if (GetTelRilCall(slotId).IsCallRespOrNotify(code)) {
        return GetTelRilCall(slotId).ProcessRespOrNotify<TelRilCall>(code, data);
    }
    if (GetTelRilSms(slotId).IsSmsRespOrNotify(code)) {
        return GetTelRilSms(slotId).ProcessRespOrNotify<TelRilSms>(code, data);
    }
    if (GetTelRilSim(slotId).IsSimRespOrNotify(code)) {
        return GetTelRilSim(slotId).ProcessRespOrNotify<TelRilSim>(code, data);
    }
    if (GetTelRilNetwork(slotId).IsNetworkRespOrNotify(code)) {
        return GetTelRilNetwork(slotId).ProcessRespOrNotify<TelRilNetwork>(code, data);
    }
    if (GetTelRilData(slotId).IsDataRespOrNotify(code)) {
        return GetTelRilData(slotId).ProcessRespOrNotify<TelRilData>(code, data);
    }
    /* The common notice should be placed last. */
    if (GetTelRilModem(slotId).IsCommonRespOrNotify(code)) {
        return GetTelRilModem(slotId).ProcessRespOrNotify<TelRilModem>(code, data);
    }
    TELEPHONY_LOGE("TelRilManager not find code:%{public}d", code);
    return CORE_SERVICE_ERROR;
}

bool TelRilManager::OnInit()
{
    bool res = false;
    int32_t i = 0;

    telRilCallback_ = this;
    death_ = sptr<OHOS::IPCObjectStub::DeathRecipient>(new HdfDeathRecipient(this));
    do {
        res = ConnectRilAdapterService();
        if (!res) {
            i++;
            sleep(1);
        }
    } while (!res && (i < RIL_INIT_COUNT_MAX));
    if (res) {
        CreatTelRilHandler();
        for (int32_t slotId = SIM_SLOT_0; slotId < SIM_SLOT_COUNT; slotId++) {
            InitTelModule(slotId);
        }
    }
    return res;
}

bool TelRilManager::ConnectRilAdapterService()
{
    std::lock_guard<std::mutex> lock_l(mutex_);
    rilAdapterRemoteObj_ = nullptr;
    auto servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
    if (servMgr_ == nullptr) {
        TELEPHONY_LOGI("Get service manager error!");
        return false;
    }

    rilAdapterRemoteObj_ = servMgr_->GetService(RIL_ADAPTER_SERVICE_NAME.c_str());
    if (rilAdapterRemoteObj_ == nullptr) {
        TELEPHONY_LOGE("bind hdf error!");
        return false;
    }
    if (death_ == nullptr) {
        TELEPHONY_LOGE("create HdfDeathRecipient object failed!");
        rilAdapterRemoteObj_ = nullptr;
        return false;
    }
    if (!rilAdapterRemoteObj_->AddDeathRecipient(death_)) {
        TELEPHONY_LOGE("AddDeathRecipient hdf failed!");
        rilAdapterRemoteObj_ = nullptr;
        return false;
    }

    int32_t ret = SetCellularRadioIndication();
    if (ret != CORE_SERVICE_SUCCESS) {
        TELEPHONY_LOGE("SetCellularRadioIndication error, ret:%{public}d", ret);
        return false;
    }
    ret = SetCellularRadioResponse();
    if (ret != CORE_SERVICE_SUCCESS) {
        TELEPHONY_LOGE("SetCellularRadioResponse error, ret:%{public}d", ret);
        return false;
    }

    return true;
}

void TelRilManager::CreatTelRilHandler(void)
{
    eventLoop_ = AppExecFwk::EventRunner::Create("TelRilEventLoop");
    if (eventLoop_ == nullptr) {
        TELEPHONY_LOGE("Failed to create EventRunner");
        return;
    }
    handler_ = std::make_shared<TelRilHandler>(eventLoop_);
    handler_->OnInit();
    eventLoop_->Run();
}

void TelRilManager::SendAckAndLock(void)
{
    if (handler_ != nullptr) {
        handler_->ApplyRunningLock(TelRilHandler::ACK_RUNNING_LOCK);
    }
    SendResponseAck();
}

int32_t TelRilManager::SendResponseAck(void)
{
    if (rilAdapterRemoteObj_ == nullptr) {
        TELEPHONY_LOGE("hdf remote object doesn't exist.");
        return RIL_ADAPTER_ERROR;
    }

    MessageParcel data;
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    return rilAdapterRemoteObj_->SendRequest(HRIL_ADAPTER_RADIO_SEND_ACK, data, reply, option);
}

void TelRilManager::InitTelModule(int32_t slotId)
{
    std::shared_ptr<ObserverHandler> observerHandler = std::make_shared<ObserverHandler>();
    observerHandler_.push_back(observerHandler);
    telRilSms_.push_back(
        std::make_unique<TelRilSms>(slotId, rilAdapterRemoteObj_, observerHandler_[slotId], handler_));
    telRilSim_.push_back(
        std::make_unique<TelRilSim>(slotId, rilAdapterRemoteObj_, observerHandler_[slotId], handler_));
    telRilCall_.push_back(
        std::make_unique<TelRilCall>(slotId, rilAdapterRemoteObj_, observerHandler_[slotId], handler_));
    telRilData_.push_back(
        std::make_unique<TelRilData>(slotId, rilAdapterRemoteObj_, observerHandler_[slotId], handler_));
    telRilModem_.push_back(
        std::make_unique<TelRilModem>(slotId, rilAdapterRemoteObj_, observerHandler_[slotId], handler_));
    telRilNetwork_.push_back(
        std::make_unique<TelRilNetwork>(slotId, rilAdapterRemoteObj_, observerHandler_[slotId], handler_));
}

TelRilSms &TelRilManager::GetTelRilSms(int32_t slotId)
{
    return *telRilSms_[slotId];
}

TelRilSim &TelRilManager::GetTelRilSim(int32_t slotId)
{
    return *telRilSim_[slotId];
}

TelRilCall &TelRilManager::GetTelRilCall(int32_t slotId)
{
    return *telRilCall_[slotId];
}

TelRilData &TelRilManager::GetTelRilData(int32_t slotId)
{
    return *telRilData_[slotId];
}

TelRilNetwork &TelRilManager::GetTelRilNetwork(int32_t slotId)
{
    return *telRilNetwork_[slotId];
}

TelRilModem &TelRilManager::GetTelRilModem(int32_t slotId)
{
    return *telRilModem_[slotId];
}

std::shared_ptr<ObserverHandler> TelRilManager::GetObserverHandler(int32_t slotId)
{
    return observerHandler_[slotId];
}

bool TelRilManager::ResetRemoteObject(void)
{
    if (rilAdapterRemoteObj_ == nullptr) {
        return false;
    }

    int32_t size = static_cast<int32_t>(telRilCall_.size());
    for (int32_t slotId = 0; slotId < size; slotId++) {
        GetTelRilSms(slotId).ResetRemoteObject(rilAdapterRemoteObj_);
        GetTelRilSim(slotId).ResetRemoteObject(rilAdapterRemoteObj_);
        GetTelRilCall(slotId).ResetRemoteObject(rilAdapterRemoteObj_);
        GetTelRilData(slotId).ResetRemoteObject(rilAdapterRemoteObj_);
        GetTelRilModem(slotId).ResetRemoteObject(rilAdapterRemoteObj_);
        GetTelRilNetwork(slotId).ResetRemoteObject(rilAdapterRemoteObj_);
    }
    return true;
}

int32_t TelRilManager::RegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int32_t what, int32_t *obj)
{
    std::lock_guard<std::mutex> lock_l(mutex_);
    std::shared_ptr<ObserverHandler> observerHandler = GetObserverHandler(slotId);
    if (observerHandler != nullptr) {
        switch (what) {
            case RadioEvent::RADIO_ICC_STATUS_CHANGED:
                observerHandler->RegObserver(what, observerCallBack);
                observerHandler->NotifyObserver(RadioEvent::RADIO_ICC_STATUS_CHANGED);
                break;
            case RadioEvent::RADIO_OFF:
                observerHandler->RegObserver(what, observerCallBack);
                if (GetTelRilModem(slotId).radioState_ == CORE_SERVICE_POWER_OFF ||
                    CORE_SERVICE_POWER_NOT_AVAILABLE == GetTelRilModem(slotId).radioState_) {
                    observerHandler->NotifyObserver(what);
                }
                break;
            default:
                TELEPHONY_LOGI("RegisterCoreNotify default what:%{public}d, slotId:%{public}d", what, slotId);
                observerHandler->RegObserver(what, observerCallBack);
                break;
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilManager::UnRegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int32_t what)
{
    std::lock_guard<std::mutex> lock_l(mutex_);
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

int32_t TelRilManager::SendDtmf(
    int32_t slotId, const DtmfParam &dtmfParam, const AppExecFwk::InnerEvent::Pointer &response)
{
    // Define the function pointer type here, it is necessary to deal with
    // the function pointer difference caused by overloading
    typedef int32_t (TelRilCall::*SendDtmfFunc)(
        const std::string &, int32_t, int32_t, int32_t, const AppExecFwk::InnerEvent::Pointer &);
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), (SendDtmfFunc)&TelRilCall::SendDtmf,
        dtmfParam.sDTMFCode, dtmfParam.index, dtmfParam.switchOn, dtmfParam.switchOff);
}

int32_t TelRilManager::SendDtmf(
    int32_t slotId, char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &response)
{
    // Define the function pointer type here, it is necessary to deal with
    // the function pointer difference caused by overloading
    typedef int32_t (TelRilCall::*SendDtmfFunc)(char, int32_t, const AppExecFwk::InnerEvent::Pointer &);
    return TaskSchedule(
        response, "TelRilCall", GetTelRilCall(slotId), (SendDtmfFunc)&TelRilCall::SendDtmf, cDTMFCode, index);
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

int32_t TelRilManager::SetUssd(
    int32_t slotId, const std::string str, const AppExecFwk::InnerEvent::Pointer &response)
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

int32_t TelRilManager::SetEmergencyCallList(int32_t slotId, std::vector<EmergencyCall>  &eccVec,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGI("SetEmergencyCallList start");
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::SetEmergencyCallList, eccVec);
}

int32_t TelRilManager::GetCallFailReason(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilCall", GetTelRilCall(slotId), &TelRilCall::GetCallFailReason);
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
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::SetPreferredNetwork,
        preferredNetworkType);
}

int32_t TelRilManager::GetCellInfoList(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetCellInfoList);
}

int32_t TelRilManager::GetCurrentCellInfo(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetCurrentCellInfo);
}
int32_t TelRilManager::GetRadioCapability(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetRadioCapability);
}

int32_t TelRilManager::GetPhysicalChannelConfig(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilNetwork", GetTelRilNetwork(slotId), &TelRilNetwork::GetPhysicalChannelConfig);
}

int32_t TelRilManager::SetLocateUpdates(
    int32_t slotId, HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response)
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
    return TaskSchedule(response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::UpdateSimMessage,
        simMessage.gsmIndex, simMessage.status, simMessage.smscPdu, simMessage.pdu);
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
    return TaskSchedule(
        response, "TelRilSms", GetTelRilSms(slotId), &TelRilSms::SetCdmaCBConfig, cdmaCBConfigInfoList);
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
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SetSimLock, simLock.fac,
        simLock.mode, simLock.passwd);
}

int32_t TelRilManager::ChangeSimPassword(
    int32_t slotId, const SimPasswordParam &simPassword, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::ChangeSimPassword, simPassword.fac,
        simPassword.oldPassword, simPassword.newPassword, simPassword.passwordLength);
}

int32_t TelRilManager::UnlockPin(int32_t slotId, std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockPin, pin);
}

int32_t TelRilManager::UnlockPuk(
    int32_t slotId, std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockPuk, puk, pin);
}

int32_t TelRilManager::UnlockPin2(int32_t slotId, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockPin2, pin2);
}

int32_t TelRilManager::UnlockPuk2(
    int32_t slotId, std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
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
    int32_t slotId, ApduSimIORequestInfo reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimTransmitApduLogicalChannel, reqInfo);
}

int32_t TelRilManager::SimTransmitApduBasicChannel(
    int32_t slotId, ApduSimIORequestInfo reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimTransmitApduBasicChannel, reqInfo);
}

int32_t TelRilManager::SimAuthentication(
    int32_t slotId, SimAuthenticationRequestInfo reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(
        response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SimAuthentication, reqInfo);
}

int32_t TelRilManager::UnlockSimLock(
    int32_t slotId, int32_t lockType, std::string password, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::UnlockSimLock, lockType, password);
}

int32_t TelRilManager::SetRadioProtocol(
    int32_t slotId, SimProtocolRequest data, const AppExecFwk::InnerEvent::Pointer &response)
{
    return TaskSchedule(response, "TelRilSim", GetTelRilSim(slotId), &TelRilSim::SetRadioProtocol, data);
}
/*********************** TelRilSim end ********************************/
} // namespace Telephony
} // namespace OHOS
