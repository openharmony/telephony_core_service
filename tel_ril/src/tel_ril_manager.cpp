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
#include "tel_ril_manager.h"
#include <limits>
#include "hdf_death_recipient.h"
#include "tel_ril_common.h"
#include "hril_modem_parcel.h"
#include "hril_network_parcel.h"
#include "hril_sim_parcel.h"
#include "hril_call_parcel.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
using namespace OHOS;

RilManager::RilManager() : IPCObjectStub(std::u16string(u""))
{
    TELEPHONY_INFO_LOG("RilManager init->");
}

RilManager::~RilManager()
{
    TELEPHONY_INFO_LOG("~RilManager!");
}

int32_t RilManager::SetCellularRadioIndication()
{
    TELEPHONY_INFO_LOG("RilManager SetCellularRadioIndication start!");
    int status = RIL_ADAPTER_ERROR;
    if (cellularRadio_ != nullptr) {
        sptr<OHOS::IPCObjectStub> callback = this;
        OHOS::MessageParcel data;
        OHOS::MessageParcel reply;
        data.WriteRemoteObject(callback);
        OHOS::MessageOption option;
        status = cellularRadio_->SendRequest(HRIL_ADAPTER_RADIO_INDICATION, data, reply, option);
        TELEPHONY_INFO_LOG("SetCellularRadioIndication status:%{public}d", status);
    }
    return status;
}

int32_t RilManager::SetCellularRadioResponse()
{
    TELEPHONY_INFO_LOG("RilManager SetCellularRadioResponse start!");
    int status = RIL_ADAPTER_ERROR;
    if (cellularRadio_ != nullptr) {
        sptr<OHOS::IPCObjectStub> callback = this;
        OHOS::MessageParcel data;
        OHOS::MessageParcel reply;
        data.WriteRemoteObject(callback);
        OHOS::MessageOption option;
        status = cellularRadio_->SendRequest(HRIL_ADAPTER_RADIO_RESPONSE, data, reply, option);
        TELEPHONY_INFO_LOG("SetCellularRadioResponse status:%{public}d", status);
    }
    return status;
}

int RilManager::OnRemoteRequest(
    uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply, OHOS::MessageOption &option)
{
    TELEPHONY_INFO_LOG("RilManager OnRemoteRequest code:%{public}d", code);
    if (telRilCall_ != nullptr && telRilCall_->IsCallRespOrNotify(code)) {
        telRilCall_->ProcessCallRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilSms_ != nullptr && telRilSms_->IsSmsRespOrNotify(code)) {
        telRilSms_->ProcessSmsRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilSim_ != nullptr && telRilSim_->IsSimRespOrNotify(code)) {
        telRilSim_->ProcessSimRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilNetwork_ != nullptr && telRilNetwork_->IsNetworkRespOrNotify(code)) {
        telRilNetwork_->ProcessNetworkRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilModem_ != nullptr && telRilModem_->IsCommonRespOrNotify(code)) {
        telRilModem_->ProcessCommonRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    if (telRilData_ != nullptr && telRilData_->IsDataRespOrNotify(code)) {
        telRilData_->ProcessDataRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    return CORE_SERVICE_SUCCESS;
}

void RilManager::TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId)
{
    TELEPHONY_INFO_LOG(" RilManager TelRilSetParam->");
    preferredNetworkType_ = preferredNetworkType;
    cdmaSubscription_ = cdmaSubscription;
    phoneId_ = instanceId;
    observerHandler_ = std::make_shared<ObserverHandler>();
}

void RilManager::OnInit()
{
    TELEPHONY_INFO_LOG("RilManager OnInit start->");
    cellularRadio_ = nullptr;
    auto servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
    if (servMgr_ == nullptr) {
        TELEPHONY_ERR_LOG("IServiceManager::Get faild!");
        return;
    }
    cellularRadio_ = servMgr_->GetService(RIL_ADAPTER_SERVICE_NAME);
    if (cellularRadio_ == nullptr) {
        TELEPHONY_ERR_LOG("RilManager bindhdf error!");
        return;
    }
    TELEPHONY_INFO_LOG("RilManager bindhdf success!");
    auto death_ = sptr<IRemoteObject::DeathRecipient>(new HdfDeathRecipient());
    if (death_ == nullptr) {
        TELEPHONY_ERR_LOG("create HdfDeathRecipient object failed!");
        return;
    }
    bool res = cellularRadio_->AddDeathRecipient(death_);
    TELEPHONY_INFO_LOG("RilManager AddDeathRecipient res:%d", res);
    int32_t indicationStatus = SetCellularRadioIndication();
    if (indicationStatus == RIL_ADAPTER_ERROR) {
        TELEPHONY_ERR_LOG("RilManager SetCellularRadioIndication error ");
        OnInit();
    }
    int32_t responseStatus = SetCellularRadioResponse();
    if (responseStatus == RIL_ADAPTER_ERROR) {
        TELEPHONY_ERR_LOG("RilManager SetCellularRadioResponse error ");
        OnInit();
    }
    InitTelInfo();
}

void RilManager::InitTelInfo()
{
    telRilSms_ = std::make_unique<TelRilSms>(cellularRadio_, observerHandler_);
    if (telRilSms_ == nullptr) {
        TELEPHONY_ERR_LOG("create TelRilSms object failed!");
        return;
    }
    telRilSim_ = std::make_unique<TelRilSim>(cellularRadio_, observerHandler_);
    if (telRilSim_ == nullptr) {
        TELEPHONY_ERR_LOG("create TelRilSim object failed!");
        return;
    }
    telRilCall_ = std::make_unique<TelRilCall>(cellularRadio_, observerHandler_);
    if (telRilCall_ == nullptr) {
        TELEPHONY_ERR_LOG("create TelRilCall object failed!");
        return;
    }
    telRilNetwork_ = std::make_unique<TelRilNetwork>(cellularRadio_, observerHandler_);
    if (telRilNetwork_ == nullptr) {
        TELEPHONY_ERR_LOG("create TelRilNetwork object failed!");
        return;
    }
    telRilModem_ = std::make_unique<TelRilModem>(cellularRadio_, observerHandler_);
    if (telRilModem_ == nullptr) {
        TELEPHONY_ERR_LOG("create TelRilModem object failed!");
        return;
    }
    telRilData_ = std::make_unique<TelRilData>(cellularRadio_, observerHandler_);
    if (telRilData_ == nullptr) {
        TELEPHONY_ERR_LOG("create TelRilData object failed!");
        return;
    }
}

void RilManager::RegisterPhoneNotify(
    const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what, void *obj)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        switch (what) {
            case ObserverHandler::RADIO_ICC_STATUS_CHANGED:
                observerHandler_->RegObserver(what, observerCallBack);
                TELEPHONY_DEBUG_LOG("RegisterSimStatusChanged what:%{public}d", what);
                TELEPHONY_DEBUG_LOG("RilManagerBase::NotifyObserver----------------before");
                observerHandler_->NotifyObserver(ObserverHandler::RADIO_ICC_STATUS_CHANGED);
                TELEPHONY_DEBUG_LOG("RilManagerBase::NotifyObserver----------------after");
                break;
            case ObserverHandler::RADIO_OFF_OR_NOT_AVAIL:
                observerHandler_->RegObserver(what, observerCallBack);
                if (telRilModem_->radioState_ == CORE_SERVICE_POWER_OFF ||
                    CORE_SERVICE_POWER_NOT_AVAILABLE == telRilModem_->radioState_) {
                    observerHandler_->NotifyObserver(what);
                }
                break;
            default:
                TELEPHONY_DEBUG_LOG("RegisterPhoneNotify default what:%{public}d", what);
                observerHandler_->RegObserver(what, observerCallBack);
                break;
        }
    }
}

void RilManager::UnRegisterPhoneNotify(int what)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        observerHandler_->Remove(what);
    }
}

void RilManager::SetRadioPower(ModemPowerState radioState)
{
    TELEPHONY_INFO_LOG("RilManager SetRadioPower->");
    if (telRilModem_ != nullptr) {
        telRilModem_->SetRadioPower(radioState);
    }
}

void RilManager::SetModemRadioPower(bool on, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager SetModemRadioPower->on: %{public}d", on);
    if (telRilModem_ != nullptr) {
        telRilModem_->SetModemRadioPower(on, response);
    }
}

ModemPowerState RilManager::GetRadioState()
{
    TELEPHONY_INFO_LOG("RilManager GetRadioState->");
    if (telRilModem_ != nullptr) {
        return telRilModem_->GetRadioState();
    }

    return ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE;
}

void RilManager::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager ShutDown->");
    if (telRilModem_ != nullptr) {
        return telRilModem_->ShutDown(response);
    }
}

void RilManager::Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    Dial(address, clirMode, nullptr, result);
}

void RilManager::Dial(std::string address, int clirMode, struct UusInformation *uusInformation,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("RilManager Dial->");
    if (telRilCall_ != nullptr) {
        telRilCall_->Dial(address, clirMode, uusInformation, result);
    }
}

void RilManager::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("RilManager Reject->");
    if (telRilCall_ != nullptr) {
        telRilCall_->Reject(result);
    }
}

void RilManager::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("RilManager Hangup->");
    if (telRilCall_ != nullptr) {
        telRilCall_->Hangup(gsmIndex, result);
    }
}

void RilManager::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("RilManager Answer->");
    if (telRilCall_ != nullptr) {
        telRilCall_->Answer(result);
    }
}

void RilManager::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("RilManager GetCallList->");
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallList(result);
    }
}

void RilManager::ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager ActivatePdpContext->");
    if (telRilData_ != nullptr) {
        telRilData_->ActivatePdpContext(radioTechnology, dataProfile, isRoaming, allowRoaming, response);
    }
}

void RilManager::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager DeactivatePdpContext->");
    if (telRilData_ != nullptr) {
        telRilData_->DeactivatePdpContext(cid, reason, response);
    }
}

void RilManager::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager GetSignalStrength->");
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetSignalStrength(response);
    }
}

void RilManager::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager GetCsRegStatus->");
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetCsRegStatus(response);
    }
}

void RilManager::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager GetPsRegStatus->");
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetPsRegStatus(response);
    }
}

void RilManager::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager GetOperatorInfo->");
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetOperatorInfo(response);
    }
}

void RilManager::SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager SendSms->");
    if (telRilSms_ != nullptr) {
        telRilSms_->SendSms(smscPdu, pdu, response);
    }
}

void RilManager::SendSmsMoreMode(
    std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager SendSmsMoreMode->");
    if (telRilSms_ != nullptr) {
        telRilSms_->SendSmsMoreMode(smscPdu, pdu, response);
    }
}

void RilManager::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager SendSmsAck->");
    if (telRilSms_ != nullptr) {
        telRilSms_->SendSmsAck(success, cause, response);
    }
}

void RilManager::ReadIccFile(int32_t command, int32_t fileId, std::string path, int32_t p1, int32_t p2, int32_t p3,
    std::string data, std::string pin2, std::string aid, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("RilManager ReadIccFile->");
    if (telRilSim_ != nullptr) {
        telRilSim_->ReadIccFile(command, fileId, path, p1, p2, p3, data, pin2, aid, response);
    }
}

void RilManager::GetImsi(std::string aid, const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("RilManager GetImsi->");
    if (telRilSim_ != nullptr) {
        telRilSim_->GetImsi(aid, result);
    }
}

void RilManager::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    TELEPHONY_INFO_LOG("RilManager GetSimStatus->");
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimStatus(result);
    }
}
