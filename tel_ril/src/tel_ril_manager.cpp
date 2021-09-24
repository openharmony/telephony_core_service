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
#include <unistd.h>
#include "hdf_death_recipient.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
namespace OHOS {
namespace Telephony {
RilManager::RilManager() : IPCObjectStub(std::u16string(u""))
{
    TELEPHONY_LOGD("RilManager init->");
}

RilManager::~RilManager()
{
    TELEPHONY_LOGD("~RilManager!");
}

int32_t RilManager::SetCellularRadioIndication(bool isFirst)
{
    int32_t status = RIL_ADAPTER_ERROR;
    if (cellularRadio_ != nullptr) {
        sptr<OHOS::IPCObjectStub> callback = this;
        MessageParcel data;
        MessageParcel reply;
        /* Prevent OHOS::IPCObjectStub from getting abnormal. */
        if (isFirst) {
            telRilCallback_ = callback;
        } else {
            callback = telRilCallback_;
        }
        data.WriteRemoteObject(callback);
        OHOS::MessageOption option;
        status = cellularRadio_->SendRequest(HRIL_ADAPTER_RADIO_INDICATION, data, reply, option);
        TELEPHONY_LOGD("SetCellularRadioIndication status:%{public}d", status);
    }
    return status;
}

int32_t RilManager::SetCellularRadioResponse(bool isFirst)
{
    int status = RIL_ADAPTER_ERROR;
    if (cellularRadio_ != nullptr) {
        sptr<OHOS::IPCObjectStub> callback = this;
        MessageParcel data;
        MessageParcel reply;
        /* Prevent OHOS::IPCObjectStub from getting abnormal. */
        if (isFirst) {
            telRilCallback_ = callback;
        } else {
            callback = telRilCallback_;
        }
        data.WriteRemoteObject(callback);
        OHOS::MessageOption option;
        status = cellularRadio_->SendRequest(HRIL_ADAPTER_RADIO_RESPONSE, data, reply, option);
        TELEPHONY_LOGD("SetCellularRadioResponse status:%{public}d", status);
    }
    return status;
}

int RilManager::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, OHOS::MessageOption &option)
{
    TELEPHONY_LOGD("RilManager OnRemoteRequest code:%{public}d", code);
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
    if (telRilData_ != nullptr && telRilData_->IsDataRespOrNotify(code)) {
        telRilData_->ProcessDataRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    /* The common notice should be placed last. */
    if (telRilModem_ != nullptr && telRilModem_->IsCommonRespOrNotify(code)) {
        telRilModem_->ProcessCommonRespOrNotify(code, data);
        return CORE_SERVICE_SUCCESS;
    }
    return CORE_SERVICE_SUCCESS;
}

void RilManager::TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId)
{
    preferredNetworkType_ = preferredNetworkType;
    cdmaSubscription_ = cdmaSubscription;
    slotId_ = instanceId;
    observerHandler_ = std::make_shared<ObserverHandler>();
}

void RilManager::OnInit()
{
    bool res = false;
    int i = 0;

    do {
        res = InitCellularRadio(true);
        if (!res) {
            sleep(1);
            i++;
            TELEPHONY_LOGD("Initialization cellular radio failed. Try initialization again!");
        }
    } while (!res && (i < RIL_INIT_COUNT_MAX));
    InitTelInfo();
}

bool RilManager::InitCellularRadio(bool isFirst)
{
    int i = 0;
    cellularRadio_ = nullptr;
    auto servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
    while (servMgr_ == nullptr) {
        TELEPHONY_LOGD("bind hdf error! time:%{public}d", i++);
        sleep(1);
        servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
    }
    switch (slotId_) {
        case HRIL_SIM_1:
            cellularRadio_ = servMgr_->GetService(RIL_ADAPTER_SERVICE_NAME);
            break;
        default:
            cellularRadio_ = servMgr_->GetService(RIL_ADAPTER_SERVICE_NAME);
            break;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("bind hdf%{public}d error!", slotId_);
        return false;
    }
    auto death_ = sptr<IRemoteObject::DeathRecipient>(new HdfDeathRecipient(slotId_));
    if (death_ == nullptr) {
        TELEPHONY_LOGE("create HdfDeathRecipient object failed!");
        return false;
    }
    bool res = cellularRadio_->AddDeathRecipient(death_);
    if (!res) {
        TELEPHONY_LOGE("AddDeathRecipient hdfId:%{public}d failed!", slotId_);
        return false;
    }
    int32_t retStatus = SetCellularRadioIndication(isFirst);
    if (retStatus == RIL_ADAPTER_ERROR) {
        TELEPHONY_LOGE("SetCellularRadioIndication error ");
        return false;
    }
    retStatus = SetCellularRadioResponse(isFirst);
    if (retStatus == RIL_ADAPTER_ERROR) {
        TELEPHONY_LOGE("SetCellularRadioResponse error ");
        return false;
    }
    return true;
}

void RilManager::InitTelInfo()
{
    telRilSms_ = std::make_unique<TelRilSms>(cellularRadio_, observerHandler_);
    if (telRilSms_ == nullptr) {
        TELEPHONY_LOGE("create TelRilSms object failed!");
        return;
    }
    telRilSim_ = std::make_unique<TelRilSim>(cellularRadio_, observerHandler_);
    if (telRilSim_ == nullptr) {
        TELEPHONY_LOGE("create TelRilSim object failed!");
        return;
    }
    telRilCall_ = std::make_unique<TelRilCall>(cellularRadio_, observerHandler_);
    if (telRilCall_ == nullptr) {
        TELEPHONY_LOGE("create TelRilCall object failed!");
        return;
    }
    telRilNetwork_ = std::make_unique<TelRilNetwork>(cellularRadio_, observerHandler_);
    if (telRilNetwork_ == nullptr) {
        TELEPHONY_LOGE("create TelRilNetwork object failed!");
        return;
    }
    telRilModem_ = std::make_unique<TelRilModem>(cellularRadio_, observerHandler_);
    if (telRilModem_ == nullptr) {
        TELEPHONY_LOGE("create TelRilModem object failed!");
        return;
    }
    telRilData_ = std::make_unique<TelRilData>(cellularRadio_, observerHandler_);
    if (telRilData_ == nullptr) {
        TELEPHONY_LOGE("create TelRilData object failed!");
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
                observerHandler_->NotifyObserver(ObserverHandler::RADIO_ICC_STATUS_CHANGED);
                break;
            case ObserverHandler::RADIO_OFF:
                observerHandler_->RegObserver(what, observerCallBack);
                if (telRilModem_->radioState_ == CORE_SERVICE_POWER_OFF ||
                    CORE_SERVICE_POWER_NOT_AVAILABLE == telRilModem_->radioState_) {
                    observerHandler_->NotifyObserver(what);
                }
                break;
            default:
                TELEPHONY_LOGD("RegisterPhoneNotify default what:%{public}d", what);
                observerHandler_->RegObserver(what, observerCallBack);
                break;
        }
    }
}

void RilManager::UnRegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        observerHandler_->Remove(what, observerCallBack);
    } else {
        TELEPHONY_LOGE("observerHandler_ is null");
    }
}

void RilManager::SetRadioStatus(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGD("RilManager SetRadioStatus->fun: %{public}d,rst->%{public}d", fun, rst);
    if (telRilModem_ != nullptr) {
        telRilModem_->SetRadioStatus(fun, rst, response);
    } else {
        TELEPHONY_LOGE("telRilModem_ is null");
    }
}
void RilManager::GetRadioStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilModem_ != nullptr) {
        telRilModem_->GetRadioStatus(response);
    } else {
        TELEPHONY_LOGE("telRilModem_ is null");
    }
}

void RilManager::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilModem_ != nullptr) {
        return telRilModem_->ShutDown(response);
    } else {
        TELEPHONY_LOGE("telRilModem_ is null");
    }
}

void RilManager::Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Dial(address, clirMode, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Reject(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::Hold(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Hold(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::Active(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Active(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::Swap(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Swap(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Hangup(gsmIndex, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Answer(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::Join(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Join(callType, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::Split(int32_t nThCall, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Split(nThCall, callType, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->CallSupplement(type, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallList(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::GetCallWait(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallWait(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::SetCallWait(const int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetCallWait(activate, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::GetCallForward(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallForward(reason, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::SetCallForward(const int32_t reason, const int32_t mode, std::string number, const int32_t classx,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetCallForward(reason, mode, number, classx, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::GetClip(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetClip(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetClip(action, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::GetClir(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetClir(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetClir(action, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallRestriction(fac, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::SetCallRestriction(
    std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetCallRestriction(fac, mode, password, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SendDtmf(sDTMFCode, index, switchOn, switchOff, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SendDtmf(cDTMFCode, index, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->StartDtmf(cDTMFCode, index, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->StopDtmf(index, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void RilManager::ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilData_ != nullptr) {
        telRilData_->ActivatePdpContext(radioTechnology, dataProfile, isRoaming, allowRoaming, response);
    } else {
        TELEPHONY_LOGE("telRilData_ is null");
    }
}

void RilManager::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilData_ != nullptr) {
        telRilData_->DeactivatePdpContext(cid, reason, response);
    } else {
        TELEPHONY_LOGE("telRilData_ is null");
    }
}

void RilManager::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetSignalStrength(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void RilManager::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetCsRegStatus(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void RilManager::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetPsRegStatus(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void RilManager::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetOperatorInfo(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void RilManager::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetNetworkSearchInformation(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void RilManager::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetNetworkSelectionMode(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void RilManager::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->SetNetworkSelectionMode(automaticFlag, oper, response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void RilManager::SetNetworkLocationUpdate(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->SetNetworkLocationUpdate(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void RilManager::SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SendSms(smscPdu, pdu, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void RilManager::StorageSms(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->StorageSms(status, smscPdu, pdu, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void RilManager::DeleteSms(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->DeleteSms(gsmIndex, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void RilManager::UpdateSms(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->UpdateSms(gsmIndex, state, smscPdu, pdu, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void RilManager::GetSmsCenterAddress(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->GetSmsCenterAddress(response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void RilManager::SetSmsCenterAddress(
    int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SetSmsCenterAddress(tosca, address, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void RilManager::SetCellBroadcast(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SetCellBroadcast(mode, idList, dcsList, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void RilManager::SendSmsMoreMode(
    std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SendSmsMoreMode(smscPdu, pdu, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void RilManager::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SendSmsAck(success, cause, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}
void RilManager::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimStatus(result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::RequestSimIO(int32_t command, int32_t fileId, int32_t p1, int32_t p2, int32_t p3,
    std::string data, std::string path, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->RequestSimIO(command, fileId, p1, p2, p3, data, path, response);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::GetImsi(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetImsi(result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::GetIccID(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetIccID(result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimLockStatus(fac, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::SetSimLock(
    std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->SetSimLock(fac, mode, passwd, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
    int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->ChangeSimPassword(fac, oldPassword, newPassword, passwordLength, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::EnterSimPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->EnterSimPin(pin, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::UnlockSimPin(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->UnlockSimPin(puk, pin, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void RilManager::GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimPinInputTimes(result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}
} // namespace Telephony
} // namespace OHOS
