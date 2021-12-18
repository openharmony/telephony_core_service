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

#include "hdf_death_recipient.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
namespace OHOS {
namespace Telephony {
TelRilManager::TelRilManager() : IPCObjectStub(std::u16string(u""))
{
    TELEPHONY_LOGI("TelRilManager init->");
}

TelRilManager::~TelRilManager()
{
    TELEPHONY_LOGI("~TelRilManager!");
}

int32_t TelRilManager::SetCellularRadioIndication(bool isFirst)
{
    int32_t ret = RIL_ADAPTER_ERROR;
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
        ret = cellularRadio_->SendRequest(HRIL_ADAPTER_RADIO_INDICATION, data, reply, option);
    }
    return ret;
}

int32_t TelRilManager::SetCellularRadioResponse(bool isFirst)
{
    int ret = RIL_ADAPTER_ERROR;
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
        ret = cellularRadio_->SendRequest(HRIL_ADAPTER_RADIO_RESPONSE, data, reply, option);
    }
    return ret;
}

int TelRilManager::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, OHOS::MessageOption &option)
{
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

void TelRilManager::TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId)
{
    preferredNetworkType_ = preferredNetworkType;
    cdmaSubscription_ = cdmaSubscription;
    slotId_ = instanceId;
    observerHandler_ = std::make_shared<ObserverHandler>();
}

bool TelRilManager::OnInit()
{
    bool res = false;
    int i = 0;

    do {
        res = InitCellularRadio(true);
        if (!res) {
            i++;
            sleep(1);
        } else {
            InitTelInfo();
        }
    } while (!res && (i < RIL_INIT_COUNT_MAX));
    return res;
}

bool TelRilManager::InitCellularRadio(bool isFirst)
{
    cellularRadio_ = nullptr;
    auto servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
    while (servMgr_ == nullptr) {
        sleep(1);
        servMgr_ = OHOS::HDI::ServiceManager::V1_0::IServiceManager::Get();
    }
    cellularRadio_ = servMgr_->GetService(RIL_ADAPTER_SERVICE_NAME);
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("bind hdf%{public}d error!", slotId_);
        return false;
    }
    sptr<IRemoteObject::DeathRecipient> death_ =
        sptr<IRemoteObject::DeathRecipient>(new HdfDeathRecipient(slotId_));
    if (death_ == nullptr) {
        TELEPHONY_LOGE("create HdfDeathRecipient object failed!");
        return false;
    }
    bool res = cellularRadio_->AddDeathRecipient(death_);
    if (!res) {
        TELEPHONY_LOGE("AddDeathRecipient hdfId:%{public}d failed!", slotId_);
        return false;
    }
    if (SetCellularRadioIndication(isFirst)) {
        TELEPHONY_LOGE("SetCellularRadioIndication error ");
        return false;
    }
    if (SetCellularRadioResponse(isFirst)) {
        TELEPHONY_LOGE("SetCellularRadioResponse error ");
        return false;
    }
    return true;
}

void TelRilManager::InitTelInfo()
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

void TelRilManager::RegisterCoreNotify(
    const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what, uint8_t*)
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
                if (telRilModem_->radioState_ == ModemPowerState::CORE_SERVICE_POWER_OFF ||
                    ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE == telRilModem_->radioState_) {
                    observerHandler_->NotifyObserver(what);
                }
                break;
            default:
                observerHandler_->RegObserver(what, observerCallBack);
                break;
        }
    }
}

void TelRilManager::UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what)
{
    if (observerHandler_ != nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        observerHandler_->Remove(what, observerCallBack);
    } else {
        TELEPHONY_LOGE("observerHandler_ is null");
    }
}

void TelRilManager::SetRadioState(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilModem_ != nullptr) {
        telRilModem_->SetRadioState(fun, rst, response);
    } else {
        TELEPHONY_LOGE("telRilModem_ is null");
    }
}
void TelRilManager::GetRadioState(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilModem_ != nullptr) {
        telRilModem_->GetRadioState(response);
    } else {
        TELEPHONY_LOGE("telRilModem_ is null");
    }
}

void TelRilManager::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilModem_ != nullptr) {
        return telRilModem_->ShutDown(response);
    } else {
        TELEPHONY_LOGE("telRilModem_ is null");
    }
}

void TelRilManager::Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Dial(address, clirMode, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Reject(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::HoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->HoldCall(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->UnHoldCall(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SwitchCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SwitchCall(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Hangup(gsmIndex, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->Answer(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->CombineConference(callType, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SeparateConference(
    int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SeparateConference(callIndex, callType, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->CallSupplement(type, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallList(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallWaiting(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SetCallWaiting(const int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetCallWaiting(activate, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::GetCallTransferInfo(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallTransferInfo(reason, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SetCallTransferInfo(
    const int32_t reason, const int32_t mode, std::string number, const int32_t classx,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetCallTransferInfo(reason, mode, number, classx, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::GetClip(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetClip(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SetClip(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetClip(action, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::GetClir(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetClir(result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SetClir(const int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetClir(action, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallRestriction(fac, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SetCallRestriction(
    std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SetCallRestriction(fac, mode, password, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SendDtmf(sDTMFCode, index, switchOn, switchOff, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->SendDtmf(cDTMFCode, index, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->StartDtmf(cDTMFCode, index, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->StopDtmf(index, result);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilData_ != nullptr) {
        telRilData_->ActivatePdpContext(radioTechnology, dataProfile, isRoaming, allowRoaming, response);
    } else {
        TELEPHONY_LOGE("telRilData_ is null");
    }
}

void TelRilManager::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilData_ != nullptr) {
        telRilData_->DeactivatePdpContext(cid, reason, response);
    } else {
        TELEPHONY_LOGE("telRilData_ is null");
    }
}

void TelRilManager::GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilData_ != nullptr) {
        telRilData_->GetPdpContextList(response);
    } else {
        TELEPHONY_LOGE("telRilData_ is null");
    }
}

void TelRilManager::GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetImsRegStatus(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetSignalStrength(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetCsRegStatus(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetPsRegStatus(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetOperatorInfo(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetImei(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetImei(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::SetPsAttachStatus(int32_t psAttachStatus, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->SetPsAttachStatus(psAttachStatus, response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetPsAttachStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetPsAttachStatus(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetNetworkSearchInformation(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetNetworkSelectionMode(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->SetNetworkSelectionMode(automaticFlag, oper, response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetPreferredNetwork(response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::SetPreferredNetwork(
    int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->SetPreferredNetwork(preferredNetworkType, response);
    } else {
        TELEPHONY_LOGE("telRilNetwork_ is null");
    }
}

void TelRilManager::GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGI("TelRilManager GetCellInfoList->");
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetCellInfoList(response);
    }
}

void TelRilManager::GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGI("TelRilManager GetCurrentCellInfo->");
    if (telRilNetwork_ != nullptr) {
        telRilNetwork_->GetCurrentCellInfo(response);
    }
}

void TelRilManager::SendGsmSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SendGsmSms(smscPdu, pdu, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::SendCdmaSms(CdmaSmsMessageInfo &msg, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SendCdmaSms(msg, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::AddSimMessage(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->AddSimMessage(status, smscPdu, pdu, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->DelSimMessage(gsmIndex, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::UpdateSimMessage(int32_t gsmIndex, int32_t state, std::string smscPdu, std::string pdu,
    const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->UpdateSimMessage(gsmIndex, state, smscPdu, pdu, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->GetSmscAddr(response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->GetCdmaCBConfig(response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::SetSmscAddr(
    int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SetSmscAddr(tosca, address, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::SetCBConfig(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SetCBConfig(mode, idList, dcsList, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::SetCdmaCBConfig(
    CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SetCdmaCBConfig(cdmaCBConfigInfoList, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->GetCBConfig(result);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::SendSmsMoreMode(
    std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SendSmsMoreMode(smscPdu, pdu, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}

void TelRilManager::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSms_ != nullptr) {
        telRilSms_->SendSmsAck(success, cause, response);
    } else {
        TELEPHONY_LOGE("telRilSms_ is null");
    }
}
void TelRilManager::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimStatus(result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::GetSimIO(SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimIO(data, response);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::GetImsi(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetImsi(result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimLockStatus(fac, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::SetSimLock(
    std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->SetSimLock(fac, mode, passwd, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
    int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->ChangeSimPassword(fac, oldPassword, newPassword, passwordLength, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->UnlockPin(pin, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->UnlockPuk(puk, pin, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimPinInputTimes(result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}
void TelRilManager::UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->UnlockPin2(pin2, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->UnlockPuk2(puk2, pin2, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::GetSimPin2InputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->GetSimPin2InputTimes(result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}
void TelRilManager::SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilSim_ != nullptr) {
        telRilSim_->SetActiveSim(index, enable, result);
    } else {
        TELEPHONY_LOGE("telRilSim_ is null");
    }
}

void TelRilManager::GetImsCallList(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetImsCallList(response);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SetCallPreferenceMode(const int32_t mode, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGE("TelRilManager::SetCallPreferenceMode --> mode = [%{public}d]", mode);
    if (telRilCall_ != nullptr) {
        telRilCall_->SetCallPreferenceMode(mode, response);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetCallPreferenceMode(response);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::SetLteImsSwitchStatus(const int32_t active, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_LOGE("TelRilManager::SetLteImsSwitchStatus --> active = [%{public}d]", active);
    if (telRilCall_ != nullptr) {
        telRilCall_->SetLteImsSwitchStatus(active, response);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}

void TelRilManager::GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilCall_ != nullptr) {
        telRilCall_->GetLteImsSwitchStatus(response);
    } else {
        TELEPHONY_LOGE("telRilCall_ is null");
    }
}
} // namespace Telephony
} // namespace OHOS
