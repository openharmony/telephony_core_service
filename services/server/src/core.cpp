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

#include "core.h"
#include "icc_dialling_numbers_manager.h"
#include "network_search_manager.h"
#include "sim_account_manager.h"
#include "sim_sms_manager.h"
#include "tel_ril_manager.h"

using namespace OHOS::Telephony;
namespace OHOS {
namespace Telephony {
const int NETWORK_IS_NULL = -1;

Core::Core(int opt) : networkSearchManager_(nullptr), telRilManager_(nullptr), slotId_(opt), isInitCore_(false) {}

bool Core::OnInit()
{
    bool ret = false;
    telRilManager_ = std::make_shared<TelRilManager>();
    if (telRilManager_ != nullptr) {
        telRilManager_->TelRilSetParam(0, 1, slotId_);
        ret = telRilManager_->OnInit();
    }
    simStateManager_ = std::make_shared<SimStateManager>(telRilManager_);
    if (simStateManager_ != nullptr) {
        simStateManager_->Init();
    }
    simFileManager_ = std::make_shared<SimFileManager>(telRilManager_, simStateManager_);
    if (simFileManager_ != nullptr) {
        simFileManager_->Init();
    }
    networkSearchManager_ =
        std::make_shared<NetworkSearchManager>(telRilManager_, simStateManager_, simFileManager_);
    if (networkSearchManager_ != nullptr) {
        networkSearchManager_->Init();
    }
    simSmsManager_ = std::make_shared<SimSmsManager>(telRilManager_, simFileManager_);
    if (simSmsManager_ != nullptr) {
        simSmsManager_->Init();
    }
    simAccountManager_ = std::make_shared<SimAccountManager>(simStateManager_, simFileManager_, networkSearchManager_);
    if (simAccountManager_ != nullptr) {
        simAccountManager_->Init(slotId_);
    }
    iccDiallingNumbersManager_ = IccDiallingNumbersManager::CreateInstance(simFileManager_, simStateManager_);
    if (iccDiallingNumbersManager_ != nullptr) {
        iccDiallingNumbersManager_->Init();
    }
    if (simStateManager_ != nullptr) {
        simStateManager_->RefreshSimState(slotId_);
    }

    isInitCore_ = ret;
    return ret;
}

bool Core::IsInitCore()
{
    return isInitCore_;
}

void Core::InitTelInfo()
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->InitTelInfo();
}

void Core::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, uint8_t*)
{
    if (what >= ObserverHandler::RADIO_PS_CONNECTION_ATTACHED && what <= ObserverHandler::RADIO_PS_ROAMING_CLOSE) {
        if (networkSearchManager_ == nullptr) {
            TELEPHONY_LOGE("networkSearchManager is null!");
            return;
        }
        networkSearchManager_->RegisterCoreNotify(handler, what);
    } else if (what >= ObserverHandler::RADIO_IMSI_LOADED_READY &&
        what <= ObserverHandler::RADIO_SIM_RECORDS_LOADED) {
        if (simFileManager_ == nullptr) {
            TELEPHONY_LOGE("simFileManager is null");
            return;
        }
        simFileManager_->RegisterCoreNotify(handler, what);
    } else if (what >= ObserverHandler::RADIO_SIM_STATE_CHANGE && what <= ObserverHandler::RADIO_SIM_STATE_SIMLOCK) {
        if (simStateManager_ == nullptr) {
            TELEPHONY_LOGE("simStateManager_ is null");
            return;
        }
        simStateManager_->RegisterCoreNotify(handler, what);
    } else {
        if (telRilManager_ == nullptr) {
            TELEPHONY_LOGE("telRilManager is null!");
            return;
        }
        telRilManager_->RegisterCoreNotify(handler, what, nullptr);
    }
}

void Core::UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what)
{
    if (what >= ObserverHandler::RADIO_PS_CONNECTION_ATTACHED && what <= ObserverHandler::RADIO_PS_ROAMING_CLOSE) {
        if (networkSearchManager_ == nullptr) {
            TELEPHONY_LOGE("networkSearchManager is null!");
            return;
        }
        networkSearchManager_->UnRegisterCoreNotify(observerCallBack, what);
    } else if (what >= ObserverHandler::RADIO_IMSI_LOADED_READY &&
        what <= ObserverHandler::RADIO_SIM_RECORDS_LOADED) {
        if (simFileManager_ == nullptr) {
            TELEPHONY_LOGE("simFileManager is null");
            return;
        }
        simFileManager_->UnRegisterCoreNotify(observerCallBack, what);
    } else if (what >= ObserverHandler::RADIO_SIM_STATE_CHANGE && what <= ObserverHandler::RADIO_SIM_STATE_SIMLOCK) {
        if (simStateManager_ == nullptr) {
            TELEPHONY_LOGE("simStateManager_ is null");
            return;
        }
        simStateManager_->UnRegisterCoreNotify(observerCallBack, what);
    } else {
        if (telRilManager_ == nullptr) {
            TELEPHONY_LOGE("telRilManager is null!");
            return;
        }
        telRilManager_->UnRegisterCoreNotify(observerCallBack, what);
    }
}

void Core::SetRadioState(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }

    telRilManager_->SetRadioState(fun, rst, response);
}

void Core::GetRadioState(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetRadioState(response);
}

void Core::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->ShutDown(response);
}

void Core::Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->Dial(address, clirMode, result);
}

void Core::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->Reject(result);
}

void Core::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->Hangup(gsmIndex, result);
}

void Core::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->Answer(result);
}

void Core::GetCallList(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallList(result);
}

void Core::HoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->HoldCall(result);
}

void Core::UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->UnHoldCall(result);
}

void Core::SwitchCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SwitchCall(result);
}

void Core::CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->CombineConference(callType, result);
}

void Core::SeparateConference(int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SeparateConference(callIndex, callType, result);
}

void Core::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("CallSupplement, telRilManager is null!");
        return;
    }
    telRilManager_->CallSupplement(type, result);
}

void Core::GetClip(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetClip(result);
}

void Core::SetClip(int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetClip(action, result);
}

void Core::GetClir(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetClir(result);
}

void Core::SetClir(int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetClir(action, result);
}

void Core::SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCallWaiting(activate, result);
}
void Core::SetCallTransferInfo(int32_t reason, int32_t mode, std::string number, int32_t classx,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCallTransferInfo(reason, mode, number, classx, result);
}
void Core::GetCallTransferInfo(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallTransferInfo(reason, result);
}
void Core::GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallWaiting(result);
}

void Core::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallRestriction(fac, result);
}

void Core::SetCallRestriction(
    std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCallRestriction(fac, mode, password, result);
}

void Core::SendDTMF(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendDtmf(sDTMFCode, index, switchOn, switchOff, result);
}

void Core::SendDTMF(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendDtmf(cDTMFCode, index, result);
}

void Core::StartDTMF(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->StartDtmf(cDTMFCode, index, result);
}

void Core::StopDTMF(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->StopDtmf(index, result);
}

void Core::ActivatePdpContext(int32_t radioTechnology, ITelRilManager::CellularDataProfile dataProfile,
    bool isRoaming, bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->ActivatePdpContext(radioTechnology, dataProfile, isRoaming, allowRoaming, response);
}

void Core::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->DeactivatePdpContext(cid, reason, response);
}

void Core::GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetPdpContextList(response);
}

void Core::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetSignalStrength(response);
}

void Core::GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetImsRegStatus(response);
}

void Core::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCsRegStatus(response);
}

void Core::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetPsRegStatus(response);
}

int32_t Core::GetPsRadioTech(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetPsRadioTech(slotId);
}

int32_t Core::GetCsRadioTech(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetCsRadioTech(slotId);
}

int32_t Core::GetPsRegState(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetPsRegState(slotId);
}

int32_t Core::GetPsRoamingState(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetPsRoamingState(slotId);
}

bool Core::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SetNetworkSelectionMode(
        slotId, selectMode, networkInformation, resumeSelection, callback);
}

std::vector<sptr<SignalInformation>> Core::GetSignalInfoList(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::vector<sptr<SignalInformation>>();
    }
    return networkSearchManager_->GetSignalInfoList(slotId);
}

std::u16string Core::GetOperatorNumeric(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorNumeric(slotId);
}

std::u16string Core::GetOperatorName(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorName(slotId);
}

sptr<NetworkState> Core::GetNetworkStatus(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return nullptr;
    }
    return networkSearchManager_->GetNetworkStatus(slotId);
}

bool Core::SetRadioState(bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SetRadioState(isOn, rst, callback);
}

int32_t Core::GetRadioState() const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetRadioState();
}

bool Core::GetRadioState(const sptr<INetworkSearchCallback> &callback) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetRadioState(callback);
}

std::u16string Core::GetIsoCountryCodeForNetwork(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetIsoCountryCodeForNetwork(slotId);
}

std::u16string Core::GetImei(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetImei(slotId);
}

bool Core::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetNetworkSearchInformation(slotId, callback);
}

bool Core::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetNetworkSelectionMode(slotId, callback);
}

std::vector<sptr<CellInformation>> Core::GetCellInfoList(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::vector<sptr<CellInformation>>();
    }
    return networkSearchManager_->GetCellInfoList(slotId);
}

bool Core::SendUpdateCellLocationRequest()
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SendUpdateCellLocationRequest();
}

int32_t Core::ObtainSpnCondition(bool roaming, std::string operatorNum)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null");
        return 0;
    }
    return simFileManager_->ObtainSpnCondition(roaming, operatorNum);
}

std::u16string Core::GetSpn(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null");
        return std::u16string();
    }
    return simFileManager_->GetSimSpn(slotId);
}

bool Core::SetVoiceMailInfo(int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null");
        return false;
    }
    return simFileManager_->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

void Core::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetOperatorInfo(response);
}

void Core::GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCellInfoList(response);
}

void Core::GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCurrentCellInfo(response);
}

void Core::SendGsmSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendGsmSms(smscPdu, pdu, response);
}

void Core::SendCdmaSms(CdmaSmsMessageInfo &msg, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendCdmaSms(msg, response);
}

void Core::AddSimMessage(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->AddSimMessage(status, smscPdu, pdu, response);
}

void Core::DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->DelSimMessage(gsmIndex, response);
}

void Core::GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetSmscAddr(response);
}

void Core::SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetSmscAddr(tosca, address, response);
}

void Core::SetCBConfig(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCBConfig(mode, idList, dcsList, response);
}

void Core::SetCdmaCBConfig(
    CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCdmaCBConfig(cdmaCBConfigInfoList, response);
}

void Core::GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCBConfig(result);
}

void Core::GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCdmaCBConfig(response);
}

void Core::SendSmsMoreMode(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendSmsMoreMode(smscPdu, pdu, response);
}

void Core::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendSmsAck(success, cause, response);
}

void Core::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetNetworkSearchInformation(response);
}

void Core::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetNetworkSelectionMode(response);
}

void Core::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetNetworkSelectionMode(automaticFlag, oper, response);
}

bool Core::SetPsAttachStatus(int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SetPsAttachStatus(slotId, psAttachStatus, callback);
}

void Core::TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->TelRilSetParam(preferredNetworkType, cdmaSubscription, instanceId);
}

bool Core::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetPreferredNetwork(slotId, callback);
    }
    return false;
}

bool Core::SetPreferredNetwork(int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->SetPreferredNetwork(slotId, networkMode, callback);
    }
    return false;
}

void Core::SetPreferredNetwork(int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetPreferredNetwork(preferredNetworkType, response);
}

void Core::GetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetPreferredNetwork(response);
}

bool Core::InitCellularRadio(bool isFirst)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return false;
    }
    return telRilManager_->InitCellularRadio(isFirst);
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> Core::QueryIccDiallingNumbers(int slotId, int type)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    if (iccDiallingNumbersManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return result;
    }
    return iccDiallingNumbersManager_->QueryIccDiallingNumbers(slotId, type);
}

bool Core::AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (iccDiallingNumbersManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return false;
    }
    return iccDiallingNumbersManager_->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

bool Core::DelIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (iccDiallingNumbersManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return false;
    }
    return iccDiallingNumbersManager_->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

bool Core::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (iccDiallingNumbersManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return false;
    }
    return iccDiallingNumbersManager_->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

bool Core::AddSmsToIcc(int status, std::string &pdu, std::string &smsc)
{
    if (simSmsManager_ == nullptr) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return false;
    }
    return simSmsManager_->AddSmsToIcc(status, pdu, smsc);
}

bool Core::UpdateSmsIcc(int index, int status, std::string &pduData, std::string &smsc)
{
    if (simSmsManager_ == nullptr) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return false;
    }
    return simSmsManager_->UpdateSmsIcc(index, status, pduData, smsc);
}

std::vector<std::string> Core::ObtainAllSmsOfIcc()
{
    std::vector<std::string> result;
    if (simSmsManager_ == nullptr) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return result;
    }
    return simSmsManager_->ObtainAllSmsOfIcc();
}

bool Core::DelSmsIcc(int index)
{
    if (simSmsManager_ == nullptr) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return false;
    }
    return simSmsManager_->DelSmsIcc(index);
}

bool Core::IsSimActive(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->IsSimActive(slotId);
}

bool Core::SetActiveSim(int32_t slotId, int32_t enable)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetActiveSim(slotId, enable);
}

bool Core::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->GetSimAccountInfo(slotId, info);
}

bool Core::SetDefaultVoiceSlotId(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetDefaultVoiceSlotId(slotId);
}

bool Core::SetDefaultSmsSlotId(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetDefaultSmsSlotId(slotId);
}

bool Core::SetDefaultCellularDataSlotId(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetDefaultCellularDataSlotId(slotId);
}

bool Core::SetShowNumber(int32_t slotId, const std::u16string number)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetShowNumber(slotId, number);
}

bool Core::SetShowName(int32_t slotId, const std::u16string name)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetShowName(slotId, name);
}

int32_t Core::GetDefaultVoiceSlotId()
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return TELEPHONY_ERROR;
    }
    return simAccountManager_->GetDefaultVoiceSlotId();
}

int32_t Core::GetDefaultSmsSlotId()
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return TELEPHONY_ERROR;
    }
    return simAccountManager_->GetDefaultSmsSlotId();
}

int32_t Core::GetDefaultCellularDataSlotId()
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return TELEPHONY_ERROR;
    }
    return simAccountManager_->GetDefaultCellularDataSlotId();
}

std::u16string Core::GetShowNumber(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return u"";
    }
    return simAccountManager_->GetShowNumber(slotId);
}

std::u16string Core::GetShowName(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return u"";
    }
    return simAccountManager_->GetShowName(slotId);
}

bool Core::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->GetActiveSimAccountInfoList(iccAccountInfoList);
}

bool Core::GetOperatorConfigs(int slotId, OperatorConfig &poc)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->GetOperatorConfigs(slotId, poc);
}

std::u16string Core::GetSimOperatorNumeric(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimOperatorNumeric(slotId);
}

std::u16string Core::GetISOCountryCodeForSim(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetISOCountryCodeForSim(slotId);
}

std::u16string Core::GetSimIccId(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimIccId(slotId);
}

std::u16string Core::GetIMSI(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetIMSI(slotId);
}

std::u16string Core::GetLocaleFromDefaultSim()
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetLocaleFromDefaultSim();
}

std::u16string Core::GetSimGid1(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimGid1(slotId);
}

std::u16string Core::GetSimTelephoneNumber(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimTelephoneNumber(slotId);
}

std::u16string Core::GetVoiceMailIdentifier(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetVoiceMailIdentifier(slotId);
}

std::u16string Core::GetVoiceMailNumber(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetVoiceMailNumber(slotId);
}

bool Core::HasSimCard(int32_t slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->HasSimCard(slotId);
}

int32_t Core::GetSimState(int32_t slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return TELEPHONY_ERROR;
    }
    return static_cast<int32_t>(simStateManager_->GetSimState(slotId));
}

bool Core::UnlockPin(int32_t slotId, std::string pin, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockPin(slotId, pin, response);
}

bool Core::UnlockPuk(int32_t slotId, std::string newPin, std::string puk, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockPuk(slotId, newPin, puk, response);
}

bool Core::AlterPin(int32_t slotId, std::string newPin, std::string oldPin, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->AlterPin(slotId, newPin, oldPin, response);
}

bool Core::SetLockState(int32_t slotId, std::string pin, int32_t enable, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->SetLockState(slotId, pin, enable, response);
}

int32_t Core::GetLockState(int32_t slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->GetLockState(slotId);
}

int32_t Core::RefreshSimState(int32_t slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->RefreshSimState(slotId);
}

bool Core::UnlockPin2(int32_t slotId, std::string pin2, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockPin2(slotId, pin2, response);
}

bool Core::UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockPuk2(slotId, newPin2, puk2, response);
}

bool Core::AlterPin2(int32_t slotId, std::string newPin2, std::string oldPin2, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->AlterPin2(slotId, newPin2, oldPin2, response);
}

int32_t Core::GetMaxSimCount()
{
    return SIM_SLOT_NUM;
}

std::shared_ptr<ITelRilManager> Core::GetRilManager() const
{
    return telRilManager_;
}

void Core::GetImsCallList(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetImsCallList(result);
}

void Core::SetCallPreferenceMode(int32_t mode, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCallPreferenceMode(mode, result);
}

void Core::GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallPreferenceMode(result);
}

void Core::SetLteImsSwitchStatus(int32_t active, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetLteImsSwitchStatus(active, result);
}

void Core::GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetLteImsSwitchStatus(result);
}

bool Core::GetImsRegStatus() const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetImsRegStatus();
}
} // namespace Telephony
} // namespace OHOS