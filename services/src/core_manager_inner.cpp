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

#include "core_manager_inner.h"
#include "icc_dialling_numbers_manager.h"
#include "network_search_manager.h"
#include "sim_account_manager.h"
#include "sim_sms_manager.h"
#include "tel_ril_manager.h"
#include "stk_manager.h"
#include "hril_vendor_network_defs.h"

using namespace OHOS::Telephony;
namespace OHOS {
namespace Telephony {
const int NETWORK_IS_NULL = -1;

void CoreManagerInner::RegisterManager(const ManagerInfo &managerInfo)
{
    std::shared_ptr<INetworkSearch> networkSearchManager_ = managerInfo.networkSearchManager;
    std::shared_ptr<Telephony::TelRilManager> telRilManager = managerInfo.telRilManager;
    std::shared_ptr<Telephony::ISimFileManager> simFileManager = managerInfo.simFileManager;
    std::shared_ptr<Telephony::ISimStateManager> simStateManager_ = managerInfo.simStateManager;
    std::shared_ptr<Telephony::ISimSmsManager> simSmsManager_ = managerInfo.simSmsManager;
    std::shared_ptr<Telephony::ISimAccountManager> simAccountManager_ = managerInfo.simAccountManager;
    std::shared_ptr<Telephony::IIccDiallingNumbersManager> iccDiallingNumbersManager_ =
        managerInfo.iccDiallingNumbersManager;
    std::shared_ptr<Telephony::IStkManager> stkManager_ = managerInfo.stkManager;
}

void CoreManagerInner::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj)
{
    if (what >= ObserverHandler::RADIO_PS_CONNECTION_ATTACHED &&
        what <= ObserverHandler::RADIO_EMERGENCY_STATE_CLOSE) {
        if (networkSearchManager_ == nullptr) {
            TELEPHONY_LOGE("networkSearchManager is null!");
            return;
        }
        networkSearchManager_->RegisterCoreNotify(handler, what);
    } else if ((what >= ObserverHandler::RADIO_IMSI_LOADED_READY) &&
        (what <= ObserverHandler::RADIO_SIM_RECORDS_LOADED)) {
        if (simFileManager_ == nullptr) {
            TELEPHONY_LOGE("simFileManager is null");
            return;
        }
        simFileManager_->RegisterCoreNotify(handler, what);
    } else if ((what >= ObserverHandler::RADIO_SIM_STATE_CHANGE) &&
        (what <= ObserverHandler::RADIO_SIM_STATE_SIMLOCK)) {
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
        telRilManager_->RegisterCoreNotify(handler, what, obj);
    }
}

void CoreManagerInner::UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what)
{
    if (what >= ObserverHandler::RADIO_PS_CONNECTION_ATTACHED &&
        what <= ObserverHandler::RADIO_EMERGENCY_STATE_CLOSE) {
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

void CoreManagerInner::SetRadioState(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }

    telRilManager_->SetRadioState(fun, rst, response);
}

void CoreManagerInner::GetRadioState(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetRadioState(response);
}

void CoreManagerInner::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->ShutDown(response);
}

void CoreManagerInner::Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->Dial(address, clirMode, result);
}

void CoreManagerInner::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->Reject(result);
}

void CoreManagerInner::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->Hangup(gsmIndex, result);
}

void CoreManagerInner::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->Answer(result);
}

void CoreManagerInner::GetCallList(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallList(result);
}

void CoreManagerInner::HoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->HoldCall(result);
}

void CoreManagerInner::UnHoldCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->UnHoldCall(result);
}

void CoreManagerInner::SwitchCall(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SwitchCall(result);
}

void CoreManagerInner::CombineConference(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->CombineConference(callType, result);
}

void CoreManagerInner::SeparateConference(
    int32_t callIndex, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SeparateConference(callIndex, callType, result);
}

void CoreManagerInner::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("CallSupplement, telRilManager is null!");
        return;
    }
    telRilManager_->CallSupplement(type, result);
}

void CoreManagerInner::GetClip(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetClip(result);
}

void CoreManagerInner::SetClip(int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetClip(action, result);
}

void CoreManagerInner::GetClir(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetClir(result);
}

void CoreManagerInner::SetClir(int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetClir(action, result);
}

void CoreManagerInner::SetCallWaiting(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCallWaiting(activate, result);
}
void CoreManagerInner::SetCallTransferInfo(int32_t reason, int32_t mode, std::string number, int32_t classx,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCallTransferInfo(reason, mode, number, classx, result);
}
void CoreManagerInner::GetCallTransferInfo(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallTransferInfo(reason, result);
}
void CoreManagerInner::GetCallWaiting(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallWaiting(result);
}

void CoreManagerInner::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallRestriction(fac, result);
}

void CoreManagerInner::SetCallRestriction(
    std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCallRestriction(fac, mode, password, result);
}

void CoreManagerInner::SendDTMF(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendDtmf(sDTMFCode, index, switchOn, switchOff, result);
}

void CoreManagerInner::SendDTMF(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendDtmf(cDTMFCode, index, result);
}

void CoreManagerInner::StartDTMF(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->StartDtmf(cDTMFCode, index, result);
}

void CoreManagerInner::StopDTMF(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->StopDtmf(index, result);
}

int32_t CoreManagerInner::SetInitApnInfo(
    ITelRilManager::CellularDataProfile dataProfile, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->SetInitApnInfo(dataProfile, response);
}

int32_t CoreManagerInner::ActivatePdpContext(int32_t radioTechnology, ITelRilManager::CellularDataProfile dataProfile,
    bool isRoaming, bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->ActivatePdpContext(radioTechnology, dataProfile, isRoaming, allowRoaming, response);
}

int32_t CoreManagerInner::DeactivatePdpContext(
    int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->DeactivatePdpContext(cid, reason, response);
}

int32_t CoreManagerInner::GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetPdpContextList(response);
}

int32_t CoreManagerInner::SetLinkBandwidthReportingRule(
    LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->SetLinkBandwidthReportingRule(linkBandwidth, response);
}

int32_t CoreManagerInner::GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetLinkBandwidthInfo(cid, response);
}

void CoreManagerInner::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetSignalStrength(response);
}

void CoreManagerInner::GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetImsRegStatus(response);
}

void CoreManagerInner::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCsRegStatus(response);
}

void CoreManagerInner::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetPsRegStatus(response);
}

int32_t CoreManagerInner::GetPsRadioTech(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetPsRadioTech(slotId);
}

int32_t CoreManagerInner::GetCsRadioTech(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetCsRadioTech(slotId);
}

int32_t CoreManagerInner::GetPsRegState(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetPsRegState(slotId);
}

int32_t CoreManagerInner::GetCsRegState(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetCsRegState(slotId);
}

int32_t CoreManagerInner::GetPsRoamingState(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetPsRoamingState(slotId);
}

bool CoreManagerInner::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
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

std::vector<sptr<SignalInformation>> CoreManagerInner::GetSignalInfoList(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::vector<sptr<SignalInformation>>();
    }
    return networkSearchManager_->GetSignalInfoList(slotId);
}

std::u16string CoreManagerInner::GetOperatorNumeric(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorNumeric(slotId);
}

std::u16string CoreManagerInner::GetOperatorName(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorName(slotId);
}

sptr<NetworkState> CoreManagerInner::GetNetworkStatus(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return nullptr;
    }
    return networkSearchManager_->GetNetworkStatus(slotId);
}

bool CoreManagerInner::SetRadioState(bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SetRadioState(isOn, rst, callback);
}

int32_t CoreManagerInner::GetRadioState() const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return NETWORK_IS_NULL;
    }
    return networkSearchManager_->GetRadioState();
}

bool CoreManagerInner::GetRadioState(const sptr<INetworkSearchCallback> &callback) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetRadioState(callback);
}

std::u16string CoreManagerInner::GetIsoCountryCodeForNetwork(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetIsoCountryCodeForNetwork(slotId);
}

std::u16string CoreManagerInner::GetImei(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetImei(slotId);
}

std::u16string CoreManagerInner::GetMeid(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetMeid(slotId);
}

std::u16string CoreManagerInner::GetUniqueDeviceId(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetUniqueDeviceId(slotId);
}

PhoneType CoreManagerInner::GetPhoneType() const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return PhoneType::PHONE_TYPE_IS_NONE;
    }
    return networkSearchManager_->GetPhoneType();
}

sptr<CellLocation> CoreManagerInner::GetCellLocation(int32_t slotId) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return nullptr;
    }
    return networkSearchManager_->GetCellLocation(slotId);
}

bool CoreManagerInner::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetNetworkSearchInformation(slotId, callback);
}

bool CoreManagerInner::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetNetworkSelectionMode(slotId, callback);
}

std::vector<sptr<CellInformation>> CoreManagerInner::GetCellInfoList(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::vector<sptr<CellInformation>>();
    }
    return networkSearchManager_->GetCellInfoList(slotId);
}

bool CoreManagerInner::SendUpdateCellLocationRequest()
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SendUpdateCellLocationRequest();
}

int32_t CoreManagerInner::ObtainSpnCondition(bool roaming, std::string operatorNum)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null");
        return 0;
    }
    return simFileManager_->ObtainSpnCondition(roaming, operatorNum);
}

std::u16string CoreManagerInner::GetSpn(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null");
        return std::u16string();
    }
    return simFileManager_->GetSimSpn(slotId);
}

bool CoreManagerInner::SetVoiceMailInfo(
    int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null");
        return false;
    }
    return simFileManager_->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

void CoreManagerInner::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetOperatorInfo(response);
}

void CoreManagerInner::GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCellInfoList(response);
}

void CoreManagerInner::GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCurrentCellInfo(response);
}

void CoreManagerInner::SendGsmSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendGsmSms(smscPdu, pdu, response);
}

void CoreManagerInner::SendCdmaSms(std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendCdmaSms(pdu, response);
}

void CoreManagerInner::AddSimMessage(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->AddSimMessage(status, smscPdu, pdu, response);
}

void CoreManagerInner::DelSimMessage(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->DelSimMessage(gsmIndex, response);
}

void CoreManagerInner::GetSmscAddr(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetSmscAddr(response);
}

void CoreManagerInner::SetSmscAddr(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetSmscAddr(tosca, address, response);
}

void CoreManagerInner::SetCBConfig(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCBConfig(mode, idList, dcsList, response);
}

void CoreManagerInner::SetCdmaCBConfig(
    CdmaCBConfigInfoList &cdmaCBConfigInfoList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCdmaCBConfig(cdmaCBConfigInfoList, response);
}

void CoreManagerInner::GetCBConfig(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCBConfig(result);
}

void CoreManagerInner::GetCdmaCBConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCdmaCBConfig(response);
}

void CoreManagerInner::SendSmsMoreMode(
    std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendSmsMoreMode(smscPdu, pdu, response);
}

void CoreManagerInner::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SendSmsAck(success, cause, response);
}

void CoreManagerInner::AddCdmaSimMessage(
    int32_t status, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->AddCdmaSimMessage(status, pdu, response);
}

void CoreManagerInner::DelCdmaSimMessage(int32_t cdmaIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->DelCdmaSimMessage(cdmaIndex, response);
}

void CoreManagerInner::UpdateCdmaSimMessage(
    int32_t cdmaIndex, int32_t state, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->UpdateCdmaSimMessage(cdmaIndex, state, pdu, response);
}

void CoreManagerInner::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetNetworkSearchInformation(response);
}

void CoreManagerInner::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetNetworkSelectionMode(response);
}

void CoreManagerInner::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetNetworkSelectionMode(automaticFlag, oper, response);
}

bool CoreManagerInner::SetPsAttachStatus(
    int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SetPsAttachStatus(slotId, psAttachStatus, callback);
}

void CoreManagerInner::TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->TelRilSetParam(preferredNetworkType, cdmaSubscription, instanceId);
}

bool CoreManagerInner::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetPreferredNetwork(slotId, callback);
    }
    return false;
}

bool CoreManagerInner::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->SetPreferredNetwork(slotId, networkMode, callback);
    }
    return false;
}

bool CoreManagerInner::IsNrSupported()
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->IsNrSupported();
    }
    return false;
}

void CoreManagerInner::DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive)
{
    if (networkSearchManager_ != nullptr) {
        networkSearchManager_->DcPhysicalLinkActiveUpdate(slotId, isActive);
    }
}

NrMode CoreManagerInner::GetNrOptionMode(int32_t slotId)
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetNrOptionMode(slotId);
    }
    return NrMode::NR_MODE_UNKNOWN;
}

FrequencyType CoreManagerInner::GetFrequencyType(int32_t slotId) const
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetFrequencyType(slotId);
    }
    return FrequencyType::FREQ_TYPE_UNKNOWN;
}

NrState CoreManagerInner::GetNrState(int32_t slotId) const
{
    if (networkSearchManager_ != nullptr) {
        return networkSearchManager_->GetNrState(slotId);
    }
    return NrState::NR_STATE_NOT_SUPPORT;
}

void CoreManagerInner::SetPreferredNetworkPara(
    int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetPreferredNetwork(preferredNetworkType, response);
}

void CoreManagerInner::GetPreferredNetworkPara(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetPreferredNetwork(response);
}

void CoreManagerInner::GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetRadioCapability(response);
}

void CoreManagerInner::SetRadioCapability(
    RadioCapabilityInfo &radioCapabilityInfo, const AppExecFwk::InnerEvent::Pointer &response) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetRadioCapability(radioCapabilityInfo, response);
}

bool CoreManagerInner::InitCellularRadio(bool isFirst)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return false;
    }
    return telRilManager_->InitCellularRadio(isFirst);
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> CoreManagerInner::QueryIccDiallingNumbers(int slotId, int type)
{
    std::vector<std::shared_ptr<DiallingNumbersInfo>> result;
    if (iccDiallingNumbersManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return result;
    }
    return iccDiallingNumbersManager_->QueryIccDiallingNumbers(slotId, type);
}

bool CoreManagerInner::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (iccDiallingNumbersManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return false;
    }
    return iccDiallingNumbersManager_->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreManagerInner::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (iccDiallingNumbersManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return false;
    }
    return iccDiallingNumbersManager_->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreManagerInner::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    if (iccDiallingNumbersManager_ == nullptr) {
        TELEPHONY_LOGE("iccDiallingNumbersManager is null!");
        return false;
    }
    return iccDiallingNumbersManager_->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreManagerInner::AddSmsToIcc(int status, std::string &pdu, std::string &smsc)
{
    if (simSmsManager_ == nullptr) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return false;
    }
    return simSmsManager_->AddSmsToIcc(status, pdu, smsc);
}

bool CoreManagerInner::UpdateSmsIcc(int index, int status, std::string &pduData, std::string &smsc)
{
    if (simSmsManager_ == nullptr) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return false;
    }
    return simSmsManager_->UpdateSmsIcc(index, status, pduData, smsc);
}

std::vector<std::string> CoreManagerInner::ObtainAllSmsOfIcc()
{
    std::vector<std::string> result;
    if (simSmsManager_ == nullptr) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return result;
    }
    return simSmsManager_->ObtainAllSmsOfIcc();
}

bool CoreManagerInner::DelSmsIcc(int index)
{
    if (simSmsManager_ == nullptr) {
        TELEPHONY_LOGE("simSmsManager_ is null!");
        return false;
    }
    return simSmsManager_->DelSmsIcc(index);
}

bool CoreManagerInner::IsSimActive(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->IsSimActive(slotId);
}

bool CoreManagerInner::SetActiveSim(int32_t slotId, int32_t enable)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetActiveSim(slotId, enable);
}

bool CoreManagerInner::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->GetSimAccountInfo(slotId, info);
}

bool CoreManagerInner::SetDefaultVoiceSlotId(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetDefaultVoiceSlotId(slotId);
}

bool CoreManagerInner::SetDefaultSmsSlotId(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetDefaultSmsSlotId(slotId);
}

bool CoreManagerInner::SetDefaultCellularDataSlotId(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetDefaultCellularDataSlotId(slotId);
}

bool CoreManagerInner::SetPrimarySlotId(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetPrimarySlotId(slotId);
}

bool CoreManagerInner::SetShowNumber(int32_t slotId, const std::u16string number)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetShowNumber(slotId, number);
}

bool CoreManagerInner::SetShowName(int32_t slotId, const std::u16string name)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->SetShowName(slotId, name);
}

int32_t CoreManagerInner::GetDefaultVoiceSlotId()
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return TELEPHONY_ERROR;
    }
    return simAccountManager_->GetDefaultVoiceSlotId();
}

int32_t CoreManagerInner::GetDefaultSmsSlotId()
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return TELEPHONY_ERROR;
    }
    return simAccountManager_->GetDefaultSmsSlotId();
}

int32_t CoreManagerInner::GetDefaultCellularDataSlotId()
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return TELEPHONY_ERROR;
    }
    return simAccountManager_->GetDefaultCellularDataSlotId();
}

int32_t CoreManagerInner::GetPrimarySlotId()
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return TELEPHONY_ERROR;
    }
    return simAccountManager_->GetPrimarySlotId();
}

std::u16string CoreManagerInner::GetShowNumber(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return u"";
    }
    return simAccountManager_->GetShowNumber(slotId);
}

std::u16string CoreManagerInner::GetShowName(int32_t slotId)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return u"";
    }
    return simAccountManager_->GetShowName(slotId);
}

bool CoreManagerInner::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->GetActiveSimAccountInfoList(iccAccountInfoList);
}

bool CoreManagerInner::GetOperatorConfigs(int slotId, OperatorConfig &poc)
{
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager is null!");
        return false;
    }
    return simAccountManager_->GetOperatorConfigs(slotId, poc);
}

std::u16string CoreManagerInner::GetSimOperatorNumeric(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimOperatorNumeric(slotId);
}

std::u16string CoreManagerInner::GetISOCountryCodeForSim(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetISOCountryCodeForSim(slotId);
}

std::u16string CoreManagerInner::GetSimIccId(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimIccId(slotId);
}

std::u16string CoreManagerInner::GetIMSI(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetIMSI(slotId);
}

std::u16string CoreManagerInner::GetLocaleFromDefaultSim()
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetLocaleFromDefaultSim();
}

std::u16string CoreManagerInner::GetSimGid1(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimGid1(slotId);
}

std::u16string CoreManagerInner::GetSimTelephoneNumber(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimTelephoneNumber(slotId);
}

std::u16string CoreManagerInner::GetSimTeleNumberIdentifier(const int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetSimTeleNumberIdentifier(slotId);
}

std::u16string CoreManagerInner::GetVoiceMailIdentifier(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetVoiceMailIdentifier(slotId);
}

std::u16string CoreManagerInner::GetVoiceMailNumber(int32_t slotId)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager is null!");
        return u"";
    }
    return simFileManager_->GetVoiceMailNumber(slotId);
}

bool CoreManagerInner::HasSimCard(int32_t slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->HasSimCard(slotId);
}

int32_t CoreManagerInner::GetSimState(int32_t slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return TELEPHONY_ERROR;
    }
    return static_cast<int32_t>(simStateManager_->GetSimState(slotId));
}

int32_t CoreManagerInner::GetCardType(int32_t slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return TELEPHONY_ERROR;
    }
    return static_cast<int32_t>(simStateManager_->GetCardType(slotId));
}

bool CoreManagerInner::UnlockPin(int32_t slotId, std::string pin, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockPin(slotId, pin, response);
}

bool CoreManagerInner::UnlockPuk(int32_t slotId, std::string newPin, std::string puk, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockPuk(slotId, newPin, puk, response);
}

bool CoreManagerInner::AlterPin(int32_t slotId, std::string newPin, std::string oldPin, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->AlterPin(slotId, newPin, oldPin, response);
}

bool CoreManagerInner::SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->SetLockState(slotId, options, response);
}

int32_t CoreManagerInner::GetLockState(int32_t slotId, LockType lockType)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->GetLockState(slotId, lockType);
}

int32_t CoreManagerInner::RefreshSimState(int32_t slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->RefreshSimState(slotId);
}

bool CoreManagerInner::UnlockPin2(int32_t slotId, std::string pin2, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockPin2(slotId, pin2, response);
}

bool CoreManagerInner::UnlockPuk2(int32_t slotId, std::string newPin2, std::string puk2, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockPuk2(slotId, newPin2, puk2, response);
}

bool CoreManagerInner::AlterPin2(
    int32_t slotId, std::string newPin2, std::string oldPin2, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->AlterPin2(slotId, newPin2, oldPin2, response);
}

int32_t CoreManagerInner::GetMaxSimCount()
{
    return SIM_SLOT_NUM;
}

bool CoreManagerInner::SendEnvelopeCmd(const std::string &cmd)
{
    if (stkManager_ == nullptr) {
        TELEPHONY_LOGE("stkManager is null!");
        return false;
    }
    return stkManager_->SendEnvelopeCmd(cmd);
}

bool CoreManagerInner::SendTerminalResponseCmd(const std::string &cmd)
{
    if (stkManager_ == nullptr) {
        TELEPHONY_LOGE("stkManager is null!");
        return false;
    }
    return stkManager_->SendTerminalResponseCmd(cmd);
}

bool CoreManagerInner::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager is null!");
        return false;
    }
    return simStateManager_->UnlockSimLock(slotId, lockInfo, response);
}

std::shared_ptr<ITelRilManager> CoreManagerInner::GetRilManager() const
{
    return telRilManager_;
}

void CoreManagerInner::GetImsCallList(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetImsCallList(result);
}

void CoreManagerInner::SetCallPreferenceMode(int32_t mode, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetCallPreferenceMode(mode, result);
}

void CoreManagerInner::GetCallPreferenceMode(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallPreferenceMode(result);
}

void CoreManagerInner::SetLteImsSwitchStatus(int32_t active, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetLteImsSwitchStatus(active, result);
}

void CoreManagerInner::GetLteImsSwitchStatus(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetLteImsSwitchStatus(result);
}

bool CoreManagerInner::GetImsRegStatus() const
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetImsRegStatus();
}

void CoreManagerInner::SetUssdCusd(const std::string str, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetUssdCusd(str, result);
}

void CoreManagerInner::GetUssdCusd(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetUssdCusd(result);
}

void CoreManagerInner::GetMute(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetMute(result);
}

void CoreManagerInner::SetMute(int32_t mute, const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->SetMute(mute, result);
}

void CoreManagerInner::GetEmergencyCallList(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetEmergencyCallList(result);
}

void CoreManagerInner::GetCallFailReason(const AppExecFwk::InnerEvent::Pointer &result) const
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager is null!");
        return;
    }
    telRilManager_->GetCallFailReason(result);
}

bool CoreManagerInner::HasOperatorPrivileges(const int32_t slotId)
{
    TELEPHONY_LOGI("CoreManagerInner::HasOperatorPrivileges slotId:%{public}d", slotId);
    if (simAccountManager_ == nullptr) {
        TELEPHONY_LOGE("simAccountManager_ can not be null!");
        return false;
    }
    return simAccountManager_->HasOperatorPrivileges(slotId);
}
} // namespace Telephony
} // namespace OHOS
