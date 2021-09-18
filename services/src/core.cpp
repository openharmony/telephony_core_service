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

#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "core.h"
#include "network_search_manager.h"
#include "sim_manager.h"
#include "sim_sms_manager.h"
#include "tel_ril_manager.h"

using namespace OHOS::Telephony;
namespace OHOS {
namespace Telephony {
Core::Core(int opt) : networkSearchManager_(nullptr), rilManager_(nullptr), slotId_(opt), isInitCore_(false) {}

void Core::OnInit()
{
    TELEPHONY_LOGD("Core OnInit");
    rilManager_ = std::make_shared<RilManager>();
    if (rilManager_ != nullptr) {
        rilManager_->TelRilSetParam(0, 1, slotId_);
        rilManager_->OnInit();
    }
    simStateManager_ = std::make_shared<SimStateManager>();
    if (simStateManager_ != nullptr) {
        simStateManager_->Init();
    }
    simFileManager_ = std::make_shared<SimFileManager>(simStateManager_);
    if (simFileManager_ != nullptr) {
        simFileManager_->Init();
    }
    networkSearchManager_ = std::make_shared<NetworkSearchManager>(rilManager_, simStateManager_, simFileManager_);
    if (networkSearchManager_ != nullptr) {
        networkSearchManager_->Init();
    }
    simSmsManager_ = std::make_shared<SimSmsManager>();
    if (simSmsManager_ != nullptr) {
        simSmsManager_->Init();
    }
    simManager_ = std::make_shared<SimManager>();
    if (simManager_ != nullptr) {
        simManager_->Init();
    }

    isInitCore_ = true;
}

bool Core::IsInitCore()
{
    return isInitCore_;
}

void Core::InitTelInfo()
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->InitTelInfo();
}

void Core::RegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj)
{
    if (what >= ObserverHandler::RADIO_PS_CONNECTION_ATTACHED && what <= ObserverHandler::RADIO_PS_ROAMING_CLOSE) {
        if (networkSearchManager_ == nullptr) {
            TELEPHONY_LOGE("networkSearchManager is null!");
            return;
        }
        networkSearchManager_->RegisterPhoneNotify(handler, what, obj);
    } else {
        if (rilManager_ == nullptr) {
            TELEPHONY_LOGE("rilManager is null!");
            return;
        }
        rilManager_->RegisterPhoneNotify(handler, what, obj);
    }
}

void Core::UnRegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what)
{
    if (what >= ObserverHandler::RADIO_PS_CONNECTION_ATTACHED && what <= ObserverHandler::RADIO_PS_ROAMING_CLOSE) {
        if (networkSearchManager_ == nullptr) {
            TELEPHONY_LOGE("networkSearchManager is null!");
            return;
        }
        networkSearchManager_->UnRegisterPhoneNotify(observerCallBack, what);
    } else {
        if (rilManager_ == nullptr) {
            TELEPHONY_LOGE("rilManager is null!");
            return;
        }
        rilManager_->UnRegisterPhoneNotify(observerCallBack, what);
    }
}

void Core::SetRadioStatus(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }

    rilManager_->SetRadioStatus(fun, rst, response);
}

void Core::GetRadioStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetRadioStatus(response);
}

void Core::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->ShutDown(response);
}

void Core::Dial(std::string address, int clirMode, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Dial(address, clirMode, result);
}

void Core::DialIms(const AppExecFwk::InnerEvent::Pointer &result)
{
    auto handler = result->GetOwner();
    sptr<ISystemAbilityManager> systemAbilityMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        printf("Service Get ISystemAbilityManager failed.\n");
        return;
    }
    int32_t TELEPHONY_IMS_SYS_ABILITY_ID = 10001;
    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_IMS_SYS_ABILITY_ID);
    if (remote == nullptr) {
        printf("Service Remote service not exists.\n");
        return;
    }
}

void Core::Reject(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Reject(result);
}

void Core::Hangup(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Hangup(gsmIndex, result);
}

void Core::Answer(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Answer(result);
}

void Core::GetCallList(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetCallList(result);
}

void Core::Hold(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Hold(result);
}

void Core::Active(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Active(result);
}

void Core::Swap(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Swap(result);
}

void Core::Join(int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Join(callType, result);
}

void Core::Split(int32_t nThCall, int32_t callType, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->Split(nThCall, callType, result);
}

void Core::CallSupplement(int32_t type, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("CallSupplement, rilManager is null!");
        return;
    }
    rilManager_->CallSupplement(type, result);
}

void Core::GetClip(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetClip(result);
}

void Core::SetClip(int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetClip(action, result);
}

void Core::GetClir(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetClir(result);
}

void Core::SetClir(int32_t action, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetClir(action, result);
}

void Core::SetCallWait(int32_t activate, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetCallWait(activate, result);
}
void Core::SetCallForward(int32_t reason, int32_t mode, std::string number, int32_t classx,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetCallForward(reason, mode, number, classx, result);
}
void Core::GetCallForward(const int32_t reason, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetCallForward(reason, result);
}
void Core::GetCallWait(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetCallWait(result);
}

void Core::GetCallRestriction(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetCallRestriction(fac, result);
}

void Core::SetCallRestriction(
    std::string &fac, int32_t mode, std::string &password, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetCallRestriction(fac, mode, password, result);
}

void Core::SendDtmf(const std::string &sDTMFCode, int32_t index, int32_t switchOn, int32_t switchOff,
    const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SendDtmf(sDTMFCode, index, switchOn, switchOff, result);
}

void Core::SendDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SendDtmf(cDTMFCode, index, result);
}

void Core::StartDtmf(char cDTMFCode, int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->StartDtmf(cDTMFCode, index, result);
}

void Core::StopDtmf(int32_t index, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->StopDtmf(index, result);
}

void Core::ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->ActivatePdpContext(radioTechnology, dataProfile, isRoaming, allowRoaming, response);
}

void Core::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->DeactivatePdpContext(cid, reason, response);
}

void Core::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetSignalStrength(response);
}

void Core::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetCsRegStatus(response);
}

void Core::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetPsRegStatus(response);
}

int32_t Core::GetPsRadioTech(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return -1;
    }
    return networkSearchManager_->GetPsRadioTech(slotId);
}

int32_t Core::GetCsRadioTech(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return -1;
    }
    return networkSearchManager_->GetCsRadioTech(slotId);
}

bool Core::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->SetNetworkSelectionMode(
        slotId, selectMode, networkInformation, resumeSelection, callback);
}

std::vector<sptr<SignalInformation>> Core::GetSignalInfoList(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::vector<sptr<SignalInformation>>();
    }
    return networkSearchManager_->GetSignalInfoList(slotId);
}

std::u16string Core::GetOperatorNumeric(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorNumeric(slotId);
}

std::u16string Core::GetOperatorName(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetOperatorName(slotId);
}

sptr<NetworkState> Core::GetNetworkStatus(int32_t slotId)
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

bool Core::GetRadioState(const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetRadioState(callback);
}

std::u16string Core::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return std::u16string();
    }
    return networkSearchManager_->GetIsoCountryCodeForNetwork(slotId);
}

bool Core::GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetNetworkSearchResult(slotId, callback);
}

bool Core::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("networkSearchManager is null!");
        return false;
    }
    return networkSearchManager_->GetNetworkSelectionMode(slotId, callback);
}

void Core::RegisterIccStateChanged(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (simStateManager_ != nullptr) {
        simStateManager_->RegisterIccStateChanged(handler);
    }
}

void Core::RegisterImsiLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (simFileManager_ != nullptr) {
        simFileManager_->RegisterImsiLoaded(handler);
    }
}

void Core::RegisterAllFilesLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (simFileManager_ != nullptr) {
        simFileManager_->RegisterAllFilesLoaded(handler);
    }
}

int32_t Core::ObtainSpnCondition(bool roaming, std::string operatorNum)
{
    if (simFileManager_ != nullptr) {
        return simFileManager_->ObtainSpnCondition(roaming, operatorNum);
    }
    return 0;
}

std::u16string Core::GetSpn(int32_t slotId)
{
    if (simFileManager_ != nullptr) {
        return simFileManager_->GetSimSpn(slotId);
    }
    return std::u16string();
}

void Core::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetOperatorInfo(response);
}

void Core::SendSms(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SendSms(smscPdu, pdu, response);
}

void Core::StorageSms(
    int32_t status, std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->StorageSms(status, smscPdu, pdu, response);
}

void Core::DeleteSms(int32_t gsmIndex, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->DeleteSms(gsmIndex, response);
}

void Core::GetSmsCenterAddress(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetSmsCenterAddress(response);
}

void Core::SetSmsCenterAddress(int32_t tosca, std::string address, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetSmsCenterAddress(tosca, address, response);
}

void Core::SetCellBroadcast(
    int32_t mode, std::string idList, std::string dcsList, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetCellBroadcast(mode, idList, dcsList, response);
}

void Core::SendSmsMoreMode(std::string smscPdu, std::string pdu, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SendSmsMoreMode(smscPdu, pdu, response);
}

void Core::SendSmsAck(bool success, int32_t cause, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SendSmsAck(success, cause, response);
}

void Core::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetSimStatus(result);
}

void Core::ReadIccFile(int32_t command, int32_t fileId, int32_t p1, int32_t p2, int32_t p3, std::string data,
    std::string path, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->RequestSimIO(command, fileId, p1, p2, p3, data, path, response);
}

void Core::GetImsi(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetImsi(result);
}
void Core::GetIccID(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetIccID(result);
}

void Core::GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetSimLockStatus(fac, result);
}

void Core::SetSimLock(
    std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetSimLock(fac, mode, passwd, result);
}

void Core::ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
    int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->ChangeSimPassword(fac, oldPassword, newPassword, passwordLength, result);
}

void Core::EnterSimPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->EnterSimPin(pin, result);
}

void Core::UnlockSimPin(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->UnlockSimPin(puk, pin, result);
}

void Core::GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetSimPinInputTimes(result);
}

void Core::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetNetworkSearchInformation(response);
}

void Core::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->GetNetworkSelectionMode(response);
}

void Core::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetNetworkSelectionMode(automaticFlag, oper, response);
}

void Core::SetNetworkLocationUpdate(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->SetNetworkLocationUpdate(result);
}

void Core::TelRilSetParam(int32_t preferredNetworkType, int32_t cdmaSubscription, int32_t instanceId)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return;
    }
    rilManager_->TelRilSetParam(preferredNetworkType, cdmaSubscription, instanceId);
}

bool Core::InitCellularRadio(bool isFirst)
{
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("rilManager is null!");
        return false;
    }
    return rilManager_->InitCellularRadio(isFirst);
}

std::shared_ptr<INetworkSearch> Core::GetNetworkSearchManager() const
{
    return networkSearchManager_;
}

std::shared_ptr<IRilManager> Core::GetRilManager() const
{
    return rilManager_;
}

std::shared_ptr<ISimFileManager> Core::GetSimFileManager() const
{
    return simFileManager_;
}

std::shared_ptr<ISimStateManager> Core::GetSimStateManager() const
{
    return simStateManager_;
}

std::shared_ptr<ISimSmsManager> Core::GetSimSmsManager() const
{
    return simSmsManager_;
}

std::shared_ptr<ISimManager> Core::GetSimManager() const
{
    return simManager_;
}
} // namespace Telephony
} // namespace OHOS