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

#include "core_service_client.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "core_service_proxy.h"
#include "telephony_log_wrapper.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
CoreServiceClient::CoreServiceClient() = default;
CoreServiceClient::~CoreServiceClient() = default;

sptr<ICoreService> CoreServiceClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(mutexProxy_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        TELEPHONY_LOGE("Failed to get system ability manager");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (obj == nullptr) {
        TELEPHONY_LOGE("Failed to get cellular data service");
        return nullptr;
    }
    std::unique_ptr<CoreServiceDeathRecipient> recipient = std::make_unique<CoreServiceDeathRecipient>(*this);
    if (recipient == nullptr) {
        TELEPHONY_LOGE("recipient is null");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr(recipient.release());
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        TELEPHONY_LOGE("Failed to add death recipient");
        return nullptr;
    }
    proxy_ = iface_cast<CoreServiceProxy>(obj);
    deathRecipient_ = dr;
    TELEPHONY_LOGI("Succeed to connect cellular data service %{public}d", proxy_ == nullptr);
    return proxy_;
}

void CoreServiceClient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        TELEPHONY_LOGE("OnRemoteDied failed, remote is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(mutexProxy_);
    if (proxy_ == nullptr) {
        TELEPHONY_LOGE("OnRemoteDied proxy_ is nullptr");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
        TELEPHONY_LOGE("on remote died");
    }
}

int32_t CoreServiceClient::GetPsRadioTech(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetPsRadioTech(slotId);
}

int32_t CoreServiceClient::GetCsRadioTech(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetCsRadioTech(slotId);
}

std::u16string CoreServiceClient::GetMeid(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetMeid(slotId);
}

std::u16string CoreServiceClient::GetUniqueDeviceId(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetUniqueDeviceId(slotId);
}
bool CoreServiceClient::IsNrSupported(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->IsNrSupported(slotId);
}

NrMode CoreServiceClient::GetNrOptionMode(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return NrMode::NR_MODE_UNKNOWN;
    }
    return proxy->GetNrOptionMode(slotId);
}

std::vector<sptr<SignalInformation>> CoreServiceClient::GetSignalInfoList(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        std::vector<sptr<SignalInformation>> vec;
        vec.clear();
        return vec;
    }
    return proxy->GetSignalInfoList(slotId);
}

std::u16string CoreServiceClient::GetOperatorNumeric(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetOperatorNumeric(slotId);
}

std::u16string CoreServiceClient::GetOperatorName(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetOperatorName(slotId);
}

const sptr<NetworkState> CoreServiceClient::GetNetworkState(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        const sptr<NetworkState> vec = nullptr;
        return vec;
    }
    return proxy->GetNetworkState(slotId);
}

bool CoreServiceClient::SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetRadioState(slotId, isOn, callback);
}

bool CoreServiceClient::GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->GetRadioState(slotId, callback);
}

std::u16string CoreServiceClient::GetImei(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetImei(slotId);
}

bool CoreServiceClient::HasSimCard(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->HasSimCard(slotId);
}

int32_t CoreServiceClient::GetSimState(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSimState(slotId);
}

std::u16string CoreServiceClient::GetSimOperatorNumeric(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetSimOperatorNumeric(slotId);
}

std::u16string CoreServiceClient::GetISOCountryCodeForSim(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetISOCountryCodeForSim(slotId);
}

std::u16string CoreServiceClient::GetSimSpn(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetSimSpn(slotId);
}

std::u16string CoreServiceClient::GetSimIccId(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetSimIccId(slotId);
}

std::u16string CoreServiceClient::GetIMSI(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetIMSI(slotId);
}

bool CoreServiceClient::IsSimActive(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->IsSimActive(slotId);
}

bool CoreServiceClient::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->GetNetworkSearchInformation(slotId, callback);
}

bool CoreServiceClient::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->GetNetworkSelectionMode(slotId, callback);
}

std::u16string CoreServiceClient::GetLocaleFromDefaultSim()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetLocaleFromDefaultSim();
}

std::u16string CoreServiceClient::GetSimGid1(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetSimGid1(slotId);
}

bool CoreServiceClient::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetNetworkSelectionMode(slotId, selectMode, networkInformation, resumeSelection, callback);
}

std::u16string CoreServiceClient::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetIsoCountryCodeForNetwork(slotId);
}

bool CoreServiceClient::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->GetSimAccountInfo(slotId, info);
}

bool CoreServiceClient::SetDefaultVoiceSlotId(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetDefaultVoiceSlotId(slotId);
}

int32_t CoreServiceClient::GetDefaultVoiceSlotId()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetDefaultVoiceSlotId();
}

bool CoreServiceClient::SetShowNumber(int32_t slotId, const std::u16string number)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetShowNumber(slotId, number);
}

std::u16string CoreServiceClient::GetShowNumber(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetShowNumber(slotId);
}

bool CoreServiceClient::SetShowName(int32_t slotId, const std::u16string name)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetShowName(slotId, name);
}

std::u16string CoreServiceClient::GetShowName(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetShowName(slotId);
}

bool CoreServiceClient::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->GetActiveSimAccountInfoList(iccAccountInfoList);
}

bool CoreServiceClient::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->GetOperatorConfigs(slotId, poc);
}

bool CoreServiceClient::UnlockPin(int32_t slotId, std::u16string pin, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->UnlockPin(slotId, pin, response);
}

bool CoreServiceClient::UnlockPuk(
    int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->UnlockPuk(slotId, newPin, puk, response);
}

bool CoreServiceClient::AlterPin(
    int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->AlterPin(slotId, newPin, oldPin, response);
}

bool CoreServiceClient::UnlockPin2(int32_t slotId, std::u16string pin2, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->UnlockPin2(slotId, pin2, response);
}

bool CoreServiceClient::UnlockPuk2(
    int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->UnlockPuk2(slotId, newPin2, puk2, response);
}

bool CoreServiceClient::AlterPin2(
    int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->AlterPin2(slotId, newPin2, oldPin2, response);
}

bool CoreServiceClient::SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetLockState(slotId, options, response);
}

int32_t CoreServiceClient::GetLockState(int32_t slotId, LockType lockType)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetLockState(slotId, lockType);
}

int32_t CoreServiceClient::RefreshSimState(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->RefreshSimState(slotId);
}

bool CoreServiceClient::SetActiveSim(const int32_t slotId, int32_t enable)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetActiveSim(slotId, enable);
}

bool CoreServiceClient::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->GetPreferredNetwork(slotId, callback);
}

bool CoreServiceClient::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetPreferredNetwork(slotId, networkMode, callback);
}

bool CoreServiceClient::SetPsAttachStatus(
    int32_t slotId, int32_t psAttachStatus, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetPsAttachStatus(slotId, psAttachStatus, callback);
}

std::u16string CoreServiceClient::GetSimTelephoneNumber(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetSimTelephoneNumber(slotId);
}

std::u16string CoreServiceClient::GetVoiceMailIdentifier(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetVoiceMailIdentifier(slotId);
}

std::u16string CoreServiceClient::GetVoiceMailNumber(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetVoiceMailNumber(slotId);
}

std::vector<std::shared_ptr<DiallingNumbersInfo>> CoreServiceClient::QueryIccDiallingNumbers(int slotId, int type)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        std::vector<std::shared_ptr<DiallingNumbersInfo>> vec;
        vec.clear();
        return vec;
    }
    return proxy->QueryIccDiallingNumbers(slotId, type);
}

bool CoreServiceClient::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreServiceClient::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreServiceClient::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

bool CoreServiceClient::SetVoiceMailInfo(
    int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

bool CoreServiceClient::GetImsRegStatus(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->GetImsRegStatus(slotId);
}

int32_t CoreServiceClient::GetMaxSimCount()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetMaxSimCount();
}

int32_t CoreServiceClient::GetCardType(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetCardType(slotId);
}

bool CoreServiceClient::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SendEnvelopeCmd(slotId, cmd);
}
bool CoreServiceClient::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SendTerminalResponseCmd(slotId, cmd);
}
bool CoreServiceClient::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->UnlockSimLock(slotId, lockInfo, response);
}

bool CoreServiceClient::HasOperatorPrivileges(const int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->HasOperatorPrivileges(slotId);
}

int32_t CoreServiceClient::GetPrimarySlotId()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetPrimarySlotId();
}

bool CoreServiceClient::SetPrimarySlotId(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SetPrimarySlotId(slotId);
}

std::vector<sptr<CellInformation>> CoreServiceClient::GetCellInfoList(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        std::vector<sptr<CellInformation>> vec;
        vec.clear();
        return vec;
    }
    return proxy->GetCellInfoList(slotId);
}

bool CoreServiceClient::SendUpdateCellLocationRequest(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SendUpdateCellLocationRequest(slotId);
}
} // namespace Telephony
} // namespace OHOS
