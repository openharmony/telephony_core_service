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

#include "core_service_client.h"

#include "core_service_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "network_search_types.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t INVALID_VALUE = -1;

CoreServiceClient::CoreServiceClient() = default;
CoreServiceClient::~CoreServiceClient()
{
    RemoveDeathRecipient(nullptr, false);
}

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
    proxy_ = iface_cast<ICoreService>(obj);
    deathRecipient_ = dr;
    TELEPHONY_LOGD("Succeed to connect core service %{public}d", proxy_ == nullptr);
    return proxy_;
}

void CoreServiceClient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    RemoveDeathRecipient(remote, true);
}

void CoreServiceClient::RemoveDeathRecipient(const wptr<IRemoteObject> &remote, bool isRemoteDied)
{
    if (isRemoteDied && remote == nullptr) {
        TELEPHONY_LOGE("Remote died, remote is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(mutexProxy_);
    if (proxy_ == nullptr) {
        TELEPHONY_LOGE("proxy_ is nullptr");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if (serviceRemote == nullptr) {
        TELEPHONY_LOGE("serviceRemote is nullptr");
        return;
    }
    if (isRemoteDied && serviceRemote != remote.promote()) {
        TELEPHONY_LOGE("Remote died serviceRemote is not same");
        return;
    }
    serviceRemote->RemoveDeathRecipient(deathRecipient_);
    proxy_ = nullptr;
    TELEPHONY_LOGI("RemoveDeathRecipient success");
}

int32_t CoreServiceClient::GetPsRadioTech(int32_t slotId, int32_t &psRadioTech)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetPsRadioTech(slotId, psRadioTech);
}

int32_t CoreServiceClient::GetCsRadioTech(int32_t slotId, int32_t &csRadioTech)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetCsRadioTech(slotId, csRadioTech);
}

int32_t CoreServiceClient::GetMeid(int32_t slotId, std::u16string &meid)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetMeid(slotId, meid);
}

int32_t CoreServiceClient::GetUniqueDeviceId(int32_t slotId, std::u16string &deviceId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetUniqueDeviceId(slotId, deviceId);
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

int32_t CoreServiceClient::SetNrOptionMode(int32_t slotId, int32_t mode, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetNrOptionMode(slotId, mode, callback);
}

int32_t CoreServiceClient::GetNrOptionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetNrOptionMode(slotId, callback);
}

int32_t CoreServiceClient::GetSignalInfoList(int32_t slotId, std::vector<sptr<SignalInformation>> &signals)
{
    signals.clear();
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSignalInfoList(slotId, signals);
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

int32_t CoreServiceClient::GetOperatorName(int32_t slotId, std::u16string &operatorName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetOperatorName(slotId, operatorName);
}

int32_t CoreServiceClient::GetNetworkState(int32_t slotId, sptr<NetworkState> &networkState)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetNetworkState(slotId, networkState);
}

int32_t CoreServiceClient::SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetRadioState(slotId, isOn, callback);
}

int32_t CoreServiceClient::GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetRadioState(slotId, callback);
}

int32_t CoreServiceClient::GetImei(int32_t slotId, std::u16string &imei)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetImei(slotId, imei);
}

int32_t CoreServiceClient::HasSimCard(int32_t slotId, bool &hasSimCard)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->HasSimCard(slotId, hasSimCard);
}

int32_t CoreServiceClient::GetSimState(int32_t slotId, SimState &simState)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSimState(slotId, simState);
}

int32_t CoreServiceClient::GetDsdsMode(int32_t &dsdsMode)
{
    TELEPHONY_LOGI("Enter CoreServiceClient::GetDsdsMode");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetDsdsMode(dsdsMode);
}

int32_t CoreServiceClient::GetSimOperatorNumeric(int32_t slotId, std::u16string &operatorNumeric)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSimOperatorNumeric(slotId, operatorNumeric);
}

int32_t CoreServiceClient::GetISOCountryCodeForSim(int32_t slotId, std::u16string &countryCode)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetISOCountryCodeForSim(slotId, countryCode);
}

int32_t CoreServiceClient::GetSimSpn(int32_t slotId, std::u16string &spn)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSimSpn(slotId, spn);
}

int32_t CoreServiceClient::GetSimIccId(int32_t slotId, std::u16string &iccId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSimIccId(slotId, iccId);
}

int32_t CoreServiceClient::GetIMSI(int32_t slotId, std::u16string &imsi)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetIMSI(slotId, imsi);
}

int32_t CoreServiceClient::IsCTSimCard(int32_t slotId, bool &isCTSimCard)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->IsCTSimCard(slotId, isCTSimCard);
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

int32_t CoreServiceClient::GetSlotId(int32_t simId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERROR;
    }
    return proxy->GetSlotId(simId);
}

int32_t CoreServiceClient::GetSimId(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERROR;
    }
    return proxy->GetSimId(slotId);
}

int32_t CoreServiceClient::GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetNetworkSearchInformation(slotId, callback);
}

int32_t CoreServiceClient::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
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

int32_t CoreServiceClient::GetSimGid1(int32_t slotId, std::u16string &gid1)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSimGid1(slotId, gid1);
}

std::u16string CoreServiceClient::GetSimGid2(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetSimGid2(slotId);
}

std::u16string CoreServiceClient::GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac,
    bool longNameRequired)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return std::u16string();
    }
    return proxy->GetSimEons(slotId, plmn, lac, longNameRequired);
}

int32_t CoreServiceClient::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetNetworkSelectionMode(slotId, selectMode, networkInformation, resumeSelection, callback);
}

int32_t CoreServiceClient::GetIsoCountryCodeForNetwork(int32_t slotId, std::u16string &countryCode)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetIsoCountryCodeForNetwork(slotId, countryCode);
}

int32_t CoreServiceClient::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSimAccountInfo(slotId, info);
}

int32_t CoreServiceClient::SetDefaultVoiceSlotId(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
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

int32_t CoreServiceClient::GetDefaultVoiceSimId(int32_t &simId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetDefaultVoiceSimId(simId);
}

int32_t CoreServiceClient::SetShowNumber(int32_t slotId, const std::u16string &number)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetShowNumber(slotId, number);
}

int32_t CoreServiceClient::GetShowNumber(int32_t slotId, std::u16string &showNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetShowNumber(slotId, showNumber);
}

int32_t CoreServiceClient::SetShowName(int32_t slotId, const std::u16string &name)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetShowName(slotId, name);
}

int32_t CoreServiceClient::GetShowName(int32_t slotId, std::u16string &showName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetShowName(slotId, showName);
}

int32_t CoreServiceClient::GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetActiveSimAccountInfoList(iccAccountInfoList);
}

int32_t CoreServiceClient::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetOperatorConfigs(slotId, poc);
}

int32_t CoreServiceClient::UnlockPin(int32_t slotId, const std::u16string &pin, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UnlockPin(slotId, pin, response);
}

int32_t CoreServiceClient::UnlockPuk(
    int32_t slotId, const std::u16string &newPin, const std::u16string &puk, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UnlockPuk(slotId, newPin, puk, response);
}

int32_t CoreServiceClient::AlterPin(
    int32_t slotId, const std::u16string &newPin, const std::u16string &oldPin, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->AlterPin(slotId, newPin, oldPin, response);
}

int32_t CoreServiceClient::UnlockPin2(int32_t slotId, const std::u16string &pin2, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UnlockPin2(slotId, pin2, response);
}

int32_t CoreServiceClient::UnlockPuk2(
    int32_t slotId, const std::u16string &newPin2, const std::u16string &puk2, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UnlockPuk2(slotId, newPin2, puk2, response);
}

int32_t CoreServiceClient::AlterPin2(
    int32_t slotId, const std::u16string &newPin2, const std::u16string &oldPin2, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->AlterPin2(slotId, newPin2, oldPin2, response);
}

int32_t CoreServiceClient::SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetLockState(slotId, options, response);
}

int32_t CoreServiceClient::GetLockState(int32_t slotId, LockType lockType, LockState &lockState)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetLockState(slotId, lockType, lockState);
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

int32_t CoreServiceClient::SetActiveSim(const int32_t slotId, int32_t enable)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetActiveSim(slotId, enable);
}

int32_t CoreServiceClient::GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetPreferredNetwork(slotId, callback);
}

int32_t CoreServiceClient::SetPreferredNetwork(
    int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetPreferredNetwork(slotId, networkMode, callback);
}

int32_t CoreServiceClient::GetNetworkCapability(
    int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetNetworkCapability(slotId, networkCapabilityType, networkCapabilityState);
}

int32_t CoreServiceClient::SetNetworkCapability(
    int32_t slotId, int32_t networkCapabilityType, int32_t networkCapabilityState)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetNetworkCapability(slotId, networkCapabilityType, networkCapabilityState);
}

int32_t CoreServiceClient::GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetSimTelephoneNumber(slotId, telephoneNumber);
}

int32_t CoreServiceClient::GetVoiceMailIdentifier(int32_t slotId, std::u16string &voiceMailIdentifier)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetVoiceMailIdentifier(slotId, voiceMailIdentifier);
}

int32_t CoreServiceClient::GetVoiceMailNumber(int32_t slotId, std::u16string &voiceMailNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetVoiceMailNumber(slotId, voiceMailNumber);
}

int32_t CoreServiceClient::GetVoiceMailCount(int32_t slotId, int32_t &voiceMailCount)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreServiceClient::SetVoiceMailCount(int32_t slotId, int32_t voiceMailCount)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetVoiceMailCount(slotId, voiceMailCount);
}

int32_t CoreServiceClient::SetVoiceCallForwarding(int32_t slotId, bool enable, const std::string &number)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetVoiceCallForwarding(slotId, enable, number);
}

int32_t CoreServiceClient::QueryIccDiallingNumbers(
    int slotId, int type, std::vector<std::shared_ptr<DiallingNumbersInfo>> &result)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->QueryIccDiallingNumbers(slotId, type, result);
}

int32_t CoreServiceClient::AddIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->AddIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreServiceClient::DelIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->DelIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreServiceClient::UpdateIccDiallingNumbers(
    int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UpdateIccDiallingNumbers(slotId, type, diallingNumber);
}

int32_t CoreServiceClient::SetVoiceMailInfo(
    int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetVoiceMailInfo(slotId, mailName, mailNumber);
}

int32_t CoreServiceClient::GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetImsRegStatus(slotId, imsSrvType, info);
}

int32_t CoreServiceClient::GetMaxSimCount()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return 0;
    }
    return proxy->GetMaxSimCount();
}

int32_t CoreServiceClient::GetOpKey(int32_t slotId, std::u16string &opkey)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_UNINIT;
    }
    return proxy->GetOpKey(slotId, opkey);
}

int32_t CoreServiceClient::GetOpKeyExt(int32_t slotId, std::u16string &opkeyExt)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_UNINIT;
    }
    return proxy->GetOpKeyExt(slotId, opkeyExt);
}

int32_t CoreServiceClient::GetOpName(int32_t slotId, std::u16string &opname)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_UNINIT;
    }
    return proxy->GetOpName(slotId, opname);
}

int32_t CoreServiceClient::GetCardType(int32_t slotId, CardType &cardType)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetCardType(slotId, cardType);
}

int32_t CoreServiceClient::SendEnvelopeCmd(int32_t slotId, const std::string &cmd)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SendEnvelopeCmd(slotId, cmd);
}

int32_t CoreServiceClient::SendTerminalResponseCmd(int32_t slotId, const std::string &cmd)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SendTerminalResponseCmd(slotId, cmd);
}

int32_t CoreServiceClient::SendCallSetupRequestResult(int32_t slotId, bool accept)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SendCallSetupRequestResult(slotId, accept);
}

int32_t CoreServiceClient::UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UnlockSimLock(slotId, lockInfo, response);
}

int32_t CoreServiceClient::HasOperatorPrivileges(const int32_t slotId, bool &hasOperatorPrivileges)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->HasOperatorPrivileges(slotId, hasOperatorPrivileges);
}

int32_t CoreServiceClient::SimAuthentication(
    int32_t slotId, AuthType authType, const std::string &authData, SimAuthenticationResponse &response)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->SimAuthentication(slotId, authType, authData, response);
}

int32_t CoreServiceClient::GetPrimarySlotId(int32_t &slotId)
{
    slotId = INVALID_VALUE;
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetPrimarySlotId(slotId);
}

int32_t CoreServiceClient::SetPrimarySlotId(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetPrimarySlotId(slotId);
}

int32_t CoreServiceClient::GetCellInfoList(int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetCellInfoList(slotId, cellInfo);
}

int32_t CoreServiceClient::SendUpdateCellLocationRequest(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SendUpdateCellLocationRequest(slotId);
}

int32_t CoreServiceClient::RegisterImsRegInfoCallback(
    int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback is nullptr");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->RegisterImsRegInfoCallback(slotId, imsSrvType, callback);
}

int32_t CoreServiceClient::UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UnregisterImsRegInfoCallback(slotId, imsSrvType);
}

int32_t CoreServiceClient::GetBasebandVersion(int32_t slotId, std::string &version)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetBasebandVersion(slotId, version);
}

int32_t CoreServiceClient::GetNrSsbIdInfo(int32_t slotId, const std::shared_ptr<NrSsbInformation> &nrSsbInformation)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetNrSsbIdInfo(slotId, nrSsbInformation);
}

int32_t CoreServiceClient::FactoryReset(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->FactoryReset(slotId);
}

int32_t CoreServiceClient::InitExtraModule(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->InitExtraModule(slotId);
}

bool CoreServiceClient::IsAllowedInsertApn(std::string &value)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return true;
    }
    return proxy->IsAllowedInsertApn(value);
}

int32_t CoreServiceClient::GetTargetOpkey(int32_t slotId, std::u16string &opkey)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetTargetOpkey(slotId, opkey);
}
} // namespace Telephony
} // namespace OHOS
