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

#include "telephony_state_registry_client.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
TelephonyStateRegistryClient::TelephonyStateRegistryClient() = default;
TelephonyStateRegistryClient::~TelephonyStateRegistryClient() = default;

sptr<ITelephonyStateNotify> TelephonyStateRegistryClient::GetProxy()
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
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID);
    if (obj == nullptr) {
        TELEPHONY_LOGE("Failed to get state registry service");
        return nullptr;
    }
    std::unique_ptr<StateRegistryDeathRecipient> recipient = std::make_unique<StateRegistryDeathRecipient>(*this);
    if (recipient == nullptr) {
        TELEPHONY_LOGE("recipient is null");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr(recipient.release());
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        TELEPHONY_LOGE("Failed to add death recipient");
        return nullptr;
    }
    proxy_ = iface_cast<ITelephonyStateNotify>(obj);
    deathRecipient_ = dr;
    TELEPHONY_LOGI("Succeed to connect state registry service %{public}d", proxy_ == nullptr);
    return proxy_;
}

void StateRegistryDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
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

int32_t TelephonyStateRegistryClient::UpdateCellularDataConnectState(
    int32_t simId, int32_t dataState, int32_t networkState)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UpdateCellularDataConnectState(simId, dataState, networkState);
}

int32_t TelephonyStateRegistryClient::UpdateCallState(int32_t callStatus, const std::u16string &number)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UpdateCallState(callStatus, number);
}

int32_t TelephonyStateRegistryClient::UpdateCallStateForSimId(
    int32_t simId, int32_t callId, int32_t callStatus, const std::u16string &number)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UpdateCallStateForSimId(simId, callId, callStatus, number);
}

int32_t TelephonyStateRegistryClient::UpdateSignalInfo(
    int32_t simId, const std::vector<sptr<SignalInformation>> &vec)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UpdateSignalInfo(simId, vec);
}

int32_t TelephonyStateRegistryClient::UpdateCellInfo(int32_t simId, const std::vector<sptr<CellInformation>> &vec)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UpdateCellInfo(simId, vec);
}

int32_t TelephonyStateRegistryClient::UpdateNetworkState(int32_t simId, const sptr<NetworkState> &networkState)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UpdateNetworkState(simId, networkState);
}

int32_t TelephonyStateRegistryClient::UpdateSimState(int32_t simId, SimState state, LockReason reason)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UpdateSimState(simId, state, reason);
}

int32_t TelephonyStateRegistryClient::RegisterStateChange(const sptr<TelephonyObserverBroker> &telephonyObserver,
    int32_t simId, uint32_t mask, const std::u16string &package, bool isUpdate)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->RegisterStateChange(telephonyObserver, simId, mask, package, isUpdate);
}

int32_t TelephonyStateRegistryClient::UnregisterStateChange(int32_t simId, uint32_t mask)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UnregisterStateChange(simId, mask);
}
}
}

