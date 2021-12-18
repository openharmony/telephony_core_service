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

#include "cellular_data_client.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
CellularDataClient::CellularDataClient() = default;
CellularDataClient::~CellularDataClient() = default;

sptr<ICellularDataManager> CellularDataClient::GetProxy()
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
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(TELEPHONY_CELLULAR_DATA_SYS_ABILITY_ID);
    if (obj == nullptr) {
        TELEPHONY_LOGE("Failed to get cellular data service");
        return nullptr;
    }
    std::unique_ptr<CellularDataDeathRecipient> recipient = std::make_unique<CellularDataDeathRecipient>(*this);
    if (recipient == nullptr) {
        TELEPHONY_LOGE("recipient is null");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr(recipient.release());
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        TELEPHONY_LOGE("Failed to add death recipient");
        return nullptr;
    }
    proxy_ = iface_cast<ICellularDataManager>(obj);
    deathRecipient_ = dr;
    TELEPHONY_LOGI("Succeed to connect cellular data service %{public}d", proxy_ == nullptr);
    return proxy_;
}

void CellularDataClient::OnRemoteDied(const wptr<IRemoteObject> &remote)
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

bool CellularDataClient::IsConnect() const
{
    return (proxy_ != nullptr);
}

int32_t CellularDataClient::GetDefaultCellularDataSlotId()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetDefaultCellularDataSlotId();
}

int32_t CellularDataClient::SetDefaultCellularDataSlotId(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetDefaultCellularDataSlotId(slotId);
}

int32_t CellularDataClient::EnableCellularData(bool enable)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->EnableCellularData(enable);
}

int32_t CellularDataClient::IsCellularDataEnabled()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->IsCellularDataEnabled();
}

int32_t CellularDataClient::GetCellularDataState()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetCellularDataState();
}

int32_t CellularDataClient::IsCellularDataRoamingEnabled(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->IsCellularDataRoamingEnabled(slotId);
}

int32_t CellularDataClient::EnableCellularDataRoaming(int32_t slotId, bool enable)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->EnableCellularDataRoaming(slotId, enable);
}

int32_t CellularDataClient::RequestNet(std::string ident, uint64_t capability)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->RequestNet(std::move(ident), capability);
}

int32_t CellularDataClient::ReleaseNet(std::string ident, uint64_t capability)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->ReleaseNet(std::move(ident), capability);
}

int32_t CellularDataClient::GetCellularDataFlowType()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetCellularDataFlowType();
}

int32_t CellularDataClient::StrategySwitch(bool enable)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->StrategySwitch(enable);
}
} // namespace Telephony
} // namespace OHOS