/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "satellite_service_client.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "satellite_service_proxy.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
SatelliteServiceClient::SatelliteServiceClient()
{
    statusChangeListener_ = new (std::nothrow) SystemAbilityListener();
    if (statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("Init, failed to create statusChangeListener.");
        return;
    }
    auto managerPtr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (managerPtr == nullptr) {
        TELEPHONY_LOGE("Init, get system ability manager error.");
        return;
    }
    int32_t ret = managerPtr->SubscribeSystemAbility(TELEPHONY_SATELLITE_SERVICE_ABILITY_ID, statusChangeListener_);
    if (ret) {
        TELEPHONY_LOGE("Init, failed to subscribe sa:%{public}d", TELEPHONY_SATELLITE_SERVICE_ABILITY_ID);
        return;
    }
}

SatelliteServiceClient::~SatelliteServiceClient()
{
    RemoveDeathRecipient(nullptr, false);
}

sptr<ISatelliteService> SatelliteServiceClient::GetProxy()
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
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(TELEPHONY_SATELLITE_SERVICE_ABILITY_ID);
    if (obj == nullptr) {
        TELEPHONY_LOGE("Failed to get satellite service");
        return nullptr;
    }
    std::unique_ptr<SatelliteServiceDeathRecipient> recipient = std::make_unique<SatelliteServiceDeathRecipient>(*this);
    if (recipient == nullptr) {
        TELEPHONY_LOGE("recipient is null");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr(recipient.release());
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        TELEPHONY_LOGE("Failed to add death recipient");
        return nullptr;
    }
    proxy_ = iface_cast<ISatelliteService>(obj);
    deathRecipient_ = dr;
    TELEPHONY_LOGD("Succeed to connect satellite service %{public}d", proxy_ == nullptr);
    return proxy_;
}

void SatelliteServiceClient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    RemoveDeathRecipient(remote, true);
}

void SatelliteServiceClient::RemoveDeathRecipient(const wptr<IRemoteObject> &remote, bool isRemoteDied)
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

void SatelliteServiceClient::SystemAbilityListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    TELEPHONY_LOGI("SA:%{public}d is added!", systemAbilityId);
    if (!CheckInputSysAbilityId(systemAbilityId)) {
        TELEPHONY_LOGE("add SA:%{public}d is invalid!", systemAbilityId);
        return;
    }

    std::shared_ptr<SatelliteServiceClient> satelliteClient = DelayedSingleton<SatelliteServiceClient>::GetInstance();
    satelliteClient->ServiceOn();
    TELEPHONY_LOGI("SA:%{public}d reconnect service successfully!", systemAbilityId);
}

void SatelliteServiceClient::SystemAbilityListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    TELEPHONY_LOGI("SA:%{public}d is removed!", systemAbilityId);
    std::shared_ptr<SatelliteServiceClient> satelliteClient = DelayedSingleton<SatelliteServiceClient>::GetInstance();
    satelliteClient->ServiceOff();
}

int32_t SatelliteServiceClient::AddSimHandler(int32_t slotId, const std::shared_ptr<TelEventHandler> &handler)
{
    if (handler == nullptr) {
        TELEPHONY_LOGE("AddSimHandler return, handler is null.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    simHandlerMap_.insert(std::make_pair(slotId, handler));
    TELEPHONY_LOGI("AddSimHandler success: %{public}d", slotId);
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteServiceClient::AddNetworkHandler(int32_t slotId, const std::shared_ptr<TelEventHandler> &handler)
{
    if (handler == nullptr) {
        TELEPHONY_LOGE("AddNetworkHandler return, handler is null.");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    networkHandlerMap_.insert(std::make_pair(slotId, handler));
    TELEPHONY_LOGI("AddNetworkHandler success: %{public}d", slotId);
    return TELEPHONY_SUCCESS;
}

void SatelliteServiceClient::ServiceOn()
{
    for (auto pair : simHandlerMap_) {
        auto handler = static_cast<SimStateHandle *>(pair.second.get());
        if (handler == nullptr) {
            TELEPHONY_LOGE("SimStateHandle is null: %{public}d", pair.first);
            continue;
        }
        handler->RegisterSatelliteCallback();
    }
    for (auto pair : networkHandlerMap_) {
        auto handler = static_cast<NetworkSearchHandler *>(pair.second.get());
        if (handler == nullptr) {
            TELEPHONY_LOGE("NetworkSearchHandler is null: %{public}d", pair.first);
            continue;
        }
        handler->RegisterSatelliteCallback();
    }
}

void SatelliteServiceClient::ServiceOff()
{
    std::lock_guard<std::mutex> lock(mutexProxy_);
    proxy_ = nullptr;

    for (auto pair : simHandlerMap_) {
        auto handler = static_cast<SimStateHandle *>(pair.second.get());
        if (handler == nullptr) {
            TELEPHONY_LOGE("SimStateHandle is null: %{public}d", pair.first);
            continue;
        }
        handler->UnregisterSatelliteCallback();
    }
    for (auto pair : networkHandlerMap_) {
        auto handler = static_cast<NetworkSearchHandler *>(pair.second.get());
        if (handler == nullptr) {
            TELEPHONY_LOGE("NetworkSearchHandler is null: %{public}d", pair.first);
            continue;
        }
        handler->UnregisterSatelliteCallback();
    }
}

int32_t SatelliteServiceClient::RegisterCoreNotify(
    int32_t slotId, int32_t what, const sptr<ISatelliteCoreCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->RegisterCoreNotify(slotId, what, callback);
}

int32_t SatelliteServiceClient::UnRegisterCoreNotify(int32_t slotId, int32_t what)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->UnRegisterCoreNotify(slotId, what);
}

bool SatelliteServiceClient::IsSatelliteEnabled()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return false;
    }
    return proxy->IsSatelliteEnabled();
}

int32_t SatelliteServiceClient::GetSatelliteCapability()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return static_cast<int32_t>(SatelliteCapability::NONE);
    }
    return proxy->GetSatelliteCapability();
}

sptr<IRemoteObject> SatelliteServiceClient::GetProxyObjectPtr(SatelliteServiceProxyType type)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return nullptr;
    }
    return proxy->GetProxyObjectPtr(type);
}

int32_t SatelliteServiceClient::SetRadioState(int32_t slotId, int32_t isRadioOn, int32_t rst)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetRadioState(slotId, isRadioOn, rst);
}

std::string SatelliteServiceClient::GetImei()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return "";
    }
    return proxy->GetImei();
}
} // namespace Telephony
} // namespace OHOS
