/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "esim_service_client.h"

#include "esim_service_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t TELEPHONY_ESIM_SERVICE_SYS_ABILITY_ID = 66250;
constexpr int32_t WAIT_REMOTE_TIME_SEC = 4;
std::mutex g_loadMutex;
std::condition_variable g_cv;
void EsimServiceClientCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    TELEPHONY_LOGI("Loading system ability succeeded");
    std::unique_lock<std::mutex> lock(g_loadMutex);
    remoteObject_ = remoteObject;
    g_cv.notify_one();
}

void EsimServiceClientCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    TELEPHONY_LOGE("Loading system ability failed");
    isLoadSAFailed_ = true;
}

bool EsimServiceClientCallback::IsFailed()
{
    return isLoadSAFailed_;
}

const sptr<IRemoteObject> &EsimServiceClientCallback::GetRemoteObject() const
{
    return remoteObject_;
}

EsimServiceClient::EsimServiceClient() = default;

EsimServiceClient::~EsimServiceClient()
{
    RemoveDeathRecipient(nullptr, false);
}

sptr<IEsimService> EsimServiceClient::GetProxy()
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

    sptr<EsimServiceClientCallback> callback = new (std::nothrow) EsimServiceClientCallback();
    if (callback == nullptr) {
        return nullptr;
    }
    int32_t result = sam->LoadSystemAbility(TELEPHONY_ESIM_SERVICE_SYS_ABILITY_ID, callback);
    if (result != ERR_OK) {
        TELEPHONY_LOGE("LoadSystemAbility failed : %{public}d", result);
        return nullptr;
    }
    {
        std::unique_lock<std::mutex> uniqueLock(g_loadMutex);
        g_cv.wait_for(uniqueLock, std::chrono::seconds(WAIT_REMOTE_TIME_SEC),
            [&callback]() { return callback->GetRemoteObject() != nullptr || callback->IsFailed(); });
    }

    TELEPHONY_LOGI("SystemAbilityManagerClient LoadSystemAbility.");

    auto remote = callback->GetRemoteObject();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Failed to get service");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) EsimServiceDeathRecipient(*this);
    if (deathRecipient_ == nullptr) {
        TELEPHONY_LOGE("recipient is null");
        return nullptr;
    }
    if ((remote->IsProxyObject()) && (!remote->AddDeathRecipient(deathRecipient_))) {
        TELEPHONY_LOGE("Failed to add death recipient");
        return nullptr;
    }
    proxy_ = iface_cast<IEsimService>(remote);
    if (proxy_ == nullptr) {
        TELEPHONY_LOGE("Get remote service proxy failed");
        return nullptr;
    }
    TELEPHONY_LOGD("Succeed to connect esim service");
    return proxy_;
}

void EsimServiceClient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    RemoveDeathRecipient(remote, true);
}

void EsimServiceClient::RemoveDeathRecipient(const wptr<IRemoteObject> &remote, bool isRemoteDied)
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

int32_t EsimServiceClient::GetEid(int32_t slotId, std::string &eId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetEid(slotId, eId);
}

int32_t EsimServiceClient::GetOsuStatus(int32_t slotId, int32_t &osuStatus)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetOsuStatus(slotId, osuStatus);
}

int32_t EsimServiceClient::StartOsu(int32_t slotId, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->StartOsu(slotId, callback);
}

int32_t EsimServiceClient::GetDownloadableProfileMetadata(
    int32_t slotId, int32_t portIndex, const DownloadableProfile &profile,
    bool forceDisableProfile, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetDownloadableProfileMetadata(
        slotId, portIndex, profile, forceDisableProfile, callback);
}

int32_t EsimServiceClient::GetDownloadableProfiles(
    int32_t slotId, int32_t portIndex, bool forceDisableProfile, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetDownloadableProfiles(slotId, portIndex, forceDisableProfile, callback);
}

int32_t EsimServiceClient::DownloadProfile(int32_t slotId, DownloadProfileConfigInfo configInfo,
    const DownloadableProfile &profile, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->DownloadProfile(slotId, configInfo, profile, callback);
}

int32_t EsimServiceClient::GetEuiccProfileInfoList(int32_t slotId, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetEuiccProfileInfoList(slotId, callback);
}

int32_t EsimServiceClient::GetEuiccInfo(int32_t slotId, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetEuiccInfo(slotId, callback);
}

int32_t EsimServiceClient::DeleteProfile(
    int32_t slotId, const std::string &iccId, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->DeleteProfile(slotId, iccId, callback);
}

int32_t EsimServiceClient::SwitchToProfile(int32_t slotId, int32_t portIndex,
    const std::string &iccId, bool forceDisableProfile, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, callback);
}

int32_t EsimServiceClient::SetProfileNickname(int32_t slotId, const std::string &iccId,
    const std::string &nickname, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetProfileNickname(slotId, iccId, nickname, callback);
}

int32_t EsimServiceClient::ResetMemory(int32_t slotId, int32_t resetOption, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->ResetMemory(slotId, resetOption, callback);
}

int32_t EsimServiceClient::ReserveProfilesForFactoryRestore(int32_t slotId, int32_t &restoreResult)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->ReserveProfilesForFactoryRestore(slotId, restoreResult);
}

int32_t EsimServiceClient::SetDefaultSmdpAddress(
    int32_t slotId, const std::string &defaultSmdpAddress, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, callback);
}

int32_t EsimServiceClient::GetDefaultSmdpAddress(int32_t slotId, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->GetDefaultSmdpAddress(slotId, callback);
}

int32_t EsimServiceClient::CancelSession(
    int32_t slotId, const std::string &transactionId, int32_t cancelReason, const sptr<IEsimServiceCallback> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->CancelSession(slotId, transactionId, cancelReason, callback);
}

int32_t EsimServiceClient::IsSupported(int32_t slotId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->IsSupported(slotId);
}

int32_t EsimServiceClient::AddProfile(int32_t slotId, DownloadableProfile profile)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        TELEPHONY_LOGE("proxy is null!");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return proxy->AddProfile(slotId, profile);
}
} // namespace Telephony
} // namespace OHOS
