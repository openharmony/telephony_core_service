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

#include "network_search_service_proxy_holder.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "network_search_service_death_recipient.h"
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"
#include "telephony_napi_common_error.h"

namespace OHOS {
namespace Telephony {
bool NetworkSearchServiceProxyHolder::GetNetworkSearchProxy()
{
    TELEPHONY_LOGI("start");
    if (!radioNetworkService_) {
        std::lock_guard<std::mutex> lock(mutex_);
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (!systemAbilityManager) {
            TELEPHONY_LOGE(" Get system ability mgr failed.");
            return false;
        }
        sptr<IRemoteObject> remoteObject =
            systemAbilityManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
        if (!remoteObject) {
            TELEPHONY_LOGE("Get Telephony Core Service Failed.");
            return false;
        }
        radioNetworkService_ = iface_cast<ICoreService>(remoteObject);
        if ((!radioNetworkService_) || (!radioNetworkService_->AsObject())) {
            TELEPHONY_LOGE("Get Telephony Core Proxy Failed.");
            return false;
        }
        recipient_ = new NetworkSearchServiceDeathRecipient();
        if (!recipient_) {
            TELEPHONY_LOGE("Failed to create death Recipient ptr NetworkSearchServiceDeathRecipient!");
            return false;
        }
        radioNetworkService_->AsObject()->AddDeathRecipient(recipient_);
    }
    return true;
}

void NetworkSearchServiceProxyHolder::ResetNetworkServiceServiceProxy()
{
    TELEPHONY_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    if ((radioNetworkService_ != nullptr) && (radioNetworkService_->AsObject() != nullptr)) {
        radioNetworkService_->AsObject()->RemoveDeathRecipient(recipient_);
    }
    radioNetworkService_ = nullptr;
}

int32_t NetworkSearchServiceProxyHolder::GetPsRadioTech(int32_t slotId)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetPsRadioTech(slotId);
    }
    return ERROR_SERVICE_UNAVAILABLE;
}

int32_t NetworkSearchServiceProxyHolder::GetCsRadioTech(int32_t slotId)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetCsRadioTech(slotId);
    }
    return ERROR_SERVICE_UNAVAILABLE;
}

std::vector<sptr<SignalInformation>> NetworkSearchServiceProxyHolder::GetSignalInfoList(int32_t slotId)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetSignalInfoList(slotId);
    }
    return std::vector<sptr<SignalInformation>>();
}

std::u16string NetworkSearchServiceProxyHolder::GetOperatorNumeric(int32_t slotId)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetOperatorNumeric(slotId);
    }
    return u"";
}

std::u16string NetworkSearchServiceProxyHolder::GetOperatorName(int32_t slotId)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetOperatorName(slotId);
    }
    return u"";
}

sptr<NetworkState> NetworkSearchServiceProxyHolder::GetNetworkState(int32_t slotId)
{
    if (GetNetworkSearchProxy()) {
        return sptr<NetworkState>(radioNetworkService_->GetNetworkState(slotId));
    }
    return nullptr;
}

bool NetworkSearchServiceProxyHolder::GetNetworkSelectionMode(
    int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetNetworkSelectionMode(slotId, callback);
    }
    return false;
}

bool NetworkSearchServiceProxyHolder::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->SetNetworkSelectionMode(
            slotId, selectMode, networkInformation, resumeSelection, callback);
    }
    return false;
}

bool NetworkSearchServiceProxyHolder::SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->SetRadioState(isOn, callback);
    }
    return false;
}

bool NetworkSearchServiceProxyHolder::GetRadioState(const sptr<INetworkSearchCallback> &callback)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetRadioState(callback);
    }
    return false;
}

bool NetworkSearchServiceProxyHolder::GetNetworkSearchResult(
    int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetNetworkSearchResult(slotId, callback);
    }
    return false;
}

std::u16string NetworkSearchServiceProxyHolder::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    if (GetNetworkSearchProxy()) {
        return radioNetworkService_->GetIsoCountryCodeForNetwork(slotId);
    }
    return u"";
}
} // namespace Telephony
} // namespace OHOS
