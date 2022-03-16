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

#include "network_search_state.h"

#include <securec.h>

#include "network_search_manager.h"
#include "network_search_notify.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkSearchState::NetworkSearchState(
    const std::weak_ptr<NetworkSearchManager> &networkSearchManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), slotId_(slotId)
{}

bool NetworkSearchState::Init()
{
    TELEPHONY_LOGI("NetworkSearchState Init slotId:%{public}d", slotId_);
    networkStateOld_ = std::make_unique<NetworkState>();
    if (networkStateOld_ == nullptr) {
        TELEPHONY_LOGE("failed to create old networkState slotId:%{public}d", slotId_);
        return false;
    }
    networkState_ = std::make_unique<NetworkState>();
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("failed to create new networkState slotId:%{public}d", slotId_);
        return false;
    }
    return true;
}

void NetworkSearchState::SetOperatorInfo(
    const std::string &longName, const std::string &shortName, const std::string &numeric, DomainType domainType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetOperatorInfo(longName, shortName, numeric, domainType);
        TELEPHONY_LOGI(
            "NetworkSearchState::SetOperatorInfo longName : %{public}s, shortName : %{public}s, numeric : "
            "%{public}s, %{public}p slotId:%{public}d",
            networkState_->GetLongOperatorName().c_str(), networkState_->GetShortOperatorName().c_str(),
            networkState_->GetPlmnNumeric().c_str(), networkState_.get(), slotId_);
    }
}

void NetworkSearchState::SetEmergency(bool isEmergency)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetEmergency(isEmergency);
    }
}

bool NetworkSearchState::IsEmergency()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        return networkState_->IsEmergency();
    }
    return false;
}

void NetworkSearchState::SetNetworkType(RadioTech tech, DomainType domainType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetNetworkType(tech, domainType);
    }
}

void NetworkSearchState::SetNetworkState(RegServiceState state, DomainType domainType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetNetworkState(state, domainType);
    }
}

void NetworkSearchState::SetNetworkStateToRoaming(RoamingType roamingType, DomainType domainType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetRoaming(roamingType, domainType);
    }
}

bool NetworkSearchState::GetImsStatus()
{
    std::lock_guard<std::mutex> lock(imsMutex_);
    return imsRegStatus_;
}

void NetworkSearchState::SetImsStatus(bool imsRegStatus)
{
    std::lock_guard<std::mutex> lock(imsMutex_);
    imsRegStatus_ = imsRegStatus;
}

std::unique_ptr<NetworkState> NetworkSearchState::GetNetworkStatus()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MessageParcel data;
    networkState_->Marshalling(data);
    std::unique_ptr<NetworkState> networkState = std::make_unique<NetworkState>();
    if (networkState == nullptr) {
        TELEPHONY_LOGE("failed to create new networkState slotId:%{public}d", slotId_);
        return nullptr;
    }
    networkState->ReadFromParcel(data);
    return networkState;
}

void NetworkSearchState::SetInitial()
{
    TELEPHONY_LOGI("NetworkSearchState::SetInitial slotId:%{public}d", slotId_);
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->Init();
    }
}

void NetworkSearchState::SetCfgTech(RadioTech tech)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetCfgTech(tech);
    }
}

void NetworkSearchState::SetNrState(NrState state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetNrState(state);
    }
}

void NetworkSearchState::NotifyPsRegStatusChange()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NotifyPsRegStatusChange NetworkSearchManager is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("NotifyPsRegStatusChange networkState_ is null slotId:%{public}d", slotId_);
        return;
    }

    if (networkState_->GetPsRegStatus() == RegServiceState::REG_STATE_IN_SERVICE &&
        networkStateOld_->GetPsRegStatus() != RegServiceState::REG_STATE_IN_SERVICE) {
        networkSearchManager->NotifyPsConnectionAttachedChanged(slotId_);
    }
    if (networkState_->GetPsRegStatus() != RegServiceState::REG_STATE_IN_SERVICE &&
        networkStateOld_->GetPsRegStatus() == RegServiceState::REG_STATE_IN_SERVICE) {
        networkSearchManager->NotifyPsConnectionDetachedChanged(slotId_);
    }
}

void NetworkSearchState::NotifyPsRoamingStatusChange()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NotifyPsRoamingStatusChange NetworkSearchManager is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("NotifyPsRoamingStatusChange networkState_ is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkState_->GetPsRoamingStatus() > RoamingType::ROAMING_STATE_UNKNOWN &&
        networkStateOld_->GetPsRoamingStatus() == RoamingType::ROAMING_STATE_UNKNOWN) {
        networkSearchManager->NotifyPsRoamingOpenChanged(slotId_);
    }
    if (networkStateOld_->GetPsRoamingStatus() > RoamingType::ROAMING_STATE_UNKNOWN &&
        networkState_->GetPsRoamingStatus() == RoamingType::ROAMING_STATE_UNKNOWN) {
        networkSearchManager->NotifyPsRoamingCloseChanged(slotId_);
    }
}

void NetworkSearchState::NotifyPsRadioTechChange()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NotifyPsRadioTechChange NetworkSearchManager is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("NotifyPsRadioTechChange networkState_ is null slotId:%{public}d", slotId_);
        return;
    }

    if (networkState_->GetPsRadioTech() != networkStateOld_->GetPsRadioTech()) {
        networkSearchManager->SendUpdateCellLocationRequest(slotId_);
        networkSearchManager->NotifyPsRatChanged(slotId_);
    }
}

void NetworkSearchState::NotifyEmergencyChange()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NotifyEmergencyChange NetworkSearchManager is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("NotifyEmergencyChange networkState_ is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkState_->IsEmergency() != networkStateOld_->IsEmergency()) {
        if (networkState_->IsEmergency()) {
            networkSearchManager->NotifyEmergencyOpenChanged(slotId_);
        } else {
            networkSearchManager->NotifyEmergencyCloseChanged(slotId_);
        }
    }
}

void NetworkSearchState::NotifyNrStateChange()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NotifyPsRadioTechChange NetworkSearchManager is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("NotifyPsRadioTechChange networkState_ is null slotId:%{public}d", slotId_);
        return;
    }

    if (networkState_->GetNrState() != networkStateOld_->GetNrState()) {
        networkSearchManager->NotifyNrStateChanged(slotId_);
    }
}

void NetworkSearchState::NotifyStateChange()
{
    TELEPHONY_LOGI("NetworkSearchState::NotifyStateChange slotId:%{public}d", slotId_);
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("NotifyStateChange networkState_ is null slotId:%{public}d", slotId_);
        return;
    }

    NotifyPsRegStatusChange();
    NotifyPsRoamingStatusChange();
    NotifyPsRadioTechChange();
    NotifyEmergencyChange();
    NotifyNrStateChange();
    CsRadioTechChange();

    if (!(*networkState_ == *networkStateOld_)) {
        TELEPHONY_LOGI(
            "NetworkSearchState::StateCheck isNetworkStateChange notify to app... slotId:%{public}d", slotId_);
        sptr<NetworkState> ns = new NetworkState;
        if (ns == nullptr) {
            TELEPHONY_LOGE("failed to create networkState slotId:%{public}d", slotId_);
            return;
        }

        MessageParcel data;
        networkState_->Marshalling(data);
        ns->ReadFromParcel(data);
        DelayedSingleton<NetworkSearchNotify>::GetInstance()->NotifyNetworkStateUpdated(slotId_, ns);
        networkState_->Marshalling(data);
        networkStateOld_->ReadFromParcel(data);
        delete ns;
    }
}

void NetworkSearchState::CsRadioTechChange()
{
    TELEPHONY_LOGI("NetworkSearchState::CsRadioTechChange slotId:%{public}d", slotId_);
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("CsRadioTechChange NetworkSearchManager is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("CsRadioTechChange networkState is null slotId:%{public}d", slotId_);
        return;
    }
    if (networkStateOld_ == nullptr) {
        TELEPHONY_LOGE("CsRadioTechChange networkStateOld_ is null slotId:%{public}d", slotId_);
        return;
    }

    if (networkState_->GetCsRadioTech() != networkStateOld_->GetCsRadioTech()) {
        networkSearchManager->UpdatePhone(slotId_, networkState_->GetCsRadioTech());
    }
}
} // namespace Telephony
} // namespace OHOS
