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
NetworkSearchState::NetworkSearchState(const std::weak_ptr<NetworkSearchManager> &networkSearchManager)
    : networkSearchManager_(networkSearchManager)
{}

void NetworkSearchState::Init()
{
    TELEPHONY_LOGI("NetworkSearchState Init");
    networkStateOld_ = std::make_shared<NetworkState>();
    if (networkStateOld_ == nullptr) {
        TELEPHONY_LOGE("failed to create old networkState");
        return;
    }
    networkState_ = std::make_shared<NetworkState>();
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("failed to create new networkState");
        return;
    }
}

void NetworkSearchState::SetOperatorInfo(
    const std::string &longName, const std::string &shortName, const std::string &numeric, DomainType domainType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetOperatorInfo(longName, shortName, numeric, domainType);
        TELEPHONY_LOGI(
            "NetworkSearchState::SetOperatorInfo longName : %{public}s, shortName : %{public}s, numeric : "
            "%{public}s, %{public}p\n",
            networkState_->GetLongOperatorName().c_str(), networkState_->GetShortOperatorName().c_str(),
            networkState_->GetPlmnNumeric().c_str(), networkState_.get());
    }
}

void NetworkSearchState::SetEmergency(bool isEmergency)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->SetEmergency(isEmergency);
    }
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

bool NetworkSearchState::GsmOrNot(RadioTech radioTechnology) const
{
    return (radioTechnology == RadioTech::RADIO_TECHNOLOGY_GSM) ||
        (radioTechnology == RadioTech::RADIO_TECHNOLOGY_LTE) ||
        (radioTechnology == RadioTech::RADIO_TECHNOLOGY_WCDMA);
}

bool NetworkSearchState::CdmaOrNot(RadioTech radioTechnology) const
{
    return false;
}

std::unique_ptr<NetworkState> NetworkSearchState::GetNetworkStatus()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MessageParcel data;
    networkState_->Marshalling(data);
    std::unique_ptr<NetworkState> networkState = std::make_unique<NetworkState>();
    if (networkState == nullptr) {
        TELEPHONY_LOGE("failed to create new networkState");
        return nullptr;
    }
    networkState->ReadFromParcel(data);
    return networkState;
}

void NetworkSearchState::SetInitial()
{
    TELEPHONY_LOGI("NetworkSearchState::SetInitial");
    std::lock_guard<std::mutex> lock(mutex_);
    if (networkState_ != nullptr) {
        networkState_->Init();
    }
}

void NetworkSearchState::NotifyStateChange()
{
    TELEPHONY_LOGI("NetworkSearchState::StateCheck");
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NotifyStateChange NetworkSearchManager is null");
        return;
    }
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("NotifyStateChange networkState_ is null");
        return;
    }

    if (networkState_->GetPsRegStatus() == RegServiceState::REG_STATE_IN_SERVICE &&
        networkStateOld_->GetPsRegStatus() != RegServiceState::REG_STATE_IN_SERVICE) {
        TELEPHONY_LOGI("NetworkSearchState::StateCheck isPSNetworkChange notify to dc...");
        networkSearchManager->NotifyPsConnectionAttachedChanged();
    }
    if (networkState_->GetPsRegStatus() != RegServiceState::REG_STATE_IN_SERVICE &&
        networkStateOld_->GetPsRegStatus() == RegServiceState::REG_STATE_IN_SERVICE) {
        TELEPHONY_LOGI("NetworkSearchState::StateCheck isPSNetworkAttached notify to dc...");
        networkSearchManager->NotifyPsConnectionDetachedChanged();
    }
    if (networkState_->GetPsRoamingStatus() > RoamingType::ROAMING_STATE_UNKNOWN &&
        networkStateOld_->GetPsRoamingStatus() == RoamingType::ROAMING_STATE_UNKNOWN) {
        TELEPHONY_LOGI("NetworkSearchState::StateCheck PSRoamingOpen notify to dc...");
        networkSearchManager->NotifyPsRoamingOpenChanged();
    }
    if (networkStateOld_->GetPsRoamingStatus() > RoamingType::ROAMING_STATE_UNKNOWN &&
        networkState_->GetPsRoamingStatus() == RoamingType::ROAMING_STATE_UNKNOWN) {
        TELEPHONY_LOGI("NetworkSearchState::StateCheck PSRoamingClose notify to dc...");
        networkSearchManager->NotifyPsRoamingCloseChanged();
    }
    if (networkState_->GetPsRadioTech() != networkStateOld_->GetPsRadioTech()) {
        networkSearchManager->SendUpdateCellLocationRequest();
        networkSearchManager->NotifyPsRatChanged();
    }
    if (!(*networkState_ == *networkStateOld_)) {
        TELEPHONY_LOGI("NetworkSearchState::StateCheck isNetworkStateChange notify to app...");
        sptr<NetworkState> ns = new NetworkState;
        if (ns == nullptr) {
            TELEPHONY_LOGE("failed to create networkState");
            return;
        }

        MessageParcel data;
        networkState_->Marshalling(data);
        ns->ReadFromParcel(data);
        DelayedSingleton<NetworkSearchNotify>::GetInstance()->NotifyNetworkStateUpdated(ns);
        networkState_->Marshalling(data);
        networkStateOld_->ReadFromParcel(data);
    }
}

void NetworkSearchState::CsRadioTechChange()
{
    TELEPHONY_LOGI("NetworkSearchState::CsRadioTechChange");
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("CsRadioTechChange NetworkSearchManager is null");
        return;
    }
    if (networkState_ == nullptr) {
        TELEPHONY_LOGE("CsRadioTechChange networkState is null");
        return;
    }
    if (networkStateOld_ == nullptr) {
        TELEPHONY_LOGE("CsRadioTechChange networkStateOld_ is null");
        return;
    }

    if (networkState_->GetCsRadioTech() != networkStateOld_->GetCsRadioTech()) {
        networkSearchManager->UpdatePhone(networkState_->GetCsRadioTech());
    }
}
} // namespace Telephony
} // namespace OHOS
