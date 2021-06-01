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
#include "hilog_network_search.h"
#include "network_search_manager.h"
#include "network_search_notify.h"

namespace OHOS {
NetworkSearchState::NetworkSearchState(const std::weak_ptr<NetworkSearchManager> &networkSearchManager)
    : networkSearchManager_(networkSearchManager)
{}

void NetworkSearchState::Init()
{
    HILOG_INFO("NetworkSearchState Init");
    networkStateOld_ = std::make_shared<NetworkState>();
    if (networkStateOld_ == nullptr) {
        HILOG_ERROR("failed to create new networkState");
        return;
    }
    networkState_ = std::make_shared<NetworkState>();
    if (networkState_ == nullptr) {
        HILOG_ERROR("failed to create new networkState");
        return;
    }
}

void NetworkSearchState::SetOperatorInfo(const std::string &longName, const std::string &shortName,
    const std::string &numeric, const DomainType domainType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkState_->SetOperatorInfo(longName, shortName, numeric, domainType);
}

void NetworkSearchState::SetEmergency(bool isEmergency)
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkState_->SetEmergency(isEmergency);
}

void NetworkSearchState::SetNetworkType(RadioTech tech, DomainType domainType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkState_->SetNetworkType(tech, domainType);
}

void NetworkSearchState::SetNetworkState(RegServiceState state, DomainType domainType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkState_->SetNetworkState(state, domainType);
}

bool NetworkSearchState::GetIMSState()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return iMSRegStatus_;
}

bool NetworkSearchState::GsmOrNot(int radioTechnology)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return radioTechnology == RADIO_TECHNOLOGY_GSM;
}

bool NetworkSearchState::CdmaOrNot(int radioTechnology)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return radioTechnology == RADIO_TECHNOLOGY_1XRTT || radioTechnology == RADIO_TECHNOLOGY_WCDMA;
}

std::unique_ptr<NetworkState> NetworkSearchState::GetNetworkStatus()
{
    std::unique_ptr<NetworkState> networkState = std::make_unique<NetworkState>();
    if (networkState == nullptr) {
        HILOG_ERROR("failed to create new networkState");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (memcpy_s(static_cast<void *>(networkState.get()), sizeof(NetworkState),
        static_cast<const void *>(networkState_.get()), sizeof(NetworkState)) != 0) {
        HILOG_ERROR("fail to copy memory");
        return nullptr;
    }
    return networkState;
}

void NetworkSearchState::SetInitial()
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkState_->Init();
}

void NetworkSearchState::NotifyStateChange()
{
    HILOG_INFO("NetworkSearchManager::StateCheck");
    std::lock_guard<std::mutex> lock(mutex_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        HILOG_ERROR("RadioOffState NetworkSearchHandler is null");
        return;
    }

    if (networkState_->GetPsRegStatus() == REG_STATE_IN_SERVICE &&
        networkStateOld_->GetPsRegStatus() != REG_STATE_IN_SERVICE) {
        HILOG_INFO("NetworkSearchManager::StateCheck isPSNetworkChange notify to dc...");
        networkSearchManager->NotifyPSConnectionAttachedChanged();
    }

    if (networkState_->GetPsRegStatus() != REG_STATE_IN_SERVICE &&
        networkStateOld_->GetPsRegStatus() == REG_STATE_IN_SERVICE) {
        HILOG_INFO("NetworkSearchManager::StateCheck isPSNetworkAttached notify to dc...");
        networkSearchManager->NotifyPSConnectionDetachedChanged();
    }

    if (!(*networkState_ == *networkStateOld_)) {
        HILOG_INFO("NetworkSearchManager::StateCheck isNetworkStateChange notify to app...");
        std::unique_ptr<NetworkState> ns = std::make_unique<NetworkState>();
        if (memcpy_s(ns.get(), sizeof(NetworkState), networkState_.get(), sizeof(NetworkState)) != 0) {
            HILOG_ERROR("fail to copy memory state");
            return;
        }
        DelayedSingleton<NetworkSearchNotify>::GetInstance()->NotifyNetworkStateUpdated(ns.release());
        if (memcpy_s(networkStateOld_.get(), sizeof(NetworkState), networkState_.get(), sizeof(NetworkState)) != 0) {
            HILOG_ERROR("fail to copy memory state");
        }
    }
}
} // namespace OHOS
