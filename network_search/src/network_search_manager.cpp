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
#include "network_search_manager.h"
#include <string_ex.h>
#include "hilog_network_search.h"

namespace OHOS {
NetworkSearchManager::NetworkSearchManager()
{
    HILOG_INFO("NetworkSearchManager");
    state_ = HandleRunningState::STATE_NOT_START;
}

void NetworkSearchManager::Init()
{
    if (state_ == HandleRunningState::STATE_RUNNING) {
        HILOG_INFO("NetworkSearchManager::Init HandleRunningState started.");
        return;
    }
    eventLoop_ = AppExecFwk::EventRunner::Create("NetworkSearchManager");
    if (eventLoop_.get() == nullptr) {
        HILOG_ERROR("NetworkSearchManager failed to create EventRunner");
        return;
    }
    observerHandler_ = std::make_unique<ObserverHandler>();
    if (observerHandler_ == nullptr) {
        HILOG_ERROR("failed to create new ObserverHandler");
        return;
    }
    networkSearchState_ = std::make_shared<NetworkSearchState>(shared_from_this());
    if (networkSearchState_ == nullptr) {
        HILOG_ERROR("failed to create new NetworkSearchState");
        return;
    }

    networkSearchHandler_ = std::make_shared<NetworkSearchHandler>(eventLoop_, shared_from_this());
    if (networkSearchHandler_ == nullptr) {
        HILOG_ERROR("failed to create new NetworkSearchHandler");
        return;
    }

    networkSearchState_->Init();
    networkSearchHandler_->Init();
    DelayedSingleton<NetworkSearchNotify>::GetInstance().get()->ConnectService();

    eventLoop_->Run();
    state_ = HandleRunningState::STATE_RUNNING;
    HILOG_INFO("NetworkSearchManager::Init eventLoop_->Run()");
}

std::shared_ptr<NetworkSearchState> NetworkSearchManager::GetNetworkSearchState() const
{
    return networkSearchState_;
}

void NetworkSearchManager::SetHRilRadioState(bool isOn)
{
    ModemPowerState radioState = PhoneManager ::GetInstance().phone_[1]->rilManager_->GetRadioState();
    HILOG_INFO("NetworkSearchManager GetRadioState result %{public}d", (int32_t)(radioState));

    HILOG_INFO("NetworkSearchManager::SetHRilRadioState %{public}s", isOn ? "true" : "false");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_POWER);
    event->SetOwner(networkSearchHandler_);
    PhoneManager ::GetInstance().phone_[1]->rilManager_->SetModemRadioPower(isOn, event);

    networkSearchHandler_->RadioOffState();
}

ModemPowerState NetworkSearchManager::GetRilHRilRadioState()
{
    HILOG_INFO("NetworkSearchManager::GetRadioState");
    return PhoneManager ::GetInstance().phone_[1]->rilManager_->GetRadioState();
}

void NetworkSearchManager::RegisterForPSConnectionAttached(const HANDLE &handler)
{
    HILOG_INFO("NetworkSearchManager::RegisterForPSConnectionAttached");
    observerHandler_->RegObserver(ObserverHandler::RADIO_PS_CONNECTION_ATTACHED, handler);
    return;
}

void NetworkSearchManager::UnregisterForPSConnectionAttached(const HANDLE &handler)
{
    HILOG_INFO("NetworkSearchManager::UnregisterForPSConnectionAttached ");
    observerHandler_->Remove(ObserverHandler::RADIO_PS_CONNECTION_ATTACHED);
    return;
}

void NetworkSearchManager::RegisterForPSConnectionDetached(const HANDLE &handler)
{
    HILOG_INFO("NetworkSearchManager::RegisterForPSConnectionDetached");
    observerHandler_->RegObserver(ObserverHandler::RADIO_PS_CONNECTION_DETACHED, handler);
    return;
}

void NetworkSearchManager::UnregisterForPSConnectionDetached(const HANDLE &handler)
{
    HILOG_INFO("NetworkSearchManager::UnregisterForPSConnectionDetached");
    observerHandler_->Remove(ObserverHandler::RADIO_PS_CONNECTION_DETACHED);
    return;
}

void NetworkSearchManager::NotifyPSConnectionAttachedChanged()
{
    HILOG_INFO("NetworkSearchManager::NotifyPSConnectionAttachedChanged");
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_PS_CONNECTION_ATTACHED);
    return;
}

void NetworkSearchManager::NotifyPSConnectionDetachedChanged()
{
    HILOG_INFO("NetworkSearchManager::NotifyPSConnectionDetachedChanged");
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_PS_CONNECTION_DETACHED);
    return;
}

int32_t NetworkSearchManager::GetPsRadioTech(int32_t slotId)
{
    auto event = networkSearchState_->GetNetworkStatus()->GetPsRadioTech();

    networkSearchHandler_->GetRilPsRegistration();
    HILOG_INFO("NetworkSearchManager::GetPsRadioTech result=%{public}d", event);
    return event;
}

int32_t NetworkSearchManager::GetCsRadioTech(int32_t slotId)
{
    auto event = networkSearchState_->GetNetworkStatus()->GetCsRadioTech();

    networkSearchHandler_->GetRilCsRegistration();
    HILOG_INFO("NetworkSearchManager::GetPsRadioTech result=%{public}d", event);
    return event;
}

std::u16string NetworkSearchManager::GetOperatorNumeric(int32_t slotId)
{
    HILOG_INFO("NetworkSearchManager::GetOperatorNumeric start");
    networkSearchHandler_->GetOperatorInfo();

    auto event = networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
    std::u16string str = Str8ToStr16(event);

    HILOG_INFO("NetworkSearchManager::GetOperatorNumeric result=%{public}s", event.c_str());
    return str;
}

std::u16string NetworkSearchManager::GetOperatorName(int32_t slotId)
{
    auto event = networkSearchState_->GetNetworkStatus()->GetLongOperatorName();
    std::u16string str = Str8ToStr16(event);

    HILOG_INFO("NetworkSearchManager::GetOperatorName result=%{public}s", event.c_str());
    return str;
}

sptr<NetworkState> NetworkSearchManager::GetNetworkStatus(int32_t slotId)
{
    auto networkState = networkSearchState_->GetNetworkStatus().release();
    return networkState;
}

bool NetworkSearchManager::GetRadioState(int32_t slotId)
{
    ModemPowerState radioState = GetRilHRilRadioState();
    if (radioState == CORE_SERVICE_POWER_ON) {
        HILOG_INFO("NetworkSearchManager::GetRadioState return true");
        return true;
    } else {
        HILOG_INFO("NetworkSearchManager::GetRadioState return false");
        return false;
    }
}

std::vector<sptr<SignalInformation>> NetworkSearchManager::GetSignalInfoList(int32_t slotId)
{
    std::vector<sptr<SignalInformation>> vec;
    networkSearchHandler_->GetSignalInfo(vec);
    return vec;
}
} // namespace OHOS
