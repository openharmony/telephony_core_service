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

#include "network_search_handler.h"
#include "core_manager.h"
#include "network_search_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkSearchHandler::NetworkSearchHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::weak_ptr<NetworkSearchManager> &networkSearchManager)
    : AppExecFwk::EventHandler(runner), networkSearchManager_(networkSearchManager)
{
    memberFuncMap_[ObserverHandler::RADIO_SIM_STATE_CHANGE] = &NetworkSearchHandler::SimStateChange;
    memberFuncMap_[ObserverHandler::RADIO_IMSI_LOADED_READY] = &NetworkSearchHandler::ImsiLoadedReady;
    memberFuncMap_[ObserverHandler::RADIO_SIM_RECORDS_LOADED] = &NetworkSearchHandler::SimRecordsLoaded;
    memberFuncMap_[ObserverHandler::RADIO_STATE_CHANGED] = &NetworkSearchHandler::RadioStateChange;
    memberFuncMap_[ObserverHandler::RADIO_NETWORK_STATE] = &NetworkSearchHandler::GetNetworkStateInfo;
    memberFuncMap_[ObserverHandler::RADIO_RESTRICTED_STATE] = &NetworkSearchHandler::RadioRestrictedState;
    memberFuncMap_[ObserverHandler::RADIO_DATA_REG_STATE] = &NetworkSearchHandler::RadioRilDataRegState;
    memberFuncMap_[ObserverHandler::RADIO_VOICE_REG_STATE] = &NetworkSearchHandler::RadioRilVoiceRegState;
    memberFuncMap_[ObserverHandler::RADIO_GET_SIGNAL_STRENGTH] = &NetworkSearchHandler::RadioSignalStrength;
    memberFuncMap_[ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE] = &NetworkSearchHandler::RadioSignalStrength;
    memberFuncMap_[ObserverHandler::RADIO_OPERATOR] = &NetworkSearchHandler::RadioRilOperator;
    memberFuncMap_[ObserverHandler::RADIO_NETWORK_SEARCH_RESULT] = &NetworkSearchHandler::NetworkSearchResult;
    memberFuncMap_[ObserverHandler::RADIO_GET_NETWORK_SELECTION_MODE] =
        &NetworkSearchHandler::GetNetworkSelectionModeResponse;
    memberFuncMap_[ObserverHandler::RADIO_SET_NETWORK_SELECTION_MODE] =
        &NetworkSearchHandler::SetNetworkSelectionModeResponse;
    memberFuncMap_[ObserverHandler::RADIO_GET_STATUS] = &NetworkSearchHandler::GetRadioStatusResponse;
    memberFuncMap_[ObserverHandler::RADIO_SET_STATUS] = &NetworkSearchHandler::SetRadioStatusResponse;
}

NetworkSearchHandler::~NetworkSearchHandler()
{
    UnregisterEvents();
}

void NetworkSearchHandler::Init()
{
    TELEPHONY_LOGI("NetworkSearchHandler::Init start");
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager");
        return;
    }

    simStateManager_ = nsm->GetSimStateManager();
    simFileManager_ = nsm->GetSimFileManager();
    rilManager_ = nsm->GetRilManager();

    networkRegister_ = std::make_unique<NetworkRegister>(nsm->GetNetworkSearchState());
    if (networkRegister_ == nullptr) {
        TELEPHONY_LOGE("failed to get networkRegister");
        return;
    }
    operatorName_ = std::make_unique<OperatorName>(nsm->GetNetworkSearchState(), nsm->GetSimFileManager());
    if (operatorName_ == nullptr) {
        TELEPHONY_LOGE("failed to get operatorName");
        return;
    }
    radioInfo_ = std::make_unique<RadioInfo>(nsm);
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to get radioInfo");
        return;
    }
    signalInfo_ = std::make_unique<SignalInfo>();
    if (signalInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to get signalInfo");
        return;
    }
    networkSelection_ = std::make_unique<NetworkSelection>(nsm);
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("failed to get networkSelection");
        return;
    }
    signalInfo_->InitSignalBar();
    RegisterEvents();
}

void NetworkSearchHandler::RegisterEvents()
{
    TELEPHONY_LOGI("NetworkSearchHandler::RegisterEvents start");
    // Register SIM
    if (simStateManager_ != nullptr) {
        simStateManager_->RegisterIccStateChanged(shared_from_this());
    }

    if (simFileManager_ != nullptr) {
        simFileManager_->RegisterImsiLoaded(shared_from_this());
        simFileManager_->RegisterAllFilesLoaded(shared_from_this());
    }

    // unsol RIL
    if (rilManager_ != nullptr) {
        rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_STATE_CHANGED, nullptr);
        rilManager_->RegisterPhoneNotify(
            shared_from_this(), ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE, nullptr);
        rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_NETWORK_STATE, nullptr);
    }
}

void NetworkSearchHandler::UnregisterEvents()
{
    if (simStateManager_ != nullptr) {
        simStateManager_->UnregisterIccStateChanged(shared_from_this());
    }

    if (simFileManager_ != nullptr) {
        simFileManager_->UnregisterImsiLoaded(shared_from_this());
        simFileManager_->UnregisterAllFilesLoaded(shared_from_this());
    }

    // unsol
    if (rilManager_ != nullptr) {
        rilManager_->UnRegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_STATE_CHANGED);
        rilManager_->UnRegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE);
        rilManager_->UnRegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_NETWORK_STATE);
    }
}

void NetworkSearchHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        return;
    }
    auto msgType = event->GetInnerEventId();
    TELEPHONY_LOGI("NetworkSearchHandler::ProcessEvent received event msgType:%{public}d", msgType);
    auto itFunc = memberFuncMap_.find(msgType);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(event);
        }
    }
}

void NetworkSearchHandler::SimStateChange(const AppExecFwk::InnerEvent::Pointer &)
{
    if (simFileManager_ != nullptr) {
        simFileManager_->RegisterImsiLoaded(shared_from_this());
        simFileManager_->RegisterAllFilesLoaded(shared_from_this());
    }
}

void NetworkSearchHandler::ImsiLoadedReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    GetRilSignalIntensity();
    GetNetworkStateInfo(event);
}

void NetworkSearchHandler::SimRecordsLoaded(const AppExecFwk::InnerEvent::Pointer &)
{
    if (operatorName_ != nullptr) {
        operatorName_->NotifySpnChanged();
    }
}

void NetworkSearchHandler::RadioStateChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<int> object = event->GetSharedObject<int>();
    if (object == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioStateChange object is nullptr!");
        return;
    }
    int32_t radioState = *object;
    TELEPHONY_LOGI("NetworkSearchHandler::RadioState change: %{public}d", radioState);
    switch (radioState) {
        case CORE_SERVICE_POWER_OFF:
            RadioOffState();
            break;
        case CORE_SERVICE_POWER_ON:
            RadioOnState();
            break;
        default:
            TELEPHONY_LOGI("Unhandled message with number: %{public}d", radioState);
            break;
    }

    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioStateChange failed to get NetworkSearchManager");
        return;
    }
    if (radioState == CORE_SERVICE_POWER_ON || radioState == CORE_SERVICE_POWER_OFF) {
        networkSearchManager->SetRadioStatusValue((ModemPowerState)radioState);
    } else {
        networkSearchManager->SetRadioStatusValue(CORE_SERVICE_POWER_NOT_AVAILABLE);
    }
}

void NetworkSearchHandler::RadioRestrictedState(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessRestrictedState(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioRestrictedState");
}

void NetworkSearchHandler::RadioRilDataRegState(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessPsRegister(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioRilDataRegState");
}

void NetworkSearchHandler::RadioRilVoiceRegState(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessCsRegister(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioRilVoiceRegState");
}

void NetworkSearchHandler::RadioSignalStrength(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (signalInfo_ != nullptr) {
        signalInfo_->ProcessSignalIntensity(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioSignalStrength");
}

void NetworkSearchHandler::RadioRilOperator(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (operatorName_ != nullptr) {
        operatorName_->HandleOperatorInfo(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioRilOperator");
}

void NetworkSearchHandler::GetRilSignalIntensity()
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetRilSignalIntensity start......");
    if (!TimeOutCheck(lastTimeSignalReq_)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SIGNAL_STRENGTH);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        if (rilManager_ != nullptr) {
            rilManager_->GetSignalStrength(event);
        }
    }
}

void NetworkSearchHandler::GetNetworkStateInfo(const AppExecFwk::InnerEvent::Pointer &)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager RadioState");
        return;
    }
    ModemPowerState radioState = networkSearchManager->GetRadioStatusValue();
    TELEPHONY_LOGI("NetworkSearchHandler GetRadioState : %{public}d", radioState);
    switch (radioState) {
        case CORE_SERVICE_POWER_OFF:
            RadioOffState();
            break;
        case CORE_SERVICE_POWER_ON:
            RadioOnState();
            break;
        default:
            TELEPHONY_LOGI("Unhandled message with number: %{public}d", radioState);
            break;
    }
}

void NetworkSearchHandler::RadioOffState() const
{
    TELEPHONY_LOGI("RadioOffState enter...");

    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("RadioOffState NetworkSearchHandler is null");
        return;
    }
    std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState();
    if (networkSearchState == nullptr) {
        TELEPHONY_LOGE("networkSearchState is null");
        return;
    }

    networkSearchState->SetInitial();
    if (signalInfo_ != nullptr) {
        signalInfo_->Reset();
    }
    networkSearchState->NotifyStateChange();
}

void NetworkSearchHandler::RadioOnState()
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        if (rilManager_ != nullptr) {
            rilManager_->GetOperatorInfo(event);
        }
    }
    event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DATA_REG_STATE);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        if (rilManager_ != nullptr) {
            rilManager_->GetPsRegStatus(event);
        }
    }
    event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_VOICE_REG_STATE);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        if (rilManager_ != nullptr) {
            rilManager_->GetCsRegStatus(event);
        }
    }
    event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SIGNAL_STRENGTH);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        if (rilManager_ != nullptr) {
            rilManager_->GetSignalStrength(event);
        }
    }
    InitGetNetworkSelectionMode();
}

void NetworkSearchHandler::GetRadioStatusResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo is null");
        return;
    }
    radioInfo_->ProcessGetRadioStatus(event);
}

void NetworkSearchHandler::SetRadioStatusResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo is null");
        return;
    }
    radioInfo_->ProcessSetRadioStatus(event);
}

void NetworkSearchHandler::GetRilOperatorInfo()
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetOperatorInfo start");
    if (!TimeOutCheck(lastTimeOperatorReq_)) {
        return;
    }
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        if (rilManager_ != nullptr) {
            rilManager_->GetOperatorInfo(event);
        }
    }
}

void NetworkSearchHandler::GetRilPsRegistration()
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetPsRegStatus start");
    if (!TimeOutCheck(lastTimePsRegistrationReq_)) {
        return;
    }
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DATA_REG_STATE);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        if (rilManager_ != nullptr) {
            rilManager_->GetPsRegStatus(event);
        }
    }
}

void NetworkSearchHandler::InitGetNetworkSelectionMode()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("InitGetNetworkSelectionMode networkSearchManager is null");
        return;
    }
    networkSearchManager->GetNetworkSelectionMode(CoreManager::DEFAULT_SLOT_ID);
}

void NetworkSearchHandler::GetRilCsRegistration()
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetCsRegStatus start");
    if (!TimeOutCheck(lastTimeCsRegistrationReq_)) {
        return;
    }
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_VOICE_REG_STATE);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        if (rilManager_ != nullptr) {
            rilManager_->GetCsRegStatus(event);
        }
    }
}

void NetworkSearchHandler::NetworkSearchResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchResult NetworkSelection is null");
        return;
    }
    networkSelection_->ProcessNetworkSearchResult(event);
}

void NetworkSearchHandler::SetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("SetNetworkSelectionModeResponse NetworkSelection is null");
        return;
    }
    networkSelection_->ProcessSetNetworkSelectionMode(event);
}

void NetworkSearchHandler::GetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("GetNetworkSelectionModeResponse NetworkSelection is null");
        return;
    }
    networkSelection_->ProcessGetNetworkSelectionMode(event);
}

void NetworkSearchHandler::GetSignalInfo(std::vector<sptr<SignalInformation>> &signals)
{
    GetRilSignalIntensity();
    if (signalInfo_ != nullptr) {
        signalInfo_->GetSignalInfoList(signals);
    }
}

bool NetworkSearchHandler::TimeOutCheck(int64_t &lastTime)
{
    int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if ((now - lastTime) > REQ_INTERVAL) {
        lastTime = now;
        return true;
    }
    return false;
}
} // namespace Telephony
} // namespace OHOS
