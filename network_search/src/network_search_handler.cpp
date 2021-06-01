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
#include "hilog_network_search.h"
#include "network_search_manager.h"

namespace OHOS {
NetworkSearchHandler::NetworkSearchHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::weak_ptr<NetworkSearchManager> &networkSearchManager)
    : AppExecFwk::EventHandler(runner), networkSearchManager_(networkSearchManager)
{
    flagAutoQuerySignalIntensity_ = false;
    rilManager_ = nullptr;
    memberFuncMap_[ObserverHandler::RADIO_SIM_STATE_CHANGE] = &NetworkSearchHandler::SimStateChange;
    memberFuncMap_[ObserverHandler::RADIO_IMSI_LOADED_READY] = &NetworkSearchHandler::ImsiLoadedReady;
    memberFuncMap_[ObserverHandler::RADIO_SIM_RECORDS_LOADED] = &NetworkSearchHandler::SimRecordsLoaded;
    memberFuncMap_[ObserverHandler::RADIO_POWER] = &NetworkSearchHandler::RadioState;
    memberFuncMap_[ObserverHandler::RADIO_STATE_CHANGED] = &NetworkSearchHandler::RadioState;
    memberFuncMap_[ObserverHandler::RADIO_NETWORK_STATE] = &NetworkSearchHandler::GetNetworkStateInfo;
    memberFuncMap_[ObserverHandler::RADIO_RESTRICTED_STATE] = &NetworkSearchHandler::RadioRestrictedState;
    memberFuncMap_[ObserverHandler::RADIO_DATA_REG_STATE] = &NetworkSearchHandler::RadioRilDataRegState;
    memberFuncMap_[ObserverHandler::RADIO_VOICE_REG_STATE] = &NetworkSearchHandler::RadioRilVoiceRegState;
    memberFuncMap_[ObserverHandler::RADIO_GET_SIGNAL_STRENGTH] = &NetworkSearchHandler::RadioSignalStrength;
    memberFuncMap_[ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE] = &NetworkSearchHandler::RadioSignalStrength;
    memberFuncMap_[ObserverHandler::RADIO_OPERATOR] = &NetworkSearchHandler::RadioRilOperator;
}

NetworkSearchHandler::~NetworkSearchHandler()
{
    UnregisterEvents();
}

void NetworkSearchHandler::Init()
{
    HILOG_INFO("NetworkSearchHandler::Init start");
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    networkRegister_ = std::make_unique<NetworkRegister>(nsm->GetNetworkSearchState());
    if (networkRegister_ == nullptr) {
        HILOG_ERROR("failed to create new ObserverHandler");
        return;
    }
    operatorName_ = std::make_unique<OperatorName>(nsm->GetNetworkSearchState());
    if (operatorName_ == nullptr) {
        HILOG_ERROR("failed to create new OperatorName");
        return;
    }
    radioState_ = std::make_unique<RadioInfoState>(nsm);
    if (radioState_ == nullptr) {
        HILOG_ERROR("failed to create new RadioInfoState");
        return;
    }

    signalInfo_ = std::make_unique<SignalInfo>();
    if (signalInfo_ == nullptr) {
        HILOG_ERROR("failed to create new SignalInfo");
        return;
    }
    signalInfo_->InitSignalBar();

    if (PhoneManager ::GetInstance().phone_[1] != nullptr) {
        if (PhoneManager ::GetInstance().phone_[1]->rilManager_ != nullptr &&
            PhoneManager ::GetInstance().phone_[1]->simFileManager_ != nullptr &&
            PhoneManager ::GetInstance().phone_[1]->simStateManager_ != nullptr) {
            rilManager_ = PhoneManager ::GetInstance().phone_[1]->rilManager_;
            simStateManager_ = PhoneManager ::GetInstance().phone_[1]->simStateManager_;
            simFileManager_ = PhoneManager ::GetInstance().phone_[1]->simFileManager_;
        } else {
            HILOG_ERROR("NetworkSearchHandler::Init get RilManager is null");
            return;
        }
    } else {
        HILOG_ERROR("NetworkSearchHandler::Init get phone is null");
        return;
    }

    RegisterEvents();
}

void NetworkSearchHandler::RegisterEvents()
{
    HILOG_INFO("NetworkSearchHandler::RegisterEvents start");
    // Register SIM
    simStateManager_->RegisterForIccStateChanged(shared_from_this());

    // unsole RIL
    rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_STATE_CHANGED, nullptr);
    rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE, nullptr);
    rilManager_->RegisterPhoneNotify(shared_from_this(), ObserverHandler::RADIO_NETWORK_STATE, nullptr);
}

void NetworkSearchHandler::UnregisterEvents()
{
    // unsole
    rilManager_->UnRegisterPhoneNotify(ObserverHandler::RADIO_STATE_CHANGED);
    rilManager_->UnRegisterPhoneNotify(ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE);
    rilManager_->UnRegisterPhoneNotify(ObserverHandler::RADIO_NETWORK_STATE);
}

void NetworkSearchHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        return;
    }
    int stateChange = false;
    auto msgType = event->GetInnerEventId();
    HILOG_INFO("NetworkSearchHandler::ProcessEvent received event msgType:%{public}d", msgType);
    auto itFunc = memberFuncMap_.find(msgType);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(event);
        }
    }
    if (msgType == ObserverHandler::RADIO_OPERATOR || msgType == ObserverHandler::RADIO_DATA_REG_STATE ||
        msgType == ObserverHandler::RADIO_VOICE_REG_STATE) {
        stateChange = true;
    }
}

void NetworkSearchHandler::SimStateChange(const AppExecFwk::InnerEvent::Pointer &)
{
    if (simFileManager_ == nullptr) {
        HILOG_ERROR("NetworkSearchHandler::OnSimStateChange sim file manager is null");
        return;
    }

    simFileManager_->RegisterImsiLoaded(shared_from_this());
    simFileManager_->RegisterAllFilesLoaded(shared_from_this());
}

void NetworkSearchHandler::ImsiLoadedReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    QueryNextSignalIntensity();
    GetNetworkStateInfo(event);
}

void NetworkSearchHandler::SimRecordsLoaded(const AppExecFwk::InnerEvent::Pointer &)
{
    operatorName_->RenewSpnAndBroadcast();
}

void NetworkSearchHandler::RadioState(const AppExecFwk::InnerEvent::Pointer &)
{
    radioState_->ProcessRadioChange();
}

void NetworkSearchHandler::RadioRestrictedState(const AppExecFwk::InnerEvent::Pointer &event)
{
    networkRegister_->ProcessRestrictedState(event);
}

void NetworkSearchHandler::RadioRilDataRegState(const AppExecFwk::InnerEvent::Pointer &event)
{
    networkRegister_->ProcessPsRegister(event);
}

void NetworkSearchHandler::RadioRilVoiceRegState(const AppExecFwk::InnerEvent::Pointer &event)
{
    networkRegister_->ProcessCsRegister(event);
}

void NetworkSearchHandler::RadioSignalStrength(const AppExecFwk::InnerEvent::Pointer &event)
{
    signalInfo_->ProcessSignalIntensity(event);
}

void NetworkSearchHandler::RadioRilOperator(const AppExecFwk::InnerEvent::Pointer &event)
{
    operatorName_->HandleOperatorInfo(event);
}

void NetworkSearchHandler::QueryNextSignalIntensity()
{
    HILOG_INFO("NetworkSearchHandler::QueryNextSignalIntensity start......");
    if (!TimeOutCheck(lastTimeSignalReq)) {
        return;
    }
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SIGNAL_STRENGTH);
    event->SetOwner(shared_from_this());
    rilManager_->GetSignalStrength(event);
}

void NetworkSearchHandler::GetNetworkStateInfo(const AppExecFwk::InnerEvent::Pointer &)
{
    ModemPowerState radioState = PhoneManager ::GetInstance().phone_[1]->rilManager_->GetRadioState();
    HILOG_INFO("NetworkSearchHandler GetRadioState : %{public}d", radioState);
    switch (radioState) {
        case CORE_SERVICE_POWER_OFF:
            RadioOffState();
            break;
        case CORE_SERVICE_POWER_ON:
            RadioOnState();
            break;
        default:
            HILOG_INFO("Unhandled message with number: %{public}d", radioState);
            break;
    }
}

void NetworkSearchHandler::RadioOffState() const
{
    HILOG_INFO("RadioOffState enter");

    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        HILOG_ERROR("RadioOffState NetworkSearchHandler is null");
        return;
    }

    std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState();
    if (networkSearchState == nullptr) {
        HILOG_ERROR("networkSearchState is null");
        return;
    }

    signalInfo_->Reset();
    networkSearchState->SetInitial();
    networkSearchState->NotifyStateChange();
}

void NetworkSearchHandler::RadioOnState()
{
    HILOG_INFO("NetworkSearchHandler::GetOperatorInfo start");
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    event->SetOwner(shared_from_this());
    rilManager_->GetOperatorInfo(event);

    HILOG_INFO("NetworkSearchHandler::GetCsRegStatus start");
    event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_VOICE_REG_STATE);
    event->SetOwner(shared_from_this());
    rilManager_->GetCsRegStatus(event);

    HILOG_INFO("NetworkSearchHandler::GetPsRegStatus start");
    event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DATA_REG_STATE);
    event->SetOwner(shared_from_this());
    rilManager_->GetPsRegStatus(event);
}

void NetworkSearchHandler::GetOperatorInfo()
{
    HILOG_INFO("NetworkSearchHandler::GetOperatorInfo start");
    if (!TimeOutCheck(lastTimeOperatorReq)) {
        return;
    }
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    event->SetOwner(shared_from_this());
    rilManager_->GetOperatorInfo(event);
}

void NetworkSearchHandler::GetRilPsRegistration()
{
    HILOG_INFO("NetworkSearchHandler::GetPsRegStatus start");
    if (!TimeOutCheck(lastTimePsRegistrationReq)) {
        return;
    }
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DATA_REG_STATE);
    event->SetOwner(shared_from_this());
    rilManager_->GetPsRegStatus(event);
}

void NetworkSearchHandler::GetRilCsRegistration()
{
    HILOG_INFO("NetworkSearchHandler::GetCsRegStatus start");
    if (!TimeOutCheck(lastTimeCsRegistrationReq)) {
        return;
    }
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_VOICE_REG_STATE);
    event->SetOwner(shared_from_this());
    rilManager_->GetCsRegStatus(event);
}

void NetworkSearchHandler::GetSignalInfo(std::vector<sptr<SignalInformation>> &signals)
{
    QueryNextSignalIntensity();
    signalInfo_->GetSignalInfoList(signals);
}

bool NetworkSearchHandler::TimeOutCheck(uint64_t &lastTime)
{
    uint64_t now = time(0);
    if ((now - lastTime) > REQ_INTERVAL) {
        lastTime = now;
        return true;
    }
    return false;
}
} // namespace OHOS
