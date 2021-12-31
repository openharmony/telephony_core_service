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
const int64_t IMS_STATE_REGISTED = 1;
NetworkSearchHandler::NetworkSearchHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::weak_ptr<NetworkSearchManager> &networkSearchManager,
    const std::weak_ptr<ITelRilManager> &telRilManager, const std::weak_ptr<ISimFileManager> &simFileManager,
    const std::weak_ptr<ISimStateManager> &simStateManager)
    : AppExecFwk::EventHandler(runner), networkSearchManager_(networkSearchManager), telRilManager_(telRilManager),
      simFileManager_(simFileManager), simStateManager_(simStateManager)
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
    memberFuncMap_[ObserverHandler::RADIO_GET_STATUS] = &NetworkSearchHandler::GetRadioStateResponse;
    memberFuncMap_[ObserverHandler::RADIO_SET_STATUS] = &NetworkSearchHandler::SetRadioStateResponse;
    memberFuncMap_[ObserverHandler::RADIO_SET_PREFERRED_NETWORK_MODE] =
        &NetworkSearchHandler::SetPreferredNetworkResponse;
    memberFuncMap_[ObserverHandler::RADIO_GET_PREFERRED_NETWORK_MODE] =
        &NetworkSearchHandler::GetPreferredNetworkResponse;
    memberFuncMap_[ObserverHandler::RADIO_NETWORK_TIME_UPDATE] = &NetworkSearchHandler::RadioNitzUpdate;
    memberFuncMap_[ObserverHandler::RADIO_IMS_REG_STATUS_UPDATE] = &NetworkSearchHandler::ImsRegStateUpdate;
    memberFuncMap_[ObserverHandler::RADIO_GET_IMS_REG_STATUS] = &NetworkSearchHandler::GetImsRegStatus;
    memberFuncMap_[ObserverHandler::RADIO_GET_IMEI] = &NetworkSearchHandler::RadioGetImei;
    memberFuncMap_[ObserverHandler::RADIO_SET_PS_ATTACH_STATUS] = &NetworkSearchHandler::SetPsAttachStatusResponse;
    memberFuncMap_[ObserverHandler::RADIO_GET_NEIGHBORING_CELL_INFO] =
        &NetworkSearchHandler::RadioGetNeighboringCellInfo;
    memberFuncMap_[ObserverHandler::RADIO_GET_CURRENT_CELL_INFO] = &NetworkSearchHandler::RadioGetCurrentCellInfo;
}

NetworkSearchHandler::~NetworkSearchHandler()
{
    UnregisterEvents();
}

void NetworkSearchHandler::Init()
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager");
        return;
    }
    networkRegister_ = std::make_unique<NetworkRegister>(nsm->GetNetworkSearchState(), nsm);
    if (networkRegister_ == nullptr) {
        TELEPHONY_LOGE("failed to create new networkRegister");
        return;
    }
    operatorName_ = std::make_unique<OperatorName>(
        nsm->GetNetworkSearchState(), nsm->GetSimFileManager(), networkSearchManager_);
    if (operatorName_ == nullptr) {
        TELEPHONY_LOGE("failed to create new operatorName");
        return;
    }
    radioInfo_ = std::make_unique<RadioInfo>(nsm);
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to create new radioInfo");
        return;
    }
    signalInfo_ = std::make_unique<SignalInfo>();
    if (signalInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to create new signalInfo");
        return;
    }
    networkSelection_ = std::make_unique<NetworkSelection>(networkSearchManager_);
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("failed to create new networkSelection");
        return;
    }
    networkType_ = std::make_unique<NetworkType>(nsm);
    if (networkType_ == nullptr) {
        TELEPHONY_LOGE("failed to create new networkType");
        return;
    }
    nitzUpdate_ = std::make_unique<NitzUpdate>(networkSearchManager_);
    if (nitzUpdate_ == nullptr) {
        TELEPHONY_LOGE("failed to create new nitzUpdate");
        return;
    }
    cellManager_ = std::make_unique<CellManager>(networkSearchManager_);
    if (cellManager_ == nullptr) {
        TELEPHONY_LOGE("failed to create new CellManager");
        return;
    }
    signalInfo_->InitSignalBar();
    RegisterEvents();
}

void NetworkSearchHandler::RegisterEvents()
{
    TELEPHONY_LOGI("NetworkSearchHandler::RegisterEvents start");
    // Register SIM
    {
        std::shared_ptr<ISimStateManager> simStateManager = simStateManager_.lock();
        if (simStateManager != nullptr) {
            simStateManager->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_STATE_CHANGE);
        }
    }

    {
        std::shared_ptr<ISimFileManager> simFileManager = simFileManager_.lock();
        if (simFileManager != nullptr) {
            simFileManager->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_IMSI_LOADED_READY);
            simFileManager->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_RECORDS_LOADED);
        }
    }

    // unsol RIL
    {
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_STATE_CHANGED, nullptr);
            telRilManager->RegisterCoreNotify(
                shared_from_this(), ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE, nullptr);
            telRilManager->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_NETWORK_STATE, nullptr);
            telRilManager->RegisterCoreNotify(
                shared_from_this(), ObserverHandler::RADIO_NETWORK_TIME_UPDATE, nullptr);
            telRilManager->RegisterCoreNotify(
                shared_from_this(), ObserverHandler::RADIO_IMS_REG_STATUS_UPDATE, nullptr);
        }
    }
}

void NetworkSearchHandler::UnregisterEvents()
{
    {
        std::shared_ptr<ISimStateManager> simStateManager = simStateManager_.lock();
        if (simStateManager != nullptr) {
            simStateManager->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_STATE_CHANGE);
        }
    }

    {
        std::shared_ptr<ISimFileManager> simFileManager = simFileManager_.lock();
        if (simFileManager != nullptr) {
            simFileManager->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_IMSI_LOADED_READY);
            simFileManager->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_RECORDS_LOADED);
        }
    }

    // unsol
    {
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_STATE_CHANGED);
            telRilManager->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE);
            telRilManager->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_NETWORK_STATE);
            telRilManager->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_NETWORK_TIME_UPDATE);
            telRilManager->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_IMS_REG_STATUS_UPDATE);
        }
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
    std::shared_ptr<ISimFileManager> simFileManager = simFileManager_.lock();
    if (simFileManager != nullptr) {
        simFileManager->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_IMSI_LOADED_READY);
        simFileManager->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_RECORDS_LOADED);
    }
}

void NetworkSearchHandler::ImsiLoadedReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    SendUpdateCellLocationRequest();
    GetRilSignalIntensity(false);
    InitGetNetworkSelectionMode();
    GetNetworkStateInfo(event);
}

void NetworkSearchHandler::SimRecordsLoaded(const AppExecFwk::InnerEvent::Pointer &)
{
    if (operatorName_ != nullptr) {
        operatorName_->NotifySpnChanged();
    }

    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager != nullptr) {
        RadioTech csRadioTech =
            static_cast<RadioTech>(networkSearchManager->GetCsRadioTech(CoreManager::DEFAULT_SLOT_ID));
        UpdatePhone(csRadioTech);
    }
}

void NetworkSearchHandler::RadioStateChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<int32_t> object = event->GetSharedObject<int32_t>();
    if (object == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioStateChange object is nullptr!");
        return;
    }
    int32_t radioState = *object;
    TELEPHONY_LOGI("NetworkSearchHandler::RadioState change: %{public}d", radioState);
    switch (radioState) {
        case static_cast<int32_t>(ModemPowerState::CORE_SERVICE_POWER_OFF): {
            RadioOffState();
            break;
        }
        case static_cast<int32_t>(ModemPowerState::CORE_SERVICE_POWER_ON): {
            SendUpdateCellLocationRequest();
            GetRilSignalIntensity(true);
            InitGetNetworkSelectionMode();
            RadioOnState();
            break;
        }
        default:
            TELEPHONY_LOGI("Unhandled message with number: %{public}d", radioState);
            break;
    }

    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioStateChange failed to get NetworkSearchManager");
        return;
    }
    networkSearchManager->GetImei(0);
    if (radioState == static_cast<int32_t>(ModemPowerState::CORE_SERVICE_POWER_ON) ||
        radioState == static_cast<int32_t>(ModemPowerState::CORE_SERVICE_POWER_OFF)) {
        networkSearchManager->SetRadioStateValue((ModemPowerState)radioState);
    } else {
        networkSearchManager->SetRadioStateValue(ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE);
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

void NetworkSearchHandler::GetRilSignalIntensity(bool checkTime)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetRilSignalIntensity start......");
    if (!TimeOutCheck(lastTimeSignalReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SIGNAL_STRENGTH);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetSignalStrength(event);
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
    ModemPowerState radioState = networkSearchManager->GetRadioStateValue();
    TELEPHONY_LOGI("NetworkSearchHandler GetRadioState : %{public}d", radioState);
    switch (radioState) {
        case ModemPowerState::CORE_SERVICE_POWER_OFF:
            RadioOffState();
            break;
        case ModemPowerState::CORE_SERVICE_POWER_ON:
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
    if (cellManager_ != nullptr) {
        cellManager_->ClearCellInfoList();
    }
    networkSearchState->CsRadioTechChange();
    networkSearchState->NotifyStateChange();

    if (!networkSearchManager->GetAirplaneMode()) {
        networkSearchManager->SetRadioState(static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
    }
}

void NetworkSearchHandler::RadioOnState()
{
    GetRilOperatorInfo(false);
    GetRilPsRegistration(false);
    GetRilCsRegistration(false);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager != nullptr) {
        networkSearchManager->InitMsgNum();
    }
}

void NetworkSearchHandler::GetRadioStateResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo is null");
        return;
    }
    radioInfo_->ProcessGetRadioState(event);
}

void NetworkSearchHandler::SetRadioStateResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo is null");
        return;
    }
    radioInfo_->ProcessSetRadioState(event);
}

void NetworkSearchHandler::GetRilOperatorInfo(bool checkTime)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetOperatorInfo start");
    if (!TimeOutCheck(lastTimeOperatorReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetOperatorInfo(event);
        }
    }
}

void NetworkSearchHandler::GetRilPsRegistration(bool checkTime)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetPsRegStatus start");
    if (!TimeOutCheck(lastTimePsRegistrationReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DATA_REG_STATE);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetPsRegStatus(event);
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

void NetworkSearchHandler::GetRilCsRegistration(bool checkTime)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetCsRegStatus start");
    if (!TimeOutCheck(lastTimeCsRegistrationReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_VOICE_REG_STATE);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetCsRegStatus(event);
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
    if (signalInfo_ != nullptr) {
        signalInfo_->GetSignalInfoList(signals);
    }
}

bool NetworkSearchHandler::TimeOutCheck(int64_t &lastTime, bool checkTime)
{
    int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (!checkTime || (checkTime && (now - lastTime) > REQ_INTERVAL)) {
        lastTime = now;
        return true;
    }
    return false;
}

void NetworkSearchHandler::GetPreferredNetworkResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkType_ != nullptr) {
        networkType_->ProcessGetPreferredNetwork(CoreManager::DEFAULT_SLOT_ID, event);
    } else {
        TELEPHONY_LOGE("GetPreferredNetworkResponse NetworkType is null");
    }
}

void NetworkSearchHandler::SetPreferredNetworkResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkType_ != nullptr) {
        networkType_->ProcessSetPreferredNetwork(CoreManager::DEFAULT_SLOT_ID, event);
    } else {
        TELEPHONY_LOGE("SetPreferredNetworkResponse NetworkType is null");
    }
}

void NetworkSearchHandler::InitPreferredNetwork()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("InitGetNetworkSelectionMode networkSearchManager is null");
        return;
    }
    int32_t networkMode = networkSearchManager->GetPreferredNetworkValue(CoreManager::DEFAULT_SLOT_ID);
    networkSearchManager->SetPreferredNetwork(CoreManager::DEFAULT_SLOT_ID, networkMode);
}

void NetworkSearchHandler::RadioNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->ProcessNitzUpdate(event);
    } else {
        TELEPHONY_LOGE("RadioNitzUpdate nitzUpdate is null");
    }
}

void NetworkSearchHandler::RadioGetImei(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("NetworkSearchHandler::RadioGetImei start");
    if (radioInfo_ != nullptr) {
        radioInfo_->ProcessGetImei(event);
    } else {
        TELEPHONY_LOGE("RadioGetImei radioInfo_ is null");
    }
}

void NetworkSearchHandler::UpdatePhone(RadioTech csRadioTech) const
{
    if (networkType_ != nullptr) {
        networkType_->UpdatePhone(csRadioTech);
    } else {
        TELEPHONY_LOGE("UpdatePhone networkType is null");
    }
}

void NetworkSearchHandler::GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("InitGetNetworkSelectionMode networkSearchManager is null");
        return;
    }
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::GetImsRegStatus event is nullptr");
        return;
    }
    std::shared_ptr<ImsRegStatusInfo> imsRegStatusInfo = event->GetSharedObject<ImsRegStatusInfo>();
    if (imsRegStatusInfo == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::GetImsRegStatus imsRegStatusInfo is nullptr\n");
        return;
    }
    if (imsRegStatusInfo != nullptr) {
        TELEPHONY_LOGI("NetworkSearchHandler::GetImsRegStatus ImsRegStatusInfo : %{public}d-%{public}d-%{public}d",
            imsRegStatusInfo->notifyType, imsRegStatusInfo->regInfo, imsRegStatusInfo->extInfo);
        std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState();
        if (networkSearchState != nullptr) {
            networkSearchState->SetImsStatus(imsRegStatusInfo->regInfo == IMS_STATE_REGISTED);
        }
    }
}

void NetworkSearchHandler::ImsRegStateUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("InitGetNetworkSelectionMode networkSearchManager is null");
        return;
    }
    if (event == nullptr) {
        TELEPHONY_LOGE("IMSRegister::ImsRegStateUpdate event is nullptr");
        return;
    }
    std::shared_ptr<ImsRegStatusInfo> imsRegStatusInfo = event->GetSharedObject<ImsRegStatusInfo>();
    if (imsRegStatusInfo == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::ImsRegStateUpdate imsRegStatusInfo is nullptr\n");
    } else {
        TELEPHONY_LOGI("NetworkSearchHandler::ImsRegStateUpdate  %{public}d-%{public}d-%{public}d",
            imsRegStatusInfo->notifyType, imsRegStatusInfo->regInfo, imsRegStatusInfo->extInfo);
        std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState();
        if (networkSearchState != nullptr) {
            networkSearchState->SetImsStatus(imsRegStatusInfo->regInfo == IMS_STATE_REGISTED);
        }
    }
    networkSearchManager->NotifyImsRegStateChanged();
}

void NetworkSearchHandler::SetPsAttachStatusResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessPsAttachStatus(event);
    } else {
        TELEPHONY_LOGE("SetPsAttachStatusResponse networkRegister_ is null");
    }
}

void NetworkSearchHandler::RadioGetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (cellManager_ != nullptr) {
        cellManager_->ProcessCurrentCellInfo(event);
    }
}

void NetworkSearchHandler::RadioGetNeighboringCellInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (cellManager_ != nullptr) {
        cellManager_->ProcessNeighboringCellInfo(event);
    }
}

void NetworkSearchHandler::GetCellInfoList(std::vector<sptr<CellInformation>> &cells)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetCellInfoList start......");
    if (cellManager_ != nullptr) {
        cellManager_->GetCellInfoList(cells);
    }
}

void NetworkSearchHandler::SendUpdateCellLocationRequest()
{
    TELEPHONY_LOGI("NetworkSearchHandler::SendUpdateCellLocationRequest start......");
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CURRENT_CELL_INFO);
    if (event != nullptr && telRilManager != nullptr) {
        event->SetOwner(shared_from_this());
        telRilManager->GetCurrentCellInfo(event);
    }
}

void NetworkSearchHandler::UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac)
{
    TELEPHONY_LOGI("NetworkSearchHandler::UpdateCellLocation");
    if (cellManager_ != nullptr) {
        cellManager_->UpdateCellLocation(techType, cellId, lac);
    }
}
} // namespace Telephony
} // namespace OHOS
