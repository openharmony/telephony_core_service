/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "ims_core_service_client.h"
#include "network_search_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const int32_t REQ_INTERVAL = 30;
const std::map<uint32_t, NetworkSearchHandler::NsHandlerFunc> NetworkSearchHandler::memberFuncMap_ = {
    { RadioEvent::RADIO_SIM_STATE_CHANGE, &NetworkSearchHandler::SimStateChange },
    { RadioEvent::RADIO_IMSI_LOADED_READY, &NetworkSearchHandler::ImsiLoadedReady },
    { RadioEvent::RADIO_SIM_RECORDS_LOADED, &NetworkSearchHandler::SimRecordsLoaded },
    { RadioEvent::RADIO_STATE_CHANGED, &NetworkSearchHandler::RadioStateChange },
    { RadioEvent::RADIO_NETWORK_STATE, &NetworkSearchHandler::GetNetworkStateInfo },
    { RadioEvent::RADIO_RESTRICTED_STATE, &NetworkSearchHandler::RadioRestrictedState },
    { RadioEvent::RADIO_DATA_REG_STATE, &NetworkSearchHandler::RadioRilDataRegState },
    { RadioEvent::RADIO_VOICE_REG_STATE, &NetworkSearchHandler::RadioRilVoiceRegState },
    { RadioEvent::RADIO_GET_SIGNAL_STRENGTH, &NetworkSearchHandler::RadioSignalStrength },
    { RadioEvent::RADIO_SIGNAL_STRENGTH_UPDATE, &NetworkSearchHandler::RadioSignalStrength },
    { RadioEvent::RADIO_OPERATOR, &NetworkSearchHandler::RadioRilOperator },
    { RadioEvent::RADIO_NETWORK_SEARCH_RESULT, &NetworkSearchHandler::NetworkSearchResult },
    { RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE, &NetworkSearchHandler::GetNetworkSelectionModeResponse },
    { RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, &NetworkSearchHandler::SetNetworkSelectionModeResponse },
    { RadioEvent::RADIO_GET_STATUS, &NetworkSearchHandler::GetRadioStateResponse },
    { RadioEvent::RADIO_SET_STATUS, &NetworkSearchHandler::SetRadioStateResponse },
    { RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE, &NetworkSearchHandler::SetPreferredNetworkResponse },
    { RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE, &NetworkSearchHandler::GetPreferredNetworkResponse },
    { RadioEvent::RADIO_NETWORK_TIME_UPDATE, &NetworkSearchHandler::RadioNitzUpdate },
    { RadioEvent::RADIO_IMS_SERVICE_STATUS_UPDATE, &NetworkSearchHandler::UpdateImsServiceStatus },
    { RadioEvent::RADIO_IMS_REGISTER_STATE_UPDATE, &NetworkSearchHandler::UpdateImsRegisterState },
    { RadioEvent::RADIO_GET_IMEI, &NetworkSearchHandler::RadioGetImei },
    { RadioEvent::RADIO_GET_MEID, &NetworkSearchHandler::RadioGetMeid },
    { RadioEvent::RADIO_GET_NEIGHBORING_CELL_INFO, &NetworkSearchHandler::RadioGetNeighboringCellInfo },
    { RadioEvent::RADIO_GET_CURRENT_CELL_INFO, &NetworkSearchHandler::RadioGetCurrentCellInfo },
    { RadioEvent::RADIO_CURRENT_CELL_UPDATE, &NetworkSearchHandler::RadioCurrentCellInfoUpdate },
    { RadioEvent::RADIO_CHANNEL_CONFIG_UPDATE, &NetworkSearchHandler::RadioChannelConfigInfo },
    { RadioEvent::RADIO_VOICE_TECH_CHANGED, &NetworkSearchHandler::RadioVoiceTechChange },
    { RadioEvent::RADIO_GET_VOICE_TECH, &NetworkSearchHandler::RadioVoiceTechChange },
    { RadioEvent::RADIO_SET_DATA_CONNECT_ACTIVE, &NetworkSearchHandler::DcPhysicalLinkActiveUpdate },
    { SettingEventCode::MSG_AUTO_TIME, &NetworkSearchHandler::AutoTimeChange },
    { SettingEventCode::MSG_AUTO_TIMEZONE, &NetworkSearchHandler::AutoTimeZoneChange },
    { SettingEventCode::MSG_AUTO_AIRPLANE_MODE, &NetworkSearchHandler::AirplaneModeChange }
};

NetworkSearchHandler::NetworkSearchHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    const std::weak_ptr<NetworkSearchManager> &networkSearchManager, const std::weak_ptr<ITelRilManager> &telRilManager,
    const std::weak_ptr<ISimManager> &simManager, int32_t slotId)
    : AppExecFwk::EventHandler(runner), networkSearchManager_(networkSearchManager), telRilManager_(telRilManager),
      simManager_(simManager), slotId_(slotId)
{}

NetworkSearchHandler::~NetworkSearchHandler()
{
    if (statusChangeListener_ != nullptr) {
        statusChangeListener_.clear();
        statusChangeListener_ = nullptr;
    }
}

bool NetworkSearchHandler::Init()
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager");
        return false;
    }
    networkRegister_ = std::make_unique<NetworkRegister>(nsm->GetNetworkSearchState(slotId_), nsm, slotId_);
    if (networkRegister_ == nullptr) {
        TELEPHONY_LOGE("failed to create new networkRegister slotId:%{public}d", slotId_);
        return false;
    }
    networkRegister_->InitNrConversionConfig();
    if (!InitOperatorName()) {
        return false;
    }
    radioInfo_ = std::make_unique<RadioInfo>(nsm, slotId_);
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to create new radioInfo slotId:%{public}d", slotId_);
        return false;
    }
    signalInfo_ = std::make_unique<SignalInfo>();
    if (signalInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to create new signalInfo slotId:%{public}d", slotId_);
        return false;
    }
    networkSelection_ = std::make_unique<NetworkSelection>(networkSearchManager_, slotId_);
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("failed to create new networkSelection slotId:%{public}d", slotId_);
        return false;
    }
    networkType_ = std::make_unique<NetworkType>(nsm, slotId_);
    if (networkType_ == nullptr) {
        TELEPHONY_LOGE("failed to create new networkType slotId:%{public}d", slotId_);
        return false;
    }
    nitzUpdate_ = std::make_unique<NitzUpdate>(networkSearchManager_, slotId_);
    if (nitzUpdate_ == nullptr) {
        TELEPHONY_LOGE("failed to create new nitzUpdate slotId:%{public}d", slotId_);
        return false;
    }
    cellInfo_ = std::make_unique<CellInfo>(networkSearchManager_, slotId_);
    if (cellInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to create new CellInfo slotId:%{public}d", slotId_);
        return false;
    }
    signalInfo_->InitSignalBar();
    RegisterEvents();
    return true;
}

bool NetworkSearchHandler::InitOperatorName()
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    operatorName_ = std::make_shared<OperatorName>(
        subscriberInfo, nsm->GetNetworkSearchState(slotId_), nsm->GetSimManager(), networkSearchManager_, slotId_);
    if (operatorName_ == nullptr) {
        TELEPHONY_LOGE("failed to create new operatorName slotId:%{public}d", slotId_);
        return false;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(operatorName_);
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("InitOperatorName samgrProxy or statusChangeListener_ is nullptr");
    } else {
        int32_t ret = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
        TELEPHONY_LOGI("InitOperatorName SubscribeSystemAbility result:%{public}d", ret);
    }
    return true;
}

void NetworkSearchHandler::RegisterEvents()
{
    TELEPHONY_LOGI("NetworkSearchHandler::RegisterEvents start slotId:%{public}d", slotId_);
    // Register SIM
    {
        std::shared_ptr<ISimManager> simManager = simManager_.lock();
        if (simManager != nullptr) {
            simManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
            simManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_IMSI_LOADED_READY);
            simManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
        }
    }
    // unsol RIL
    {
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STATE_CHANGED, nullptr);
            telRilManager->RegisterCoreNotify(
                slotId_, shared_from_this(), RadioEvent::RADIO_SIGNAL_STRENGTH_UPDATE, nullptr);
            telRilManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_NETWORK_STATE, nullptr);
            telRilManager->RegisterCoreNotify(
                slotId_, shared_from_this(), RadioEvent::RADIO_NETWORK_TIME_UPDATE, nullptr);
            telRilManager->RegisterCoreNotify(
                slotId_, shared_from_this(), RadioEvent::RADIO_CHANNEL_CONFIG_UPDATE, nullptr);
            telRilManager->RegisterCoreNotify(
                slotId_, shared_from_this(), RadioEvent::RADIO_VOICE_TECH_CHANGED, nullptr);
            telRilManager->RegisterCoreNotify(
                slotId_, shared_from_this(), RadioEvent::RADIO_CURRENT_CELL_UPDATE, nullptr);
        }
    }
    // Register IMS
    {
        std::shared_ptr<ImsCoreServiceClient> imsCoreServiceClient =
            DelayedSingleton<ImsCoreServiceClient>::GetInstance();
        if (imsCoreServiceClient != nullptr) {
            imsCoreServiceClient->RegisterImsCoreServiceCallbackHandler(slotId_, shared_from_this());
        }
    }
}

void NetworkSearchHandler::UnregisterEvents()
{
    {
        std::shared_ptr<ISimManager> simManager = simManager_.lock();
        if (simManager != nullptr) {
            simManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
            simManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_IMSI_LOADED_READY);
            simManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
        }
    }
    // unsol
    {
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_STATE_CHANGED);
            telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIGNAL_STRENGTH_UPDATE);
            telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_NETWORK_STATE);
            telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_NETWORK_TIME_UPDATE);
            telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_CHANNEL_CONFIG_UPDATE);
            telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_VOICE_TECH_CHANGED);
            telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_CURRENT_CELL_UPDATE);
        }
    }
}

void NetworkSearchHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        return;
    }
    auto msgType = event->GetInnerEventId();
    TELEPHONY_LOGI(
        "NetworkSearchHandler::ProcessEvent received event slotId:%{public}d msgType:%{public}d", slotId_, msgType);
    auto itFunc = memberFuncMap_.find(static_cast<RadioEvent>(msgType));
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(event);
        }
    }
}

void NetworkSearchHandler::SimStateChange(const AppExecFwk::InnerEvent::Pointer &)
{
    std::shared_ptr<ISimManager> simManager = simManager_.lock();
    if (simManager != nullptr) {
        simManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_IMSI_LOADED_READY);
        simManager->RegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
    }
}

void NetworkSearchHandler::ImsiLoadedReady(const AppExecFwk::InnerEvent::Pointer &event)
{
    SendUpdateCellLocationRequest();
    InitGetNetworkSelectionMode();
    GetNetworkStateInfo(event);
}

void NetworkSearchHandler::SimRecordsLoaded(const AppExecFwk::InnerEvent::Pointer &)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager != nullptr) {
        RadioTech csRadioTech = static_cast<RadioTech>(networkSearchManager->GetCsRadioTech(slotId_));
        UpdatePhone(csRadioTech);
    }

    if (operatorName_ != nullptr) {
        operatorName_->NotifySpnChanged();
    }
}

void NetworkSearchHandler::RadioStateChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<HRilInt32Parcel> object = event->GetSharedObject<HRilInt32Parcel>();
    if (object == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioStateChange object is nullptr!");
        return;
    }
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioStateChange failed to get NetworkSearchManager");
        return;
    }
    int32_t radioState = object->data;
    TELEPHONY_LOGI("NetworkSearchHandler::RadioState change: %{public}d", radioState);
    switch (radioState) {
        case CORE_SERVICE_POWER_NOT_AVAILABLE:
        case CORE_SERVICE_POWER_OFF: {
            RadioOffOrUnavailableState(radioState);
            break;
        }
        case CORE_SERVICE_POWER_ON: {
            SendUpdateCellLocationRequest();
            InitGetNetworkSelectionMode();
            RadioOnState();
            break;
        }
        default:
            TELEPHONY_LOGI("Unhandled message with number: %{public}d", radioState);
            break;
    }
    if (radioState == CORE_SERVICE_POWER_ON || radioState == CORE_SERVICE_POWER_OFF) {
        networkSearchManager->SetRadioStateValue(slotId_, (ModemPowerState)radioState);
        auto inner = networkSearchManager->FindManagerInner(slotId_);
        if (inner != nullptr && inner->deviceStateHandler_ != nullptr) {
            inner->deviceStateHandler_->ProcessRadioState();
        }
    } else {
        networkSearchManager->SetRadioStateValue(slotId_, CORE_SERVICE_POWER_NOT_AVAILABLE);
    }
    if (operatorName_ != nullptr) {
        operatorName_->NotifySpnChanged();
    }
}

void NetworkSearchHandler::RadioRestrictedState(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessRestrictedState(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioRestrictedState slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::RadioRilDataRegState(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr ||
        networkSearchManager->GetRadioState(slotId_) == (int)ModemPowerState::CORE_SERVICE_POWER_OFF) {
        TELEPHONY_LOGI("radio is power off, no need update data reg state");
        return;
    }
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessPsRegister(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioRilDataRegState slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::RadioRilVoiceRegState(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr ||
        networkSearchManager->GetRadioState(slotId_) == (int)ModemPowerState::CORE_SERVICE_POWER_OFF) {
        TELEPHONY_LOGI("radio is power off, no need update voice reg state");
        return;
    }
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessCsRegister(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioRilVoiceRegState slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::RadioSignalStrength(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (signalInfo_ != nullptr) {
        signalInfo_->ProcessSignalIntensity(slotId_, event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioSignalStrength slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::RadioRilOperator(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (operatorName_ != nullptr) {
        operatorName_->HandleOperatorInfo(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioRilOperator slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::GetRilSignalIntensity(bool checkTime)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetRilSignalIntensity start...... slotId:%{public}d", slotId_);
    if (!TimeOutCheck(lastTimeSignalReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_SIGNAL_STRENGTH);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetSignalStrength(slotId_, event);
        }
    }
}

void NetworkSearchHandler::GetNetworkStateInfo(const AppExecFwk::InnerEvent::Pointer &)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager RadioState slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState(slotId_);
    if (networkSearchState == nullptr) {
        TELEPHONY_LOGE("networkSearchState is null slotId:%{public}d", slotId_);
        return;
    }

    ModemPowerState radioState = static_cast<ModemPowerState>(networkSearchManager->GetRadioState(slotId_));
    TELEPHONY_LOGI("NetworkSearchHandler GetRadioState : %{public}d slotId:%{public}d", radioState, slotId_);
    switch (radioState) {
        case CORE_SERVICE_POWER_NOT_AVAILABLE:
        case CORE_SERVICE_POWER_OFF:
            RadioOffOrUnavailableState(radioState);
            break;
        case CORE_SERVICE_POWER_ON:
            RadioOnState();
            break;
        default:
            TELEPHONY_LOGI("Unhandled message with number: %{public}d slotId:%{public}d", radioState, slotId_);
            break;
    }
}

void NetworkSearchHandler::RadioOffOrUnavailableState(int32_t radioState) const
{
    TELEPHONY_LOGI("RadioOffOrUnavailableState enter... slotId:%{public}d", slotId_);

    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("RadioOffOrUnavailableState NetworkSearchHandler is null slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState(slotId_);
    if (networkSearchState == nullptr) {
        TELEPHONY_LOGE("networkSearchState is null slotId:%{public}d", slotId_);
        return;
    }

    networkSearchState->SetInitial();
    RegServiceState regState = radioState == CORE_SERVICE_POWER_OFF ?
        RegServiceState::REG_STATE_POWER_OFF : RegServiceState::REG_STATE_NO_SERVICE;
    networkSearchState->SetNetworkState(regState, DomainType::DOMAIN_TYPE_CS);
    networkSearchState->SetNetworkState(regState, DomainType::DOMAIN_TYPE_PS);
    if (signalInfo_ != nullptr) {
        signalInfo_->Reset();
    }
    if (cellInfo_ != nullptr) {
        cellInfo_->ClearCellInfoList();
    }
    networkSearchState->NotifyStateChange();
    networkSearchManager->SetNrOptionMode(slotId_, NrMode::NR_MODE_UNKNOWN);
    if (!networkSearchManager->GetAirplaneMode() && radioState == CORE_SERVICE_POWER_OFF) {
        networkSearchManager->SetRadioState(slotId_, static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
    }
    sptr<NetworkSearchCallBackBase> cellularData = networkSearchManager->GetCellularDataCallBack();
    if (cellularData) {
        cellularData->ClearCellularDataConnections(slotId_);
    }
    sptr<NetworkSearchCallBackBase> cellularCall = networkSearchManager->GetCellularCallCallBack();
    if (cellularCall) {
        cellularCall->ClearCellularCallList(slotId_);
    }
}

void NetworkSearchHandler::RadioOnState()
{
    GetRilOperatorInfo(false);
    GetRilPsRegistration(false);
    GetRilCsRegistration(false);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager != nullptr) {
        networkSearchManager->InitMsgNum(slotId_);
    }
    GetRilSignalIntensity(false);
}

void NetworkSearchHandler::GetRadioStateResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo is null slotId:%{public}d", slotId_);
        return;
    }
    radioInfo_->ProcessGetRadioState(event);
}

void NetworkSearchHandler::SetRadioStateResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo is null slotId:%{public}d", slotId_);
        return;
    }
    radioInfo_->ProcessSetRadioState(event);
}

void NetworkSearchHandler::GetRilOperatorInfo(bool checkTime)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetOperatorInfo start slotId:%{public}d", slotId_);
    if (!TimeOutCheck(lastTimeOperatorReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetOperatorInfo(slotId_, event);
        }
    }
}

void NetworkSearchHandler::GetRilPsRegistration(bool checkTime)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetPsRegStatus start slotId:%{public}d", slotId_);
    if (!TimeOutCheck(lastTimePsRegistrationReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_DATA_REG_STATE);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetPsRegStatus(slotId_, event);
        }
    }
}

void NetworkSearchHandler::InitGetNetworkSelectionMode()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("InitGetNetworkSelectionMode networkSearchManager is null slotId:%{public}d", slotId_);
        return;
    }
    networkSearchManager->GetNetworkSelectionMode(slotId_);
}

void NetworkSearchHandler::GetRilCsRegistration(bool checkTime)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetCsRegStatus start slotId:%{public}d", slotId_);
    if (!TimeOutCheck(lastTimeCsRegistrationReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_VOICE_REG_STATE);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetCsRegStatus(slotId_, event);
        }
    }
}

void NetworkSearchHandler::NetworkSearchResult(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchResult NetworkSelection is null slotId:%{public}d", slotId_);
        return;
    }
    networkSelection_->ProcessNetworkSearchResult(event);
}

void NetworkSearchHandler::SetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("SetNetworkSelectionModeResponse NetworkSelection is null slotId:%{public}d", slotId_);
        return;
    }
    networkSelection_->ProcessSetNetworkSelectionMode(event);
}

void NetworkSearchHandler::GetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("GetNetworkSelectionModeResponse NetworkSelection is null slotId:%{public}d", slotId_);
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
    if (!checkTime || (now - lastTime) > REQ_INTERVAL) {
        lastTime = now;
        return true;
    }
    return false;
}

void NetworkSearchHandler::GetPreferredNetworkResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkType_ != nullptr) {
        networkType_->ProcessGetPreferredNetwork(event);
    } else {
        TELEPHONY_LOGE("GetPreferredNetworkResponse NetworkType is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::SetPreferredNetworkResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkType_ != nullptr) {
        networkType_->ProcessSetPreferredNetwork(event);
    } else {
        TELEPHONY_LOGE("SetPreferredNetworkResponse NetworkType is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->ProcessNitzUpdate(event);
    } else {
        TELEPHONY_LOGE("RadioNitzUpdate nitzUpdate is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioGetImei(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("NetworkSearchHandler::RadioGetImei start slotId:%{public}d", slotId_);
    if (radioInfo_ != nullptr) {
        radioInfo_->ProcessGetImei(event);
    } else {
        TELEPHONY_LOGE("RadioGetImei radioInfo_ is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioGetMeid(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("NetworkSearchHandler::RadioGetMeid start slotId:%{public}d", slotId_);
    if (radioInfo_ != nullptr) {
        radioInfo_->ProcessGetMeid(event);
    } else {
        TELEPHONY_LOGE("RadioGetMeid radioInfo_ is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::UpdatePhone(RadioTech csRadioTech) const
{
    if (radioInfo_ != nullptr) {
        radioInfo_->UpdatePhone(csRadioTech);
    } else {
        TELEPHONY_LOGE("UpdatePhone networkType is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioGetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (cellInfo_ != nullptr) {
        cellInfo_->ProcessCurrentCellInfo(event);
    }
}

void NetworkSearchHandler::RadioCurrentCellInfoUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (cellInfo_ != nullptr) {
        cellInfo_->ProcessCurrentCellInfo(event);
    }
}

void NetworkSearchHandler::RadioGetNeighboringCellInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (cellInfo_ != nullptr) {
        cellInfo_->ProcessNeighboringCellInfo(event);
    }
}

void NetworkSearchHandler::GetCellInfoList(std::vector<sptr<CellInformation>> &cells)
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetCellInfoList slotId:%{public}d", slotId_);
    if (cellInfo_ != nullptr) {
        cellInfo_->GetCellInfoList(cells);
    }
}

sptr<CellLocation> NetworkSearchHandler::GetCellLocation()
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetCellLocation slotId:%{public}d", slotId_);
    if (cellInfo_ != nullptr) {
        return cellInfo_->GetCellLocation();
    }
    return nullptr;
}

void NetworkSearchHandler::TimezoneRefresh()
{
    TELEPHONY_LOGI("NetworkSearchHandler::TimezoneRefresh slotId:%{public}d", slotId_);
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->ProcessTimeZone();
    }
}

void NetworkSearchHandler::SendUpdateCellLocationRequest()
{
    std::vector<sptr<CellInformation>> cells;
    if (cellInfo_ != nullptr) {
        cellInfo_->GetCellInfoList(cells);
    }
    uint32_t curTime = (uint32_t)time(0);
    if ((curTime - lastCellRequestTime_) < cellRequestMinInterval_ && cells.size() != 0) {
        TELEPHONY_LOGE("NetworkSearchHandler::SendUpdateCellLocationRequest interval is too short");
        return;
    }
    TELEPHONY_LOGI("NetworkSearchHandler::SendUpdateCellLocationRequest slotId:%{public}d", slotId_);
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CURRENT_CELL_INFO);
    if (event != nullptr && telRilManager != nullptr) {
        lastCellRequestTime_ = curTime;
        event->SetOwner(shared_from_this());
        telRilManager->GetCurrentCellInfo(slotId_, event);
    }
}

void NetworkSearchHandler::UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac)
{
    TELEPHONY_LOGI("NetworkSearchHandler::UpdateCellLocation slotId:%{public}d", slotId_);
    if (cellInfo_ != nullptr) {
        cellInfo_->UpdateCellLocation(techType, cellId, lac);
    }
}

PhoneType NetworkSearchHandler::GetPhoneType()
{
    TELEPHONY_LOGI("NetworkSearchHandler::GetPhoneType");
    if (radioInfo_ != nullptr) {
        return radioInfo_->GetPhoneType();
    }
    return PhoneType::PHONE_TYPE_IS_NONE;
}

void NetworkSearchHandler::RadioChannelConfigInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessChannelConfigInfo(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::ProcessChannelConfigInfo slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::DcPhysicalLinkActiveUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        return;
    }
    bool isActive = (event->GetParam() == 1);
    if (networkRegister_ != nullptr) {
        networkRegister_->DcPhysicalLinkActiveUpdate(isActive);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::DcPhysicalLinkActiveUpdate slotId:%{public}d active:%{public}s", slotId_,
        isActive ? "true" : "false");
}

void NetworkSearchHandler::UpdateImsServiceStatus(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (event == nullptr) {
        TELEPHONY_LOGE("UpdateImsServiceStatus event is null slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<ImsServiceStatus> imsServiceStatus = event->GetSharedObject<ImsServiceStatus>();
    std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState(slotId_);
    if (networkSearchState != nullptr) {
        networkSearchState->SetImsServiceStatus(*imsServiceStatus);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::UpdateImsServiceStatus slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::UpdateImsRegisterState(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (event == nullptr) {
        TELEPHONY_LOGE("UpdateImsRegisterState event is null slotId:%{public}d", slotId_);
        return;
    }
    auto registerInfo = event->GetSharedObject<int32_t>();
    bool isRegister = (*registerInfo == 1);
    std::shared_ptr<ImsServiceStatus> imsServiceStatus = event->GetSharedObject<ImsServiceStatus>();
    std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState(slotId_);
    if (networkSearchState != nullptr) {
        networkSearchState->SetImsStatus(isRegister);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::UpdateImsRegisterState slotId:%{public}d isRegister:%{public}s", slotId_,
        isRegister ? "true" : "false");
}

void NetworkSearchHandler::RadioVoiceTechChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (radioInfo_ != nullptr) {
        radioInfo_->ProcessVoiceTechChange(event);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::RadioVoiceTechChange");
}

void NetworkSearchHandler::AutoTimeChange(const AppExecFwk::InnerEvent::Pointer &)
{
    TELEPHONY_LOGI("NetworkSearchHandler::AutoTimeChange");
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->AutoTimeChange();
    }
}

void NetworkSearchHandler::AutoTimeZoneChange(const AppExecFwk::InnerEvent::Pointer &)
{
    TELEPHONY_LOGI("NetworkSearchHandler::AutoTimeZoneChange");
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->AutoTimeZoneChange();
    }
}

void NetworkSearchHandler::AirplaneModeChange(const AppExecFwk::InnerEvent::Pointer &)
{
    TELEPHONY_LOGI("NetworkSearchHandler::AirplaneModeChange");
    if (radioInfo_ != nullptr) {
        radioInfo_->AirplaneModeChange();
    }
}

void NetworkSearchHandler::SetCellRequestMinInterval(uint32_t minInterval)
{
    cellRequestMinInterval_ = minInterval;
}

NetworkSearchHandler::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    std::shared_ptr<OperatorName> &operatorName) : opName_(operatorName)
{}

void NetworkSearchHandler::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        TELEPHONY_LOGE("systemAbilityId is not COMMON_EVENT_SERVICE_ID");
        return;
    }
    if (opName_ == nullptr) {
        TELEPHONY_LOGE("OnAddSystemAbility COMMON_EVENT_SERVICE_ID opName_ is nullptr");
        return;
    }
    bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(opName_);
    TELEPHONY_LOGI("NetworkSearchHandler::OnAddSystemAbility subscribeResult = %{public}d", subscribeResult);
}

void NetworkSearchHandler::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        TELEPHONY_LOGE("systemAbilityId is not COMMON_EVENT_SERVICE_ID");
        return;
    }
    if (opName_ == nullptr) {
        TELEPHONY_LOGE("OnRemoveSystemAbility COMMON_EVENT_SERVICE_ID opName_ is nullptr");
        return;
    }
    bool subscribeResult = CommonEventManager::UnSubscribeCommonEvent(opName_);
    TELEPHONY_LOGI("NetworkSearchHandler::OnRemoveSystemAbility subscribeResult = %{public}d", subscribeResult);
}
} // namespace Telephony
} // namespace OHOS
