/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "core_service_errors.h"
#include "core_manager_inner.h"
#include "ims_core_service_client.h"
#include "mcc_pool.h"
#include "network_search_manager.h"
#include "resource_utils.h"
#include "satellite_service_client.h"
#include "telephony_ext_wrapper.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
std::mutex NetworkSearchManager::ctx_;
bool NetworkSearchManager::ssbResponseReady_ = false;
std::condition_variable NetworkSearchManager::cv_;
static const int32_t REQ_INTERVAL = 30;
const int32_t SATELLITE_STATUS_ON = 1;
const size_t MCC_LEN = 3;
const std::string PERMISSION_PUBLISH_SYSTEM_EVENT = "ohos.permission.PUBLISH_SYSTEM_COMMON_EVENT";
const std::map<uint32_t, NetworkSearchHandler::NsHandlerFunc> NetworkSearchHandler::memberFuncMap_ = {
    { RadioEvent::RADIO_SIM_STATE_CHANGE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->SimStateChange(event);
        } },
    { RadioEvent::RADIO_IMSI_LOADED_READY,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->ImsiLoadedReady(event);
        } },
    { RadioEvent::RADIO_SIM_RECORDS_LOADED,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->SimRecordsLoaded(event);
        } },
    { RadioEvent::RADIO_STATE_CHANGED,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioStateChange(event);
        } },
    { RadioEvent::RADIO_NETWORK_STATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->GetNetworkStateInfo(event);
        } },
    { RadioEvent::RADIO_RESTRICTED_STATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioRestrictedState(event);
        } },
    { RadioEvent::RADIO_DATA_REG_STATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioRilDataRegState(event);
        } },
    { RadioEvent::RADIO_VOICE_REG_STATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioRilVoiceRegState(event);
        } },
    { RadioEvent::RADIO_GET_SIGNAL_STRENGTH,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioSignalStrength(event);
        } },
    { RadioEvent::RADIO_SIGNAL_STRENGTH_UPDATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioSignalStrength(event);
        } },
    { RadioEvent::RADIO_OPERATOR,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioRilOperator(event);
        } },
    { RadioEvent::RADIO_NETWORK_SEARCH_RESULT,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->NetworkSearchResult(event);
        } },
    { RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->GetNetworkSelectionModeResponse(event);
        } },
    { RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->SetNetworkSelectionModeResponse(event);
        } },
    { RadioEvent::RADIO_GET_STATUS,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->GetRadioStateResponse(event);
        } },
    { RadioEvent::RADIO_SET_STATUS,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->SetRadioStateResponse(event);
        } },
    { RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->SetPreferredNetworkResponse(event);
        } },
    { RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->GetPreferredNetworkResponse(event);
        } },
    { RadioEvent::RADIO_NETWORK_TIME_UPDATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioNitzUpdate(event);
        } },
    { RadioEvent::RADIO_IMS_SERVICE_STATUS_UPDATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->UpdateImsServiceStatus(event);
        } },
    { RadioEvent::RADIO_IMS_REGISTER_STATE_UPDATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->UpdateImsRegisterState(event);
        } },
    { RadioEvent::RADIO_GET_IMEI,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioGetImei(event);
        } },
    { RadioEvent::RADIO_GET_IMEISV,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioGetImeiSv(event);
        } },
    { RadioEvent::RADIO_GET_MEID,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioGetMeid(event);
        } },
    { RadioEvent::RADIO_GET_NEIGHBORING_CELL_INFO,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioGetNeighboringCellInfo(event);
        } },
    { RadioEvent::RADIO_GET_CURRENT_CELL_INFO,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioGetCurrentCellInfo(event);
        } },
    { RadioEvent::RADIO_CURRENT_CELL_UPDATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioCurrentCellInfoUpdate(event);
        } },
    { RadioEvent::RADIO_CHANNEL_CONFIG_UPDATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioChannelConfigInfo(event);
        } },
    { RadioEvent::RADIO_VOICE_TECH_CHANGED,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioVoiceTechChange(event);
        } },
    { RadioEvent::RADIO_GET_VOICE_TECH,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioVoiceTechChange(event);
        } },
    { RadioEvent::RADIO_SET_DATA_CONNECT_ACTIVE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->DcPhysicalLinkActiveUpdate(event);
        } },
    { RadioEvent::RADIO_GET_BASEBAND_VERSION,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioGetBasebandVersion(event);
        } },
    { RadioEvent::RADIO_SET_NR_OPTION_MODE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->SetNrOptionModeResponse(event);
        } },
    { RadioEvent::RADIO_GET_NR_OPTION_MODE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->GetNrOptionModeResponse(event);
        } },
    { RadioEvent::RADIO_GET_RRC_CONNECTION_STATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioGetRrcConnectionState(event);
        } },
    { RadioEvent::RADIO_RRC_CONNECTION_STATE_UPDATE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioGetRrcConnectionState(event);
        } },
    { RadioEvent::NOTIFY_STATE_CHANGE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->NotifyStateChange(event);
        } },
    { RadioEvent::DELAY_NOTIFY_STATE_CHANGE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->HandleDelayNotifyEvent(event);
        } },
    { RadioEvent::RADIO_RESIDENT_NETWORK_CHANGE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->RadioResidentNetworkChange(event);
        } },
    { RadioEvent::RADIO_GET_NR_SSBID_INFO,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->GetNrSsbIdResponse(event);
        } },
    { SettingEventCode::MSG_AUTO_TIME,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->AutoTimeChange(event);
        } },
    { SettingEventCode::MSG_AUTO_TIMEZONE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->AutoTimeZoneChange(event);
        } },
    { SettingEventCode::MSG_AUTO_AIRPLANE_MODE,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->AirplaneModeChange(event);
        } },
    { RadioEvent::SATELLITE_STATUS_CHANGED,
        [](NetworkSearchHandler *handler, const AppExecFwk::InnerEvent::Pointer &event) {
            handler->SatelliteStatusChanged(event);
        } }
};

NetworkSearchHandler::NetworkSearchHandler(const std::weak_ptr<NetworkSearchManager> &networkSearchManager,
    const std::weak_ptr<ITelRilManager> &telRilManager, const std::weak_ptr<ISimManager> &simManager, int32_t slotId)
    : TelEventHandler("NetworkSearchManager_" + std::to_string(slotId)), networkSearchManager_(networkSearchManager),
      telRilManager_(telRilManager), simManager_(simManager), slotId_(slotId)
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
    ResourceUtils::Get().GetBooleanValueByName(ResourceUtils::IS_CS_CAPABLE, isCsCapable_);
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
    if (!InitOperatorName() || !InitSettingUtils()) {
        return false;
    }
    SubscribeSystemAbility();
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
    if (!SubModuleInit()) {
        return false;
    }
    signalInfo_->InitSignalBar();
    RegisterEvents();
    return true;
}

bool NetworkSearchHandler::SubModuleInit()
{
    cellInfo_ = std::make_unique<CellInfo>(networkSearchManager_, slotId_);
    if (cellInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to create new CellInfo slotId:%{public}d", slotId_);
        return false;
    }
    nrSsbInfo_ = std::make_unique<NrSsbInfo>(networkSearchManager_, slotId_);
    if (nrSsbInfo_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NrSsbInfo slotId:%{public}d", slotId_);
        return false;
    }
    return true;
}

bool NetworkSearchHandler::InitOperatorName()
{
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_LOCALE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    operatorName_ = std::make_shared<OperatorName>(
        subscriberInfo, nsm->GetNetworkSearchState(slotId_), nsm->GetSimManager(), networkSearchManager_, slotId_);
    if (operatorName_ == nullptr) {
        TELEPHONY_LOGE("failed to create new operatorName slotId:%{public}d", slotId_);
        return false;
    }
    return true;
}

bool NetworkSearchHandler::InitSettingUtils()
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(SettingUtils::COMMON_EVENT_DATA_SHARE_READY);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscriberInfo.SetPermission(PERMISSION_PUBLISH_SYSTEM_EVENT);
    SettingUtils::GetInstance()->SetCommonEventSubscribeInfo(subscriberInfo);
    if (SettingUtils::GetInstance()->GetCommonEventSubscriber() == nullptr) {
        TELEPHONY_LOGE("InitSettingUtils fail! slotId:%{public}d", slotId_);
        return false;
    }
    return true;
}

void NetworkSearchHandler::SubscribeSystemAbility()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(operatorName_);
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("SubscribeSystemAbility  samgrProxy or statusChangeListener_ is nullptr");
    } else {
        int32_t commonEventResult = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
        int32_t DataShareResult = samgrProxy->SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID,
            statusChangeListener_);
        TELEPHONY_LOGI("SubscribeSystemAbility  COMMON_EVENT_SERVICE_ID result:%{public}d"
            "DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID result:%{public}d.", commonEventResult, DataShareResult);
    }
}

void NetworkSearchHandler::RegisterEvents()
{
    TELEPHONY_LOGD("NetworkSearchHandler::RegisterEvents start slotId:%{public}d", slotId_);
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
            telRilManager->RegisterCoreNotify(
                slotId_, shared_from_this(), RadioEvent::RADIO_RRC_CONNECTION_STATE_UPDATE, nullptr);
            telRilManager->RegisterCoreNotify(
                slotId_, shared_from_this(), RadioEvent::RADIO_RESIDENT_NETWORK_CHANGE, nullptr);
        }
    }
    {
        if (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED)) {
            std::shared_ptr<SatelliteServiceClient> satelliteClient =
                DelayedSingleton<SatelliteServiceClient>::GetInstance();
            satelliteClient->AddNetworkHandler(slotId_, std::static_pointer_cast<TelEventHandler>(shared_from_this()));
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

void NetworkSearchHandler::RegisterSatelliteCallback()
{
    if (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED)) {
        satelliteCallback_ =
            std::make_unique<SatelliteCoreCallback>(std::static_pointer_cast<TelEventHandler>(shared_from_this()))
                .release();
        std::shared_ptr<SatelliteServiceClient> satelliteClient =
            DelayedSingleton<SatelliteServiceClient>::GetInstance();
        satelliteClient->RegisterCoreNotify(slotId_, RadioEvent::RADIO_SET_STATUS, satelliteCallback_);
        satelliteClient->RegisterCoreNotify(slotId_, RadioEvent::RADIO_STATE_CHANGED, satelliteCallback_);
        satelliteClient->RegisterCoreNotify(slotId_, RadioEvent::SATELLITE_STATUS_CHANGED, satelliteCallback_);
    }
}

void NetworkSearchHandler::UnregisterSatelliteCallback()
{
    if (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED)) {
        satelliteCallback_ = nullptr;
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
            telRilManager->UnRegisterCoreNotify(
                slotId_, shared_from_this(), RadioEvent::RADIO_RRC_CONNECTION_STATE_UPDATE);
            telRilManager->UnRegisterCoreNotify(slotId_, shared_from_this(), RadioEvent::RADIO_RESIDENT_NETWORK_CHANGE);
        }
    }
    if (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED) &&
        satelliteCallback_ != nullptr) {
        std::shared_ptr<SatelliteServiceClient> satelliteClient =
            DelayedSingleton<SatelliteServiceClient>::GetInstance();
        satelliteClient->UnRegisterCoreNotify(slotId_, RadioEvent::RADIO_STATE_CHANGED);
        satelliteClient->UnRegisterCoreNotify(slotId_, RadioEvent::RADIO_SET_STATUS);
        satelliteClient->UnRegisterCoreNotify(slotId_, RadioEvent::SATELLITE_STATUS_CHANGED);
    }
}

void NetworkSearchHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        return;
    }
    auto msgType = event->GetInnerEventId();
    TELEPHONY_LOGD(
        "NetworkSearchHandler::ProcessEvent received event slotId:%{public}d msgType:%{public}d", slotId_, msgType);
    auto itFunc = memberFuncMap_.find(static_cast<RadioEvent>(msgType));
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            memberFunc(this, event);
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
        int32_t csRadioTech = 0;
        int32_t psRadioTech = 0;
        networkSearchManager->GetCsRadioTech(slotId_, csRadioTech);
        networkSearchManager->GetPsRadioTech(slotId_, psRadioTech);
        UpdatePhone(static_cast<RadioTech>(csRadioTech), static_cast<RadioTech>(psRadioTech));
    }

    if (operatorName_ != nullptr) {
        operatorName_->NotifySpnChanged();
    }
}

void NetworkSearchHandler::GetDeviceId()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::GetDeviceId failed to get NetworkSearchManager");
        return;
    }
    networkSearchManager->UpdateDeviceId(slotId_);
}

void NetworkSearchHandler::RadioStateChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        return;
    }
    std::shared_ptr<Int32Parcel> object = event->GetSharedObject<Int32Parcel>();
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
    TELEPHONY_LOGI("NetworkSearchHandler::RadioState change: %{public}d, slotId: %{public}d", radioState, slotId_);
    switch (radioState) {
        case CORE_SERVICE_POWER_NOT_AVAILABLE:
        case CORE_SERVICE_POWER_OFF: {
            RadioOffOrUnavailableState(radioState);
            break;
        }
        case CORE_SERVICE_POWER_ON: {
            firstInit_ = false;
            InitGetNetworkSelectionMode();
            SetRadioOffWhenAirplaneIsOn();
            SetRadioOffWhenSimDeactive();
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
        networkSearchManager->InitSimRadioProtocol(slotId_);
        GetDeviceId();
    } else {
        networkSearchManager->SetRadioStateValue(slotId_, CORE_SERVICE_POWER_NOT_AVAILABLE);
    }
    if (operatorName_ != nullptr) {
        operatorName_->NotifySpnChanged();
    }
}

void NetworkSearchHandler::SetRadioOffWhenAirplaneIsOn()
{
    bool isAirplaneMode = false;
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::SetRadioOffWhenAirplaneIsOn failed to get NetworkSearchManager");
        return;
    }
    if (networkSearchManager->GetAirplaneMode(isAirplaneMode) == TELEPHONY_SUCCESS && isAirplaneMode) {
        networkSearchManager->SetRadioState(slotId_, static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_OFF), 0);
    }
}

void NetworkSearchHandler::SetRadioOffWhenSimDeactive()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::SetRadioOffWhenSimDeactive failed to get NetworkSearchManager");
        return;
    }
    auto simManager = networkSearchManager->GetSimManager();
    if (simManager == nullptr) {
        return;
    }
    bool hasSim = false;
    simManager->HasSimCard(slotId_, hasSim);
    TELEPHONY_LOGI("SetRadioOffWhenSimDeactive slotId: %{public}d, IsSetActiveSimInProgress: %{public}d, IsSimActive:"
        " %{public}d, IsPowerOnPrimaryRadioWhenNoSim: %{public}d",
        slotId_, simManager->IsSetActiveSimInProgress(slotId_),
        simManager->IsSimActive(slotId_), IsPowerOnPrimaryRadioWhenNoSim());
    if (TELEPHONY_EXT_WRAPPER.isVSimEnabled_ && TELEPHONY_EXT_WRAPPER.isVSimEnabled_()
        && slotId_ == static_cast<int>(SimSlotType::VSIM_SLOT_ID)) {
        TELEPHONY_LOGI("vsim not handle power Radio");
        return;
    }
    if (hasSim && !IsPowerOnPrimaryRadioWhenNoSim()
        && !simManager->IsSetActiveSimInProgress(slotId_) && !simManager->IsSimActive(slotId_)) {
        networkSearchManager->SetRadioState(slotId_, static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_OFF), 0);
    }
}

void NetworkSearchHandler::RadioRestrictedState(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioRestrictedState event is nullptr!");
        return;
    }
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessRestrictedState(event);
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioRestrictedState slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::RadioRilDataRegState(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioRilDataRegState event is nullptr!");
        return;
    }
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr ||
        networkSearchManager->GetRadioState(slotId_) == static_cast<int>(ModemPowerState::CORE_SERVICE_POWER_OFF)) {
        TELEPHONY_LOGI("radio is power off, no need update data reg state");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    psRegStatusResultInfo_ = event->GetSharedObject<PsRegStatusResultInfo>();
    if (psRegStatusResultInfo_ == nullptr) {
        TELEPHONY_LOGE("psRegStatusResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (psRegStatusResultInfo_->flag != networkSearchManager->GetSerialNum(slotId_)) {
        TELEPHONY_LOGI("Aborting outdated ps registration event slotId:%{public}d", slotId_);
        return;
    }
    networkSearchManager->decMsgNum(slotId_);
    TelRilRegStatus regStatus = psRegStatusResultInfo_->regStatus;
    bool isEmergency = (regStatus == TelRilRegStatus::REG_MT_EMERGENCY) && isCsCapable_;
    if (networkSearchManager->CheckIsNeedNotify(slotId_) || isEmergency) {
        UpdateNetworkState();
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioRilDataRegState slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::RadioRilVoiceRegState(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioRilVoiceRegState event is nullptr!");
        return;
    }
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr ||
        networkSearchManager->GetRadioState(slotId_) == static_cast<int>(ModemPowerState::CORE_SERVICE_POWER_OFF)) {
        TELEPHONY_LOGI("radio is power off, no need update voice reg state");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    csRegStatusInfo_ = event->GetSharedObject<CsRegStatusInfo>();
    if (csRegStatusInfo_ == nullptr) {
        TELEPHONY_LOGE("csRegStatusResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (csRegStatusInfo_->flag != networkSearchManager->GetSerialNum(slotId_)) {
        TELEPHONY_LOGI("Aborting outdated cs registration event slotId:%{public}d", slotId_);
        return;
    }
    networkSearchManager->decMsgNum(slotId_);
    TelRilRegStatus regStatus = csRegStatusInfo_->regStatus;
    bool isEmergency = (regStatus == TelRilRegStatus::REG_MT_EMERGENCY) && isCsCapable_;
    if (networkSearchManager->CheckIsNeedNotify(slotId_) || isEmergency) {
        UpdateNetworkState();
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioRilVoiceRegState slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::RadioSignalStrength(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioSignalStrength event is nullptr!");
        return;
    }
    if (signalInfo_ != nullptr) {
        signalInfo_->ProcessSignalIntensity(slotId_, event);
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioSignalStrength slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::RadioRilOperator(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioRilOperator event is nullptr!");
        return;
    }
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr ||
        networkSearchManager->GetRadioState(slotId_) == static_cast<int>(ModemPowerState::CORE_SERVICE_POWER_OFF)) {
        TELEPHONY_LOGI("radio is power off, no need update operator info");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    operatorInfoResult_ = event->GetSharedObject<OperatorInfoResult>();
    if (operatorInfoResult_ == nullptr) {
        TELEPHONY_LOGE("operatorInfoResult is nullptr slotId:%{public}d", slotId_);
        return;
    }
    if (operatorInfoResult_->flag == networkSearchManager->GetSerialNum(slotId_)) {
        networkSearchManager->decMsgNum(slotId_);
        if (networkSearchManager->CheckIsNeedNotify(slotId_)) {
            UpdateNetworkState();
        }
    } else if (operatorInfoResult_->flag == NetworkSearchManagerInner::SERIAL_NUMBER_EXEMPT) {
        if (operatorName_ != nullptr) {
            operatorName_->HandleOperatorInfo(operatorInfoResult_);
            networkSearchManager->ProcessNotifyStateChangeEvent(slotId_);
        }
    } else {
        TELEPHONY_LOGI("Aborting outdated operator info event slotId:%{public}d", slotId_);
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioRilOperator slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::UpdateNetworkState()
{
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessPsRegister(psRegStatusResultInfo_);
        networkRegister_->ProcessCsRegister(csRegStatusInfo_);
    }
    if (operatorName_ != nullptr) {
        operatorName_->HandleOperatorInfo(operatorInfoResult_);
        operatorName_->TrySetLongOperatorNameWithTranslation();
    }
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        return;
    }
    networkSearchManager->ProcessNotifyStateChangeEvent(slotId_);
    if (networkSearchManager->GetSkipUnsolRptFlag(slotId_) && networkSearchManager->CheckIsNeedNotify(slotId_)) {
        TELEPHONY_LOGI("Re-trigger RadioOnState slotId:%{public}d", slotId_);
        RadioOnState();
        networkSearchManager->SetSkipUnsolRptFlag(slotId_, false);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::UpdateNetworkState slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::GetRilSignalIntensity(bool checkTime)
{
    TELEPHONY_LOGD("NetworkSearchHandler::GetRilSignalIntensity start...... slotId:%{public}d", slotId_);
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
        case CORE_SERVICE_POWER_ON: {
            firstInit_ = false;
            RadioOnState(false);
            break;
        }
        default:
            TELEPHONY_LOGI("Unhandled message with number: %{public}d slotId:%{public}d", radioState, slotId_);
            break;
    }
}

void NetworkSearchHandler::RadioOnWhenHasSim(std::shared_ptr<NetworkSearchManager> &networkSearchManager,
    int32_t radioState) const
{
    bool isAirplaneMode = false;
    if (networkSearchManager->GetAirplaneMode(isAirplaneMode) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("RadioOffOrUnavailableState GetAirplaneMode fail slotId: %{public}d", slotId_);
    }
    auto simManager = networkSearchManager->GetSimManager();
    if (simManager == nullptr) {
        return;
    }
    bool hasSim = false;
    simManager->HasSimCard(slotId_, hasSim);
    bool isInModem2Optimization = TELEPHONY_EXT_WRAPPER.isInModem2Optimization_ != nullptr &&
        TELEPHONY_EXT_WRAPPER.isInModem2Optimization_(slotId_);
    TELEPHONY_LOGI("soltid: %{public}d, IsSimActive: %{public}d, hasSim: %{public}d, isAirplaneMode: "
        "%{public}d, IsSetActiveSimInProgress: %{public}d, IsPowerOnPrimaryRadioWhenNoSim: %{public}d"
        "isInModem2Optimization: %{public}d",
        slotId_, simManager->IsSimActive(slotId_), hasSim, isAirplaneMode,
        simManager->IsSetActiveSimInProgress(slotId_), IsPowerOnPrimaryRadioWhenNoSim(), isInModem2Optimization);
    bool hasSimAndActive =
        (hasSim && (!simManager->IsSetActiveSimInProgress(slotId_) && simManager->IsSimActive(slotId_)));
    bool primarySimNoSim = (!hasSim && IsPowerOnPrimaryRadioWhenNoSim());
    if (!isAirplaneMode && (!GetDynamicPowerOffModeSwitch()) && (hasSimAndActive || primarySimNoSim) &&
        radioState == CORE_SERVICE_POWER_OFF && !IsSatelliteOn() && !isInModem2Optimization) {
        networkSearchManager->SetRadioState(slotId_, static_cast<bool>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
    }
}

void NetworkSearchHandler::RadioOffOrUnavailableState(int32_t radioState) const
{
    TELEPHONY_LOGD("RadioOffOrUnavailableState enter... slotId:%{public}d", slotId_);
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("RadioOffOrUnavailableState NetworkSearchHandler is null slotId:%{public}d", slotId_);
        return;
    }
    networkSearchManager->SetResidentNetworkNumeric(slotId_, "");
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
    ClearSignalAndCellInfoList();
    networkSearchState->NotifyStateChange();
    networkSearchManager->UpdateNrOptionMode(slotId_, NrMode::NR_MODE_UNKNOWN);

    if (!TELEPHONY_EXT_WRAPPER.isInEnaDisableVSim_ || !TELEPHONY_EXT_WRAPPER.isInEnaDisableVSim_()) {
        RadioOnWhenHasSim(networkSearchManager, radioState);
    }

    sptr<NetworkSearchCallBackBase> cellularData = networkSearchManager->GetCellularDataCallBack();
    if (cellularData) {
        cellularData->ClearCellularDataConnections(slotId_);
        TELEPHONY_LOGD("RadioOffOrUnavailableState ClearCellularDataConnections");
    }
    sptr<NetworkSearchCallBackBase> cellularCall = networkSearchManager->GetCellularCallCallBack();
    if (cellularCall) {
        cellularCall->ClearCellularCallList(slotId_);
        TELEPHONY_LOGD("RadioOffOrUnavailableState ClearCellularCallList");
    }
}

void NetworkSearchHandler::RadioOnState(bool forceNotify)
{
    auto networkSearchManager = networkSearchManager_.lock();
    int64_t serialNum = NetworkSearchManagerInner::SERIAL_NUMBER_DEFAULT;
    if (networkSearchManager != nullptr) {
        if (!networkSearchManager->CheckIsNeedNotify(slotId_) && !forceNotify) {
            networkSearchManager->SetSkipUnsolRptFlag(slotId_, true);
            TELEPHONY_LOGI("Last request not finish slotId:%{public}d", slotId_);
            return;
        }
        networkSearchManager->InitMsgNum(slotId_);
        serialNum = networkSearchManager->IncreaseSerialNum(slotId_);
        if (serialNum == NetworkSearchManagerInner::SERIAL_NUMBER_DEFAULT) {
            TELEPHONY_LOGE("Invalid serial number slotId:%{public}d", slotId_);
            return;
        }
    }
    GetRilOperatorInfo(serialNum, false);
    GetRilPsRegistration(serialNum, false);
    GetRilCsRegistration(serialNum, false);
    SendUpdateCellLocationRequest();
    GetRilSignalIntensity(false);
}

void NetworkSearchHandler::GetRadioStateResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::GetRadioStateResponse event is nullptr!");
        return;
    }
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo is null slotId:%{public}d", slotId_);
        return;
    }
    radioInfo_->ProcessGetRadioState(event);
}

void NetworkSearchHandler::SetRadioStateResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::SetRadioStateResponse event is nullptr!");
        return;
    }
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioInfo is null slotId:%{public}d", slotId_);
        return;
    }
    radioInfo_->ProcessSetRadioState(event);
}

void NetworkSearchHandler::GetRilOperatorInfo(int64_t serialNum, bool checkTime)
{
    TELEPHONY_LOGD("NetworkSearchHandler::GetOperatorInfo start slotId:%{public}d", slotId_);
    if (!TimeOutCheck(lastTimeOperatorReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR, serialNum);
    if (event != nullptr) {
        event->SetOwner(shared_from_this());
        std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
        if (telRilManager != nullptr) {
            telRilManager->GetOperatorInfo(slotId_, event);
        }
    }
}

void NetworkSearchHandler::GetRilPsRegistration(int64_t serialNum, bool checkTime)
{
    TELEPHONY_LOGD("NetworkSearchHandler::GetPsRegStatus start slotId:%{public}d", slotId_);
    if (!TimeOutCheck(lastTimePsRegistrationReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_DATA_REG_STATE, serialNum);
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

void NetworkSearchHandler::GetRilCsRegistration(int64_t serialNum, bool checkTime)
{
    TELEPHONY_LOGD("NetworkSearchHandler::GetCsRegStatus start slotId:%{public}d", slotId_);
    if (!TimeOutCheck(lastTimeCsRegistrationReq_, checkTime)) {
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_VOICE_REG_STATE, serialNum);
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
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::NetworkSearchResult event is nullptr!");
        return;
    }
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchResult NetworkSelection is null slotId:%{public}d", slotId_);
        return;
    }
    networkSelection_->ProcessNetworkSearchResult(event);
}

void NetworkSearchHandler::SetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::SetNetworkSelectionModeResponse event is nullptr!");
        return;
    }
    if (networkSelection_ == nullptr) {
        TELEPHONY_LOGE("SetNetworkSelectionModeResponse NetworkSelection is null slotId:%{public}d", slotId_);
        return;
    }
    networkSelection_->ProcessSetNetworkSelectionMode(event);
}

void NetworkSearchHandler::GetNetworkSelectionModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::GetNetworkSelectionModeResponse event is nullptr!");
        return;
    }
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
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::GetPreferredNetworkResponse event is nullptr!");
        return;
    }
    if (networkType_ != nullptr) {
        networkType_->ProcessGetPreferredNetwork(event);
    } else {
        TELEPHONY_LOGE("GetPreferredNetworkResponse NetworkType is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::SetPreferredNetworkResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::SetPreferredNetworkResponse event is nullptr!");
        return;
    }
    if (networkType_ != nullptr) {
        networkType_->ProcessSetPreferredNetwork(event);
    } else {
        TELEPHONY_LOGE("SetPreferredNetworkResponse NetworkType is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioNitzUpdate event is nullptr!");
        return;
    }
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->ProcessNitzUpdate(event);
    } else {
        TELEPHONY_LOGE("RadioNitzUpdate nitzUpdate is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioGetImei(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioGetImei event is nullptr!");
        return;
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioGetImei start slotId:%{public}d", slotId_);
    if (radioInfo_ != nullptr) {
        radioInfo_->ProcessGetImei(event);
    } else {
        TELEPHONY_LOGE("RadioGetImei radioInfo_ is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioGetImeiSv(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioGetImeiSv event is nullptr!");
        return;
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioGetImeiSv start slotId:%{public}d", slotId_);
    if (radioInfo_ != nullptr) {
        radioInfo_->ProcessGetImeiSv(event);
    } else {
        TELEPHONY_LOGE("RadioGetImeiSv radioInfo_ is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioGetMeid(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGD("NetworkSearchHandler::RadioGetMeid start slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioGetMeid event is nullptr!");
        return;
    }
    if (radioInfo_ != nullptr) {
        radioInfo_->ProcessGetMeid(event);
    } else {
        TELEPHONY_LOGE("RadioGetMeid radioInfo_ is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::UpdatePhone(RadioTech csRadioTech, const RadioTech &psRadioTech) const
{
    if (radioInfo_ != nullptr) {
        radioInfo_->UpdatePhone(csRadioTech, psRadioTech);
    } else {
        TELEPHONY_LOGE("UpdatePhone networkType is null slotId:%{public}d", slotId_);
    }
}

void NetworkSearchHandler::RadioGetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioGetCurrentCellInfo event is nullptr!");
        return;
    }
    if (cellInfo_ != nullptr) {
        cellInfo_->ProcessCurrentCellInfo(event);
    }
}

void NetworkSearchHandler::RadioCurrentCellInfoUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioCurrentCellInfoUpdate event is nullptr!");
        return;
    }
    if (cellInfo_ != nullptr) {
        cellInfo_->ProcessCurrentCellInfo(event);
    }
}

void NetworkSearchHandler::RadioGetNeighboringCellInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioGetNeighboringCellInfo event is nullptr!");
        return;
    }
    if (cellInfo_ != nullptr) {
        cellInfo_->ProcessNeighboringCellInfo(event);
    }
}

int32_t NetworkSearchHandler::GetCellInfoList(std::vector<sptr<CellInformation>> &cells)
{
    TELEPHONY_LOGD("NetworkSearchHandler::GetCellInfoList slotId:%{public}d", slotId_);
    if (cellInfo_ != nullptr) {
        cellInfo_->GetCellInfoList(cells);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t NetworkSearchHandler::GetNeighboringCellInfoList(std::vector<sptr<CellInformation>> &cells)
{
    TELEPHONY_LOGD("NetworkSearchHandler::GetNeighboringCellInfoList slotId:%{public}d", slotId_);
    if (cellInfo_ != nullptr) {
        cellInfo_->GetNeighboringCellInfoList(cells);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

sptr<CellLocation> NetworkSearchHandler::GetCellLocation()
{
    TELEPHONY_LOGD("NetworkSearchHandler::GetCellLocation slotId:%{public}d", slotId_);
    if (cellInfo_ != nullptr) {
        return cellInfo_->GetCellLocation();
    }
    return nullptr;
}

void NetworkSearchHandler::TimezoneRefresh()
{
    TELEPHONY_LOGD("NetworkSearchHandler::TimezoneRefresh slotId:%{public}d", slotId_);
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->ProcessTimeZone();
    }
}

int32_t NetworkSearchHandler::SendUpdateCellLocationRequest()
{
    std::vector<sptr<CellInformation>> cells;
    if (cellInfo_ != nullptr) {
        cellInfo_->GetCellInfoList(cells);
    }
    uint32_t curTime = static_cast<uint32_t>(time(0));
    if ((curTime < cellRequestMinInterval_ + lastCellRequestTime_) && cells.size() != 0) {
        TELEPHONY_LOGE("NetworkSearchHandler::SendUpdateCellLocationRequest interval is too short");
        return TELEPHONY_ERR_SUCCESS;
    }
    TELEPHONY_LOGD("NetworkSearchHandler::SendUpdateCellLocationRequest slotId:%{public}d", slotId_);
    std::shared_ptr<ITelRilManager> telRilManager = telRilManager_.lock();
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_CURRENT_CELL_INFO);
    if (event != nullptr && telRilManager != nullptr) {
        lastCellRequestTime_ = curTime;
        event->SetOwner(shared_from_this());
        telRilManager->GetCurrentCellInfo(slotId_, event);
    }
    auto event2 = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_GET_NEIGHBORING_CELL_INFO);
    if (event2 != nullptr && telRilManager != nullptr) {
        event2->SetOwner(shared_from_this());
        telRilManager->GetNeighboringCellInfoList(slotId_, event2);
    }
    return TELEPHONY_ERR_SUCCESS;
}

void NetworkSearchHandler::UpdateCellLocation(int32_t techType, int32_t cellId, int32_t lac)
{
    TELEPHONY_LOGD("NetworkSearchHandler::UpdateCellLocation slotId:%{public}d", slotId_);
    if (cellInfo_ != nullptr) {
        cellInfo_->UpdateCellLocation(techType, cellId, lac);
    }
}

PhoneType NetworkSearchHandler::GetPhoneType()
{
    TELEPHONY_LOGD("NetworkSearchHandler::GetPhoneType");
    if (radioInfo_ != nullptr) {
        return radioInfo_->GetPhoneType();
    }
    return PhoneType::PHONE_TYPE_IS_NONE;
}

void NetworkSearchHandler::RadioChannelConfigInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioChannelConfigInfo event is nullptr!");
        return;
    }
    if (networkRegister_ != nullptr) {
        networkRegister_->ProcessChannelConfigInfo(event);
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioChannelConfigInfo slotId:%{public}d", slotId_);
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

void NetworkSearchHandler::NotifyStateChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("NetworkSearchHandler::NotifyStateChange slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::NotifyStateChange event is nullptr!");
        return;
    }
    if (networkRegister_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::NotifyStateChange networkRegister_ is nullptr!");
        return;
    }
    networkRegister_->NotifyStateChange();
}

void NetworkSearchHandler::HandleDelayNotifyEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("NetworkSearchHandler::HandleDelayNotifyEvent slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::NotifyStateChange event is nullptr!");
        return;
    }
    if (networkRegister_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::NotifyStateChange networkRegister_ is nullptr!");
        return;
    }
    RevertLastTechnology();
    RadioOnState();
}

int32_t NetworkSearchHandler::HandleRrcStateChanged(int32_t status)
{
    TELEPHONY_LOGI("NetworkSearchHandler::HandleRrcStateChanged slotId:%{public}d", slotId_);
    if (networkRegister_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::HandleRrcStateChanged networkRegister_ is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    networkRegister_->HandleRrcStateChanged(status);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t NetworkSearchHandler::RevertLastTechnology()
{
    TELEPHONY_LOGI("NetworkSearchHandler::RevertLastTechnology slotId:%{public}d", slotId_);
    if (networkRegister_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RevertLastTechnology networkRegister_ is nullptr!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    networkRegister_->RevertLastTechnology();
    return TELEPHONY_ERR_SUCCESS;
}

void NetworkSearchHandler::UpdateImsServiceStatus(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (event == nullptr) {
        TELEPHONY_LOGE("UpdateImsServiceStatus event is null slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<ImsServiceStatus> imsServiceStatus = event->GetSharedObject<ImsServiceStatus>();
    if (imsServiceStatus == nullptr) {
        TELEPHONY_LOGE("UpdateImsServiceStatus imsServiceStatus is null slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState(slotId_);
    if (networkSearchState != nullptr) {
        networkSearchState->SetImsServiceStatus(*imsServiceStatus);
    }
    TELEPHONY_LOGD("NetworkSearchHandler::UpdateImsServiceStatus slotId:%{public}d", slotId_);
}

void NetworkSearchHandler::UpdateImsRegisterState(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (event == nullptr) {
        TELEPHONY_LOGE("UpdateImsRegisterState event is null slotId:%{public}d", slotId_);
        return;
    }
    auto registerInfo = event->GetSharedObject<int32_t>();
    if (registerInfo == nullptr) {
        TELEPHONY_LOGE("UpdateImsRegisterState registerInfo is null slotId:%{public}d", slotId_);
        return;
    }
    bool isRegister = (*registerInfo == 1);
    std::shared_ptr<NetworkSearchState> networkSearchState = networkSearchManager->GetNetworkSearchState(slotId_);
    if (networkSearchState != nullptr) {
        networkSearchState->SetImsStatus(isRegister);
    }
    TELEPHONY_LOGI("NetworkSearchHandler::UpdateImsRegisterState slotId:%{public}d isRegister:%{public}s", slotId_,
        isRegister ? "true" : "false");
}

void NetworkSearchHandler::RadioGetBasebandVersion(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioGetBasebandVersion event is nullptr!");
        return;
    }
    TELEPHONY_LOGD("RadioGetBasebandVersion start slotId:%{public}d", slotId_);
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioGetBasebandVersion RadioInfo is null slotId:%{public}d", slotId_);
        return;
    }
    radioInfo_->ProcessGetBasebandVersion(event);
}

void NetworkSearchHandler::SetNrOptionModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::SetNrOptionModeResponse event is nullptr!");
        return;
    }
    TELEPHONY_LOGD("SetNrOptionModeResponse start slotId:%{public}d", slotId_);
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("SetNrOptionModeResponse RadioInfo is null slotId:%{public}d", slotId_);
        return;
    }
    radioInfo_->ProcessSetNrOptionMode(event);
}

void NetworkSearchHandler::GetNrOptionModeResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::GetNrOptionModeResponse event is nullptr!");
        return;
    }
    TELEPHONY_LOGD("GetNrOptionModeResponse start slotId:%{public}d", slotId_);
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("GetNrOptionModeResponse RadioInfo is null slotId:%{public}d", slotId_);
        return;
    }
    radioInfo_->ProcessGetNrOptionMode(event);
}

void NetworkSearchHandler::RadioGetRrcConnectionState(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioGetRrcConnectionState event is nullptr!");
        return;
    }
    TELEPHONY_LOGD("RadioGetRrcConnectionState start slotId:%{public}d", slotId_);
    if (radioInfo_ == nullptr) {
        TELEPHONY_LOGE("RadioGetRrcConnectionState RadioInfo is null slotId:%{public}d", slotId_);
        return;
    }
    radioInfo_->ProcessGetRrcConnectionState(event);
}

void NetworkSearchHandler::RadioVoiceTechChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioVoiceTechChange event is nullptr!");
        return;
    }
    if (radioInfo_ != nullptr) {
        radioInfo_->ProcessVoiceTechChange(event);
    }
    TELEPHONY_LOGD("NetworkSearchHandler::RadioVoiceTechChange");
}

void NetworkSearchHandler::GetNrSsbIdResponse(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGD("Start slotId:%{public}d", slotId_);
    if (event == nullptr) {
        TELEPHONY_LOGE("Event is nullptr!");
        return;
    }
    if (nrSsbInfo_ == nullptr) {
        TELEPHONY_LOGE("NrSsbInfo is null");
        return;
    }
    if (nrSsbInfo_->ProcessGetNrSsbId(event)) {
        SyncGetSsbInfoResponse();
    }
}

void NetworkSearchHandler::SyncGetSsbInfoResponse()
{
    std::unique_lock<std::mutex> lck(NetworkSearchManager::ctx_);
    NetworkSearchManager::ssbResponseReady_ = true;
    TELEPHONY_LOGD("ssbResponseReady_ = %{public}d", NetworkSearchManager::ssbResponseReady_);
    NetworkSearchManager::cv_.notify_one();
}

int32_t NetworkSearchHandler::GetNrSsbId(const std::shared_ptr<NrSsbInformation> &nrCellSsbIdsInfo)
{
    TELEPHONY_LOGI("SlotId:%{public}d", slotId_);
    if (nrSsbInfo_ != nullptr) {
        if (nrSsbInfo_->FillNrSsbIdInformation(nrCellSsbIdsInfo)) {
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

void NetworkSearchHandler::AutoTimeChange(const AppExecFwk::InnerEvent::Pointer &)
{
    TELEPHONY_LOGD("NetworkSearchHandler::AutoTimeChange");
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->AutoTimeChange();
    }
}

void NetworkSearchHandler::AutoTimeZoneChange(const AppExecFwk::InnerEvent::Pointer &)
{
    TELEPHONY_LOGD("NetworkSearchHandler::AutoTimeZoneChange");
    if (nitzUpdate_ != nullptr) {
        nitzUpdate_->AutoTimeZoneChange();
    }
}

void NetworkSearchHandler::AirplaneModeChange(const AppExecFwk::InnerEvent::Pointer &)
{
    TELEPHONY_LOGD("NetworkSearchHandler::AirplaneModeChange");
    if (radioInfo_ != nullptr) {
        radioInfo_->AirplaneModeChange();
    }
}

void NetworkSearchHandler::RadioResidentNetworkChange(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioResidentNetworkChange event is nullptr!");
        return;
    }
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("RadioResidentNetworkChange networkSearchManager is nullptr");
        return;
    }
    auto object = event->GetSharedObject<std::string>();
    if (object == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioResidentNetworkChange object is nullptr!");
        networkSearchManager->SetResidentNetworkNumeric(slotId_, "");
        return;
    }
    std::string plmn = *object;
    networkSearchManager->SetResidentNetworkNumeric(slotId_, plmn);
    if (TELEPHONY_EXT_WRAPPER.updatePlmnExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.updatePlmnExt_(slotId_, plmn);
    }
    if (CheckRegistrationState(networkSearchManager)) {
        TELEPHONY_LOGE("RadioResidentNetworkChange RegState is in service");
        return;
    }
    std::string countryCode = "";
    if (plmn.length() >= MCC_LEN) {
        std::string mcc = plmn.substr(0, MCC_LEN);
        int32_t value = 0;
        if (StrToInt(mcc, value)) {
            countryCode = MccPool::MccCountryCode(value);
        } else {
            TELEPHONY_LOGE("RadioResidentNetworkChange parse Failed!! slotId:%{public}d", slotId_);
        }
    }
    if (countryCode.empty()) {
        TELEPHONY_LOGE("RadioResidentNetworkChange countryCode is empty");
        return;
    }
    TELEPHONY_LOGI("RadioResidentNetworkChange: update countryCode[%{public}s]", countryCode.c_str());
    if (TELEPHONY_EXT_WRAPPER.updateCountryCodeExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.updateCountryCodeExt_(slotId_, countryCode.c_str());
    } else {
        if (nitzUpdate_ != nullptr) {
            nitzUpdate_->UpdateCountryCode(countryCode);
        }
    }
}

bool NetworkSearchHandler::CheckRegistrationState(const std::shared_ptr<NetworkSearchManager> &networkSearchManager)
{
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::CheckRegistrationState manager is nullptr!");
        return false;
    }
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (networkSearchManager->GetCsRegState(slotId) ==
            static_cast<int32_t>(RegServiceState::REG_STATE_IN_SERVICE) ||
            networkSearchManager->GetPsRegState(slotId) ==
            static_cast<int32_t>(RegServiceState::REG_STATE_IN_SERVICE)) {
            return true;
        }
    }
    return false;
}

void NetworkSearchHandler::SatelliteStatusChanged(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::RadioResidentNetworkChange event is nullptr!");
        return;
    }
    auto satelliteStatus = event->GetSharedObject<SatelliteStatus>();
    if (satelliteStatus == nullptr) {
        TELEPHONY_LOGE("NetworkSearchHandler::satelliteStatus is nullptr!");
        return;
    }
    if (satelliteStatus->mode == SATELLITE_STATUS_ON) {
        std::shared_ptr<SatelliteServiceClient> satelliteClient =
            DelayedSingleton<SatelliteServiceClient>::GetInstance();
        satelliteClient->SetRadioState(
            satelliteStatus->slotId, static_cast<int32_t>(ModemPowerState::CORE_SERVICE_POWER_ON), 0);
    }
}

void NetworkSearchHandler::SetCellRequestMinInterval(uint32_t minInterval)
{
    cellRequestMinInterval_ = minInterval;
}

int32_t NetworkSearchHandler::IsSatelliteSupported() const
{
    char satelliteSupported[SYSPARA_SIZE] = { 0 };
    GetParameter(TEL_SATELLITE_SUPPORTED, SATELLITE_DEFAULT_VALUE, satelliteSupported, SYSPARA_SIZE);
    TELEPHONY_LOGI("satelliteSupported is %{public}s", satelliteSupported);
    return std::atoi(satelliteSupported);
}

bool NetworkSearchHandler::IsSatelliteOn() const
{
    bool isSatelliteOn = CoreManagerInner::GetInstance().IsSatelliteEnabled();
    bool isSupportSatellite = (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED));
    bool isSatelliteState = isSatelliteOn && isSupportSatellite;
    TELEPHONY_LOGI("NetworkSearchHandler::IsSatelliteOn %{public}d", isSatelliteState);
    return isSatelliteState;
}

void NetworkSearchHandler::ClearSignalAndCellInfoList() const
{
    if (signalInfo_ != nullptr) {
        TELEPHONY_LOGD("reset signal info slotId: %{public}d", slotId_);
        signalInfo_->Reset();
        std::vector<sptr<SignalInformation>> signals;
        signalInfo_->GetSignalInfoList(signals);
        if (TELEPHONY_EXT_WRAPPER.sortSignalInfoListExt_ != nullptr) {
            TELEPHONY_EXT_WRAPPER.sortSignalInfoListExt_(slotId_, signals);
        }
        DelayedSingleton<NetworkSearchNotify>::GetInstance()->NotifySignalInfoUpdated(slotId_, signals);
    }
    if (cellInfo_ != nullptr) {
        cellInfo_->ClearCellInfoList();
    }
}

NetworkSearchHandler::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    std::shared_ptr<OperatorName> &operatorName) : opName_(operatorName)
{}

void NetworkSearchHandler::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    switch (systemAbilityId) {
        case COMMON_EVENT_SERVICE_ID: {
            if (opName_ == nullptr) {
                TELEPHONY_LOGE("OnAddSystemAbility COMMON_EVENT_SERVICE_ID opName_ is nullptr");
                return;
            }
            opName_->NotifySpnChanged(true);
            bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(opName_);
            bool settingsResult = EventFwk::CommonEventManager::SubscribeCommonEvent(
                SettingUtils::GetInstance()->GetCommonEventSubscriber());
            TELEPHONY_LOGI("NetworkSearchHandler::OnAddSystemAbility subscribeResult = %{public}d, %{public}d",
                subscribeResult, settingsResult);
            break;
        }
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID:
            TELEPHONY_LOGI("NetworkSearchHandler::OnAddSystemAbility DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID");
            SettingUtils::GetInstance()->UpdateDdsState(true);
            break;
        default:
            TELEPHONY_LOGE("NetworkSearchHandler::OnAddSystemAbility unknown sa id %{public}d", systemAbilityId);
    }
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

bool NetworkSearchHandler::IsPowerOnPrimaryRadioWhenNoSim() const
{
    TELEPHONY_LOGD("Start to check if power on primary modem's radio when sim slots are empty");
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("get networkSearchManager is failed");
        return false;
    }
    auto simManager = nsm->GetSimManager();
    if (simManager == nullptr) {
        TELEPHONY_LOGE("get simManager failed");
        return false;
    }
    int32_t primarySlotId = INVALID_SLOT_ID;
    simManager->GetPrimarySlotId(primarySlotId);
    if (primarySlotId != INVALID_SLOT_ID && primarySlotId == slotId_) {
        TELEPHONY_LOGD("primarySlotId = %{public}d, send radio on request", primarySlotId);
        return true;
    }
    return false;
}

void NetworkSearchHandler::ProcessSignalIntensity(int32_t slotId, const Rssi &signalIntensity)
{
    Rssi *s = const_cast<Rssi*>(&signalIntensity);
    if (signalInfo_ != nullptr) {
        signalInfo_->ProcessSignalIntensity(slotId, s);
    }
}

void NetworkSearchHandler::UpdateOperatorName()
{
    if (operatorName_ != nullptr) {
        operatorName_->NotifySpnChanged(true);
    }
}
} // namespace Telephony
} // namespace OHOS
