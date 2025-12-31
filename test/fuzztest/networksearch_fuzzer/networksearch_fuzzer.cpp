/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "networksearch_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <thread>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "tel_event_handler.h"
#include "unistd.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "network_search_handler.h"
#include "network_search_manager.h"
#include "network_search_state.h"

using namespace OHOS::Telephony;
namespace OHOS {
static const int32_t INVALID_SLOTID = -1;
constexpr int32_t SLEEP_TIME_SECONDS = 100000;

void NetworkSearchHandlerInit()
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);

    networkSearchHandler->simManager_ = simManager;
    networkSearchHandler->networkSearchManager_ = networkSearchManager;

    networkSearchHandler->Init();
    networkSearchHandler->GetDeviceId();
    networkSearchHandler->SubModuleInit();
    networkSearchHandler->RegisterEvents();
    networkSearchHandler->InitOperatorName();
    networkSearchHandler->UnregisterEvents();
    networkSearchHandler->UpdateNetworkState();
    networkSearchHandler->UpdateOperatorName();
    networkSearchHandler->SubscribeSystemAbility();
    networkSearchHandler->SyncGetSsbInfoResponse();
#ifdef CORE_SERVICE_SUPPORT_SATELLITE
    networkSearchHandler->RegisterSatelliteCallback();
    networkSearchHandler->UnregisterSatelliteCallback();
#endif // CORE_SERVICE_SUPPORT_SATELLITE
    networkSearchHandler->SetRadioOffWhenAirplaneIsOn();
    networkSearchHandler->SetRadioOffWhenSimDeactive();
    networkSearchHandler->IsPowerOnPrimaryRadioWhenNoSim();
    networkSearchHandler->ClearSignalAndCellInfoList();
}

void NetworkSearchHandlerOnInit(const uint8_t *data, size_t size)
{
    std::int32_t eventId = static_cast<int32_t>(size);
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object);
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);

    networkSearchHandler->GetRilSignalIntensity(true);
    networkSearchHandler->RadioOnWhenHasSim(networkSearchManager, eventId);
    networkSearchHandler->RadioOffOrUnavailableState(eventId);

    networkSearchHandler->RadioStateChange(event);
    networkSearchHandler->RadioRilOperator(event);
    networkSearchHandler->GetNetworkStateInfo(event);
    networkSearchHandler->RadioRilDataRegState(event);
    networkSearchHandler->RadioRestrictedState(event);
    networkSearchHandler->RadioRilVoiceRegState(event);
    networkSearchHandler->RadioResidentNetworkChange(event);

    networkSearchHandler->networkRegister_ = nullptr;
    networkSearchHandler->RadioStateChange(event);
    networkSearchHandler->RadioRilOperator(event);
    networkSearchHandler->GetNetworkStateInfo(event);
    networkSearchHandler->RadioRilDataRegState(event);
    networkSearchHandler->RadioRestrictedState(event);
    networkSearchHandler->RadioRilVoiceRegState(event);
    networkSearchHandler->RadioResidentNetworkChange(event);

    networkSearchHandler->networkSearchManager_.reset();
    networkSearchHandler->GetDeviceId();
    networkSearchHandler->SyncGetSsbInfoResponse();
    networkSearchHandler->SetRadioOffWhenSimDeactive();
    networkSearchHandler->SetRadioOffWhenAirplaneIsOn();
    networkSearchHandler->InitGetNetworkSelectionMode();
    networkSearchHandler->IsPowerOnPrimaryRadioWhenNoSim();
    networkSearchHandler->RadioOffOrUnavailableState(eventId);
}

void NetworkSearchHandlerEvents(const uint8_t *data, size_t size)
{
    std::int32_t eventId = static_cast<int32_t>(size);
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object);
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);

    networkSearchHandler->nrSsbInfo_ = nullptr;
    networkSearchHandler->radioInfo_ = nullptr;
    networkSearchHandler->nitzUpdate_ = nullptr;
    networkSearchHandler->networkType_ = nullptr;
    networkSearchHandler->networkRegister_ = nullptr;
    networkSearchHandler->networkSelection_ = nullptr;

    networkSearchHandler->RadioNitzUpdate(event);
    networkSearchHandler->GetNrSsbIdResponse(event);
    networkSearchHandler->NetworkSearchResult(event);
    networkSearchHandler->GetRadioStateResponse(event);
    networkSearchHandler->SetRadioStateResponse(event);
    networkSearchHandler->SetNrOptionModeResponse(event);
    networkSearchHandler->GetNrOptionModeResponse(event);
    networkSearchHandler->RadioGetBasebandVersion(event);
    networkSearchHandler->RadioGetRrcConnectionState(event);
    networkSearchHandler->GetPreferredNetworkResponse(event);
    networkSearchHandler->SetPreferredNetworkResponse(event);
    networkSearchHandler->SetNetworkSelectionModeResponse(event);
    networkSearchHandler->GetNetworkSelectionModeResponse(event);
#ifdef CORE_SERVICE_SUPPORT_SATELLITE
    networkSearchHandler->SatelliteStatusChanged(event);
#endif // CORE_SERVICE_SUPPORT_SATELLITE
    networkSearchHandler->RadioResidentNetworkChange(event);
}

void NetworkSearchHandlerProcesses(const uint8_t *data, size_t size)
{
    std::int32_t eventId = static_cast<int32_t>(size);
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object);
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);

    networkSearchHandler->RadioGetImei(event);
    networkSearchHandler->ProcessEvent(event);
    networkSearchHandler->RadioGetMeid(event);
    networkSearchHandler->RadioGetImeiSv(event);
    networkSearchHandler->ImsiLoadedReady(event);
    networkSearchHandler->SimRecordsLoaded(event);
    networkSearchHandler->NotifyStateChange(event);
#ifdef CORE_SERVICE_SUPPORT_SATELLITE
    networkSearchHandler->SatelliteStatusChanged(event);
#endif // CORE_SERVICE_SUPPORT_SATELLITE
    networkSearchHandler->UpdateImsRegisterState(event);
    networkSearchHandler->UpdateImsServiceStatus(event);
    networkSearchHandler->HandleDelayNotifyEvent(event);
    networkSearchHandler->RadioChannelConfigInfo(event);
    networkSearchHandler->DcPhysicalLinkActiveUpdate(event);
    networkSearchHandler->RadioResidentNetworkChange(event);
}

void NetworkSearchHandlerGetRegistration(const uint8_t *data, size_t size)
{
    std::int32_t eventId = static_cast<int32_t>(size);
    bool checkTime = eventId == INVALID_SLOTID;
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object);
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);

    networkSearchHandler->TimezoneRefresh();
    networkSearchHandler->RadioOnState(checkTime);
    networkSearchHandler->GetRilOperatorInfo(eventId, checkTime);
    networkSearchHandler->GetRilPsRegistration(eventId, checkTime);
    networkSearchHandler->GetRilCsRegistration(eventId, checkTime);

    networkSearchHandler->networkSearchManager_ = networkSearchManager;
    networkSearchHandler->AutoTimeChange(event);
    networkSearchHandler->AutoTimeZoneChange(event);
    networkSearchHandler->AirplaneModeChange(event);
    networkSearchHandler->RadioRilOperator(event);
    networkSearchHandler->RadioSignalStrength(event);
    networkSearchHandler->RadioRestrictedState(event);
    networkSearchHandler->RadioRilDataRegState(event);
    networkSearchHandler->RadioVoiceTechChange(event);
    networkSearchHandler->RadioRilVoiceRegState(event);
    networkSearchHandler->RadioGetCurrentCellInfo(event);
    networkSearchHandler->RadioCurrentCellInfoUpdate(event);
    networkSearchHandler->RadioGetNeighboringCellInfo(event);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    NetworkSearchHandlerInit();
    NetworkSearchHandlerOnInit(data, size);
    NetworkSearchHandlerEvents(data, size);
    NetworkSearchHandlerProcesses(data, size);
    NetworkSearchHandlerGetRegistration(data, size);
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}