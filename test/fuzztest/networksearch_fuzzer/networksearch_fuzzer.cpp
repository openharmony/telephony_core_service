/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "napi_util.h"
#include "satellite_core_callback.h"
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
    networkSearchHandler->InitSettingUtils();
    networkSearchHandler->UnregisterEvents();
    networkSearchHandler->UpdateNetworkState();
    networkSearchHandler->UpdateOperatorName();
    networkSearchHandler->SubscribeSystemAbility();
    networkSearchHandler->SyncGetSsbInfoResponse();
    networkSearchHandler->RegisterSatelliteCallback();
    networkSearchHandler->UnregisterSatelliteCallback();
    networkSearchHandler->SetRadioOffWhenAirplaneIsOn();
    networkSearchHandler->SetRadioOffWhenSimDeactive();
    networkSearchHandler->IsPowerOnPrimaryRadioWhenNoSim();
    networkSearchHandler->ClearSignalAndCellInfoList();
}

void NetworkSearchHandlerOnInit()
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);

    networkSearchHandler->networkSearchManager_.reset();
    networkSearchHandler->GetDeviceId();
    networkSearchHandler->SyncGetSsbInfoResponse();
    networkSearchHandler->SetRadioOffWhenSimDeactive();
    networkSearchHandler->SetRadioOffWhenAirplaneIsOn();
    networkSearchHandler->InitGetNetworkSelectionMode();
    networkSearchHandler->IsPowerOnPrimaryRadioWhenNoSim();
    networkSearchHandler->RadioOffOrUnavailableState(INVALID_SLOTID);

    networkSearchHandler->networkRegister_ = nullptr;
    networkSearchHandler->RadioStateChange(event);
    networkSearchHandler->RadioRilOperator(event);
    networkSearchHandler->GetNetworkStateInfo(event);
    networkSearchHandler->RadioRilDataRegState(event);
    networkSearchHandler->RadioRestrictedState(event);
    networkSearchHandler->RadioRilVoiceRegState(event);
    networkSearchHandler->RadioResidentNetworkChange(event);
}

void NetworkSearchHandlerEvents()
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);

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
    networkSearchHandler->SatelliteStatusChanged(event);
    networkSearchHandler->RadioResidentNetworkChange(event);

    event = nullptr;
    networkSearchHandler->ImsiLoadedReady(event);
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
}

void NetworkSearchHandlerProcesses()
{
    std::shared_ptr<TelRilManager> telRilManager = nullptr;
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, INVALID_SLOTID);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);

    networkSearchHandler->ProcessEvent(event);
    networkSearchHandler->RadioGetMeid(event);
    networkSearchHandler->ImsiLoadedReady(event);
    networkSearchHandler->RadioGetImeiSv(event);
    networkSearchHandler->NotifyStateChange(event);
    networkSearchHandler->SatelliteStatusChanged(event);
    networkSearchHandler->UpdateImsRegisterState(event);
    networkSearchHandler->UpdateImsServiceStatus(event);
    networkSearchHandler->HandleDelayNotifyEvent(event);
    networkSearchHandler->RadioChannelConfigInfo(event);
    networkSearchHandler->DcPhysicalLinkActiveUpdate(event);
    networkSearchHandler->RadioResidentNetworkChange(event);

    event = nullptr;
    networkSearchHandler->ProcessEvent(event);
    networkSearchHandler->RadioGetMeid(event);
    networkSearchHandler->RadioGetImeiSv(event);
    networkSearchHandler->RadioRilOperator(event);
    networkSearchHandler->NotifyStateChange(event);
    networkSearchHandler->RadioSignalStrength(event);
    networkSearchHandler->RadioRestrictedState(event);
    networkSearchHandler->RadioRilDataRegState(event);
    networkSearchHandler->RadioRilVoiceRegState(event);
    networkSearchHandler->SatelliteStatusChanged(event);
    networkSearchHandler->UpdateImsRegisterState(event);
    networkSearchHandler->UpdateImsServiceStatus(event);
    networkSearchHandler->HandleDelayNotifyEvent(event);
    networkSearchHandler->RadioChannelConfigInfo(event);
    networkSearchHandler->RadioCurrentCellInfoUpdate(event);
    networkSearchHandler->DcPhysicalLinkActiveUpdate(event);
    networkSearchHandler->RadioResidentNetworkChange(event);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    NetworkSearchHandlerInit();
    NetworkSearchHandlerOnInit();
    NetworkSearchHandlerEvents();
    NetworkSearchHandlerProcesses();
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
    OHOS::DelayedSingleton<CoreService>::DestroyInstance();
    return 0;
}