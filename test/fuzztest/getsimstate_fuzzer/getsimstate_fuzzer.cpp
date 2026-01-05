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
 
#include "getsimstate_fuzzer.h"
 
#include <cstddef>
#include <cstdint>
#include <thread>
 
#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "unistd.h"
#include "tel_ril_manager.h"
#include "sim_state_type.h"
#include "sim_manager.h"
#include "operator_config_cache.h"
#include "voice_mail_constants.h"
#include "fuzzer/FuzzedDataProvider.h"
 
using namespace OHOS::Telephony;
namespace OHOS {
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t SIM_STATUS_NUM = 5;
constexpr int32_t ICC_STATUS_NUM = 12;
constexpr int32_t SLEEP_TIME_SECONDS = 100000;

void GetSimStateFunc(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (provider == nullptr) {
        return;
    }
    int index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = provider->ConsumeIntegral<int32_t>() % SLOT_NUM;
    int32_t voiceMailCount = provider->ConsumeIntegral<int32_t>();
    int32_t simState = provider->ConsumeIntegral<int32_t>() % SIM_STATUS_NUM + 1;
    int32_t iccStatus = provider->ConsumeIntegral<int32_t>() % ICC_STATUS_NUM + 1;
    SimState simEnum = static_cast<SimState>(simState);
    IccSimStatus iccEnum = static_cast<IccSimStatus>(iccStatus);
    bool hasOperatorPrivileges = true;
    simManager->GetSimState(slotId, simEnum);
    simManager->GetSimIccStatus(slotId, iccEnum);
    simManager->SetModemInit(slotId, true);
    simManager->RefreshSimState(slotId);
    simManager->SendSimMatchedOperatorInfo(slotId, simState, std::string(provider->ConsumeRandomLengthString()),
        std::string(provider->ConsumeRandomLengthString()));
    simManager->SetVoiceMailCount(slotId, voiceMailCount);
    simManager->GetVoiceMailCount(slotId, voiceMailCount);
    simManager->ObtainSpnCondition(
        slotId, hasOperatorPrivileges, std::string(provider->ConsumeRandomLengthString()));
    std::string pdu(provider->ConsumeRandomLengthString());
    std::string smsc(provider->ConsumeRandomLengthString());
    simManager->AddSmsToIcc(slotId, static_cast<int32_t>(simState), pdu, smsc);
    simManager->IsCTSimCard(slotId, hasOperatorPrivileges);
    simManager->IsValidSlotIdForDefault(slotId);
    simManager->GetSimIst(slotId);
    simManager->NotifySimSlotsMapping(slotId);
    simManager->SetIccCardState(slotId, static_cast<int32_t>(simState));
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::shared_ptr<FuzzedDataProvider> provider = std::make_shared<FuzzedDataProvider>(data, size);
    GetSimStateFunc(provider);
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