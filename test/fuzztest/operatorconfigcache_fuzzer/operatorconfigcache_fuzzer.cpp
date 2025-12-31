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
 
#include "operatorconfigcache_fuzzer.h"
 
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
 
using namespace OHOS::Telephony;
namespace OHOS {
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t SIM_STATUS_NUM = 5;
constexpr int32_t SLEEP_TIME_SECONDS = 100000;
 
static int32_t GetInt(const uint8_t *data, size_t size, int index = 0)
{
    size_t typeSize = sizeof(int32_t);
    uintptr_t align = reinterpret_cast<uintptr_t>(data) % typeSize;
    const uint8_t *base = data + (align > 0 ? typeSize - align : 0);
    if (size - align < typeSize * index + (typeSize - align)) {
        return 0;
    }
    return *reinterpret_cast<const int32_t*>(base + index * typeSize);
}
 
void OperatorConfigCacheFunc(const uint8_t *data, size_t size)
{
    int index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    auto simFileManager = std::make_shared<SimFileManager>(telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t simState = *data % SIM_STATUS_NUM + 1;
    SimState simEnum = static_cast<SimState>(simState);
    operatorConfigCache->UpdateIccidCache(simState);
    operatorConfigCache->GetSimState(slotId, simEnum);
    operatorConfigCache->IsNeedOperatorLoad(slotId);
    operatorConfigCache->AnnounceOperatorConfigChanged(slotId, simState);
    operatorConfigCache->notifyInitApnConfigs(slotId);
    operatorConfigCache->SendSimMatchedOperatorInfo(slotId, simState);
    operatorConfigCache->UnRegisterForIccChange();
    operatorConfigCache->UpdateOperatorConfigs(slotId);
    operatorConfigCache->ClearOperatorValue(slotId);
    operatorConfigCache->ClearMemoryAndOpkey(slotId);
    operatorConfigCache->ClearAllCache(slotId);
    operatorConfigCache->simStateManager_ = nullptr;
    operatorConfigCache->GetSimState(slotId, simEnum);
    slotId = GetInt(data, size, index++);
    operatorConfigCache->GetSimState(slotId, simEnum);
}
 
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OperatorConfigCacheFunc(data, size);
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