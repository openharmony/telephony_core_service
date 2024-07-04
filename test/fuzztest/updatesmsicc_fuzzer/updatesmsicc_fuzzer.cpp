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

#include "updatesmsicc_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "event_handler.h"
#include "event_runner.h"
#include "sim_sms_controller.h"
#include "system_ability_definition.h"
#include "tel_ril_manager.h"

using namespace OHOS::Telephony;
namespace OHOS {
bool g_flag = false;

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    if (g_flag) {
        return;
    }
    g_flag = true;

    auto telRilManager_ = std::make_shared<TelRilManager>();
    auto stateManager_ = std::make_shared<SimStateManager>(telRilManager_);
    auto simSmsController = std::make_shared<SimSmsController>(stateManager_);
    std::int32_t eventId = static_cast<int32_t>(size);
    std::unique_ptr<uint8_t> object = std::make_unique<uint8_t>(*data);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object);
    simSmsController->BuildCallerInfo(eventId);
    simSmsController->IsCdmaCardType();
    simSmsController->ProcessEvent(event);
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
