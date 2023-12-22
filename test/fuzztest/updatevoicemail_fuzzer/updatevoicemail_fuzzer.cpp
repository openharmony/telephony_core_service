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

#include "updatevoicemail_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "addcoreservicetoken_fuzzer.h"
#include "event_runner.h"
#include "napi_util.h"
#include "ruim_file.h"
#include "system_ability_definition.h"
#include "tel_ril_manager.h"

using namespace OHOS::Telephony;
namespace OHOS {
constexpr int32_t BOOL_NUM = 2;
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

    int32_t roaming = static_cast<int32_t>(size % BOOL_NUM);
    int32_t response = static_cast<int32_t>(size % BOOL_NUM);
    std::int32_t eventId = static_cast<int32_t>(size);
    std::int64_t refId = static_cast<int64_t>(size);
    std::string operatorNum(reinterpret_cast<const char *>(data), size);
    std::string mailName(reinterpret_cast<const char *>(data), size);
    std::string mailNumber(reinterpret_cast<const char *>(data), size);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, refId);
    auto telRilManager_ = std::make_shared<TelRilManager>();
    auto stateManager_ = std::make_shared<SimStateManager>(telRilManager_);
    auto ruimFile = std::make_shared<RuimFile>(stateManager_);
    ruimFile->ObtainSpnCondition(roaming, operatorNum);
    ruimFile->UpdateVoiceMail(mailName, mailNumber);
    ruimFile->ObtainIsoCountryCode();
    ruimFile->ObtainSid();
    ruimFile->ProcessGetIccidDone(event);
    ruimFile->ProcessGetSubscriptionDone(event);
    ruimFile->ProcessGetImsiDone(event);
    ruimFile->ProcessFileLoaded(response);
    ruimFile->ObtainNid();
    ruimFile->ObtainCsimSpnDisplayCondition();
    ruimFile->ObtainNAI();
    ruimFile->ObtainMdn();
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
