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

#include "getsimeons_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "addcoreservicetoken_fuzzer.h"
#include "core_service_client.h"
#include "napi_util.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size <= 0) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size);
    std::string plmn(reinterpret_cast<const char *>(data), size);
    int32_t fac = static_cast<int32_t>(size);
    bool longNameRequired = size % 2;
    DelayedRefSingleton<CoreServiceClient>::GetInstance().IsNrSupported(slotId);
    DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPsRadioTech(slotId);
    DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCsRadioTech(slotId);
    DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNrOptionMode(slotId);
    DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimEons(slotId, plmn, fac, longNameRequired);
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