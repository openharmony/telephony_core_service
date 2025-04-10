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

#include "hexvectohexstr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "addcoreservicetoken_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "napi_util.h"
#include "system_ability_definition.h"
#include "tag_service.h"

using namespace OHOS::Telephony;
namespace OHOS {
constexpr int32_t TEST_MAX_UINT8 = 255;

int32_t GetRandomInt(int min, int max, const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    return fdp.ConsumeIntegralInRange<int32_t>(min, max);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    uint8_t result = static_cast<uint8_t>(GetRandomInt(0, TEST_MAX_UINT8, data, size));
    std::vector<uint8_t> parameter;
    parameter.push_back(result);
    auto tagService = std::make_shared<TagService>(parameter);
    tagService->GetValue(parameter);
    tagService->GetTagCode();
    tagService->Next();
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
