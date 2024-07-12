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

#include "isshowableasciionly_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "addcoreservicetoken_fuzzer.h"
#include "napi_util.h"
#include "sim_utils.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    auto simUtils = std::make_shared<SIMUtils>();
    int32_t byteslen = static_cast<int32_t>(*data);
    int32_t offset = static_cast<int32_t>(*data + sizeof(int32_t));
    char argument = static_cast<char>(*data);
    std::string str(reinterpret_cast<const char *>(data), size);
    std::string parameter(reinterpret_cast<const char *>(data), size);
    simUtils->HexStringConvertToBytes(str, byteslen);
    simUtils->IsShowableAsciiOnly(str);
    simUtils->BcdPlmnConvertToString(parameter, offset);
    simUtils->Trim(str);
    simUtils->HexCharConvertToInt(argument);
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
