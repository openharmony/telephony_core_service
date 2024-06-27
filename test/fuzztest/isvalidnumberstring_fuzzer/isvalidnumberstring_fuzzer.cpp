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

#include "isvalidnumberstring_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "napi_util.h"
#include "sim_char_decode.h"
#include "sim_number_decode.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    auto simCharDecode = std::make_shared<SimCharDecode>();
    auto simNumberDecode = std::make_shared<SimNumberDecode>();
    int32_t offset = 0;
    int32_t bcdExtType = static_cast<int32_t>(*data + offset);
    offset += sizeof(int32_t);
    uint8_t result = static_cast<uint8_t>(*data + offset);
    offset += sizeof(int32_t);
    char argument = static_cast<char>(*data + offset);
    std::string str(reinterpret_cast<const char *>(data), size);
    std::string number(reinterpret_cast<const char *>(data), size);
    std::vector<uint8_t> bcdCodes;
    bcdCodes.push_back(result);
    bool includeLen = static_cast<int32_t>(*data % 2);
    simCharDecode->IsChineseString(str);
    simNumberDecode->IsValidNumberString(number);
    simNumberDecode->CharToBCD(argument, result, bcdExtType);
    simNumberDecode->NumberConvertToBCD(number, bcdCodes, includeLen, bcdExtType);
    simNumberDecode->BcdToChar(result, argument, bcdExtType);
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
