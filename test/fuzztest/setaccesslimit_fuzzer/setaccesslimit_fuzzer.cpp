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

#include "setaccesslimit_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "addcoreservicetoken_fuzzer.h"
#include "icc_operator_rule.h"
#include "napi_util.h"
#include "system_ability_definition.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::Telephony;
namespace OHOS {
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::shared_ptr<FuzzedDataProvider> provider = std::make_shared<FuzzedDataProvider>(data, size);
    auto iccOperatorRule = std::make_shared<IccOperatorRule>();
    std::string result = provider->ConsumeRandomLengthString();
    std::string packageName = provider->ConsumeRandomLengthString();
    std::string hexStr = provider->ConsumeRandomLengthString();
    std::string certificate = provider->ConsumeRandomLengthString();
    std::string accessLimit = provider->ConsumeRandomLengthString();
    iccOperatorRule->GetPackageName(result);
    iccOperatorRule->GetPackageName(packageName);
    iccOperatorRule->SetPackageNameByHexStr(hexStr);
    iccOperatorRule->GetCertificate(result);
    iccOperatorRule->SetCertificate(certificate);
    iccOperatorRule->SetAccessLimit(accessLimit);
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
