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

#include "unmarshalling_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "napi_util.h"
#include "plmn_file.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::string plmn(reinterpret_cast<const char *>(data), size);
    int32_t accessTechs = static_cast<int32_t>(size);
    auto plmnFile = std::make_shared<PlmnFile>(plmn, accessTechs);
    Parcel parcel;
    parcel.WriteString(plmn);
    plmnFile->ReadFromParcel(parcel);
    plmnFile->Marshalling(parcel);
    plmnFile->UnMarshalling(parcel);
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
