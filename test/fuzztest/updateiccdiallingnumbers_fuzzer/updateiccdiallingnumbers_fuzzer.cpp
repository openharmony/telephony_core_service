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

#include "updateiccdiallingnumbers_fuzzer.h"

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
    int32_t type = 0 - size % 8;
    std::string number(reinterpret_cast<const char *>(data), size);
    std::string name(reinterpret_cast<const char *>(data), size);
    std::string pin2(reinterpret_cast<const char *>(data), size);
    std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
    telNumber->index_ = size;
    telNumber->name_ = Str8ToStr16(name);
    telNumber->number_ = Str8ToStr16(number);
    telNumber->pin2_ = Str8ToStr16(pin2);
    std::u16string opKey;
    std::u16string opName;
    DelayedRefSingleton<CoreServiceClient>::GetInstance().SendCallSetupRequestResult(slotId, size % 2);
    DelayedRefSingleton<CoreServiceClient>::GetInstance().HasOperatorPrivileges(slotId);
    DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCellInfoList(slotId);
    DelayedRefSingleton<CoreServiceClient>::GetInstance().UpdateIccDiallingNumbers(slotId, type, telNumber);
    return;
}
}  // namespace OHOS
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
