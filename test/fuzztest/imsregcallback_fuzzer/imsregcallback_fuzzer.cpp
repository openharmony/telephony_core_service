/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "imsregcallback_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "addcoreservicetoken_fuzzer.h"
#include "ims_reg_info_callback_stub.h"
#include "napi_ims_reg_info_callback.h"
#include "napi_ims_reg_info_callback_manager.h"
#include "napi_util.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t BOOL_NUM = 2;
constexpr int32_t TECH_NUM = 4;
constexpr int32_t IMS_SERVICE_TYPE_NUM = 4;
void OnRemoteRequest(const uint8_t *data, size_t size)
{
    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(ImsRegInfoCallbackStub::GetDescriptor())) {
        return;
    }
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t reg = static_cast<int32_t>(size % BOOL_NUM);
    int32_t tech = static_cast<int32_t>(size % TECH_NUM);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(reg);
    dataMessageParcel.WriteInt32(tech);

    uint32_t code = static_cast<uint32_t>(size % IMS_SERVICE_TYPE_NUM);
    MessageParcel reply;
    MessageOption option;
    sptr<NapiImsRegInfoCallback> imsCallback = new NapiImsRegInfoCallback();
    imsCallback->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OnRemoteRequest(data, size);
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
