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

#include "setvoicemailinfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>
#include <thread>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "unistd.h"
#include "tel_ril_manager.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t LOCK_TYPE = 2;

bool IsServiceInited()
{
    if (!g_isInited) {
        DelayedSingleton<CoreService>::GetInstance()->OnStart();
        if (DelayedSingleton<CoreService>::GetInstance()->GetServiceRunningState() ==
            static_cast<int32_t>(ServiceRunningState::STATE_RUNNING)) {
            g_isInited = true;
        }
    }
    return g_isInited;
}

void GetDefaultVoiceSlotId(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteBuffer(provider->ConsumeIntegral<uin8_t>(), ConsumeIntegral<size_t>());
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetDefaultVoiceSlotId(dataMessageParcel, reply);
}

void GetActiveSimAccountInfoList(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteBuffer(provider->ConsumeIntegral<uin8_t>(), ConsumeIntegral<size_t>());
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetActiveSimAccountInfoList(dataMessageParcel, reply);
}

void GetOperatorConfigs(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = provider->ConsumeIntegral<int32_t>() % SLOT_NUM;
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(provider->ConsumeIntegral<uin8_t>(), provider->ConsumeIntegral<size_t>());
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetOperatorConfig(dataMessageParcel, reply);
}

void GetLockState(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = provider->ConsumeIntegral<int32_t>() % SLOT_NUM;
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(provider->ConsumeIntegral<int32_t>() % LOCK_TYPE);
    dataMessageParcel.WriteBuffer(provider->ConsumeIntegral<uin8_t>(), provider->ConsumeIntegral<size_t>());
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetLockState(dataMessageParcel, reply);
}

void SetVoiceMailInfo(std::shared_ptr<FuzzedDataProvider> provider)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = provider->ConsumeIntegral<int32_t>() % SLOT_NUM;
    std::string mailNumber = provider->ConsumeRandomLengthString();
    std::string mailName = provider->ConsumeRandomLengthString();
    auto mailNameU16 = Str8ToStr16(mailName);
    auto mailNumberU16 = Str8ToStr16(mailNumber);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteString16(mailNameU16);
    dataMessageParcel.WriteString16(mailNumberU16);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetVoiceMailInfo(dataMessageParcel, reply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    std::shared_ptr<FuzzedDataProvider> provider = std::make_shared<FuzzedDataProvider>(data, size);
    GetDefaultVoiceSlotId(provider);
    GetOperatorConfigs(provider);
    GetActiveSimAccountInfoList(provider);
    GetLockState(provider);
    SetVoiceMailInfo(provider);
    sleep(1);
    return;
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
