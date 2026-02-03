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
 
#include "coreservice_fuzzer.h"
 
#include <cstddef>
#include <cstdint>
#include <thread>
 
#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "unistd.h"
#include "tel_ril_manager.h"
#include "sim_state_type.h"
 
using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t SIM_TYPE_NUM = 2;
constexpr int32_t SLEEP_TIME_SECONDS = 2;
 
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

void GetDefaultVoiceSimId(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetDefaultVoiceSimId(dataMessageParcel, reply);
}

void SetPrimarySlotId(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetPrimarySlotId(dataMessageParcel, reply);
}

void GetPrimarySlotId(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetPrimarySlotId(dataMessageParcel, reply);
}

void RefreshSimState(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnRefreshSimState(dataMessageParcel, reply);
}

void GetPreferredNetwork(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetPreferredNetwork(dataMessageParcel, reply);
}

void GetSimTeleNumberIdentifier(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimTeleNumberIdentifier(dataMessageParcel, reply);
}

void GetVoiceMailCount(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetVoiceMailCount(dataMessageParcel, reply);
}

void SetVoiceMailCount(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetVoiceMailCount(dataMessageParcel, reply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
 
    GetDefaultVoiceSimId(data, size);
    SetPrimarySlotId(data, size);
    GetPrimarySlotId(data, size);
    RefreshSimState(data, size);
    GetPreferredNetwork(data, size);
    GetSimTeleNumberIdentifier(data, size);
    GetVoiceMailCount(data, size);
    SetVoiceMailCount(data, size);
    sleep(SLEEP_TIME_SECONDS);
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