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
#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t LOCK_TYPE = 2;
constexpr int32_t TWO_INT_NUM = 2;

bool IsServiceInited()
{
    DelayedSingleton<CoreService>::GetInstance()->OnStart();
    if (!g_isInited && (static_cast<int32_t>(DelayedSingleton<CoreService>::GetInstance()->state_) ==
                         static_cast<int32_t>(ServiceRunningState::STATE_RUNNING))) {
        g_isInited = true;
    }
    return g_isInited;
}

void OnRemoteRequest(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    size_t dataSize = size - sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), dataSize);
    dataMessageParcel.RewindRead(0);
    uint32_t code = static_cast<uint32_t>(size);
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<CoreService>::GetInstance()->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void GetDefaultVoiceSlotId(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetDefaultVoiceSlotId(dataMessageParcel, reply);
}

void GetActiveSimAccountInfoList(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetActiveSimAccountInfoList(dataMessageParcel, reply);
}

void GetOperatorConfigs(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    size_t dataSize = size - sizeof(int32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(int32_t), dataSize);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetOperatorConfig(dataMessageParcel, reply);
}

void GetLockState(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(static_cast<int32_t>(size % LOCK_TYPE));
    size_t dataSize = size - sizeof(int32_t) * TWO_INT_NUM;
    dataMessageParcel.WriteBuffer(data + sizeof(int32_t) * TWO_INT_NUM, dataSize);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetLockState(dataMessageParcel, reply);
}

void SetVoiceMailInfo(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    std::string mailNumber(reinterpret_cast<const char *>(data), size);
    std::string mailName(reinterpret_cast<const char *>(data), size);
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

    OnRemoteRequest(data, size);
    GetDefaultVoiceSlotId(data, size);
    GetOperatorConfigs(data, size);
    GetActiveSimAccountInfoList(data, size);
    GetLockState(data, size);
    SetVoiceMailInfo(data, size);
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
