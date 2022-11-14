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
#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "system_ability_definition.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t ACCEPT_TYPE = 2;
constexpr int32_t SIM_TYPE_NUM = 2;
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

void GetOpKey(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetOpKey(dataMessageParcel, reply);
}

void GetOpKeyExt(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetOpKeyExt(dataMessageParcel, reply);
}

void GetOpName(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetOpName(dataMessageParcel, reply);
}

void SendCallSetupRequestResult(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t accept = static_cast<int32_t>(size % ACCEPT_TYPE);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(accept);
    size_t dataSize = size - sizeof(int32_t) * TWO_INT_NUM;
    dataMessageParcel.WriteBuffer(data + sizeof(int32_t) * TWO_INT_NUM, dataSize);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSendCallSetupRequestResult(dataMessageParcel, reply);
}

void HasOperatorPrivileges(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnHasOperatorPrivileges(dataMessageParcel, reply);
}

void GetCellInfoList(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetCellInfoList(dataMessageParcel, reply);
}

void UpdateIccDiallingNumbers(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t type = size % SIM_TYPE_NUM + 1;
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(type);
    size_t dataSize = size - sizeof(int32_t) * TWO_INT_NUM;
    dataMessageParcel.WriteBuffer(data + sizeof(int32_t) * TWO_INT_NUM, dataSize);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnUpdateIccDiallingNumbers(dataMessageParcel, reply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OnRemoteRequest(data, size);
    GetOpKey(data, size);
    GetOpKeyExt(data, size);
    GetOpName(data, size);
    SendCallSetupRequestResult(data, size);
    HasOperatorPrivileges(data, size);
    GetCellInfoList(data, size);
    UpdateIccDiallingNumbers(data, size);
    return;
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
