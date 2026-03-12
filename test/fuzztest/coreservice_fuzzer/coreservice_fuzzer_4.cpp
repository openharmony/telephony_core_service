/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "i_network_search_callback_stub.h"
 
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
 
void GetSimIO(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimIO(dataMessageParcel, reply);
}
 
void GetAllSimAccountInfoList(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetAllSimAccountInfoList(dataMessageParcel, reply);
}
 
void GetSimLabel(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimLabel(dataMessageParcel, reply);
}

void SendApduData(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSendApduData(dataMessageParcel, reply);
}
 
void GetManualNetworkScanState(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    std::unique_ptr<INetworkSearchCallback> callback = std::make_unique<INetworkSearchCallbackStub>();
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteRemoteObject(callback.release()->AsObject().GetRefPtr());
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetManualNetworkScanState(dataMessageParcel, reply);
}
 
void StartManualNetworkScan(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    std::unique_ptr<INetworkSearchCallback> callback = std::make_unique<INetworkSearchCallbackStub>();
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteRemoteObject(callback.release()->AsObject().GetRefPtr());
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnStartManualNetworkScan(dataMessageParcel, reply);
}
 
void StopManualNetworkScan(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnStopManualNetworkScan(dataMessageParcel, reply);
}
 
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
 
    GetSimIO(data, size);
    GetAllSimAccountInfoList(data, size);
    GetSimLabel(data, size);
    StartEmcRescueService(data, size);
    StopEmcRescueService(data, size);
    SendApduData(data, size);
    GetManualNetworkScanState(data, size);
    StartManualNetworkScan(data, size);
    StopManualNetworkScan(data, size);
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