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
constexpr int32_t SLEEP_TIME_SECONDS = 100000;
 
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
 
void GetSimGid1(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimGid1(dataMessageParcel, reply);
}
 
void GetSimGid2(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimGid2(dataMessageParcel, reply);
}
 
void GetSimAccountInfo(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimSubscriptionInfo(dataMessageParcel, reply);
}
 
void GetCardType(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetCardType(dataMessageParcel, reply);
}
 
void GetSimState(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimState(dataMessageParcel, reply);
}
 
void GetDsdsMode(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t dsdsMode = static_cast<int32_t>(*data);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(dsdsMode);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetDsdsMode(dataMessageParcel, reply);
}
 
void HasSimCard(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnHasSimCard(dataMessageParcel, reply);
}
 
void AddIccDiallingNumbers(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t type = *data % SIM_TYPE_NUM + 1; // SIM_ADN 1  SIM_FDN 2
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(type);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnAddIccDiallingNumbers(dataMessageParcel, reply);
}
 
void IsCTSimCard(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnIsCTSimCard(dataMessageParcel, reply);
}
 
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
 
    GetSimGid1(data, size);
    GetSimGid2(data, size);
    GetSimAccountInfo(data, size);
    GetCardType(data, size);
    GetSimState(data, size);
    GetDsdsMode(data, size);
    HasSimCard(data, size);
    AddIccDiallingNumbers(data, size);
    IsCTSimCard(data, size);
    auto telRilManager = std::static_pointer_cast<TelRilManager>(
         DelayedSingleton<CoreService>::GetInstance()->telRilManager_);
    if (telRilManager == nullptr || telRilManager->handler_ == nullptr) {
        return;
    }
    auto handler = telRilManager->handler_;
    if (handler != nullptr) {
        handler->RemoveAllEvents();
        usleep(SLEEP_TIME_SECONDS);
    }
    telRilManager->handler_->ClearFfrt(false);
    telRilManager->handler_->queue_ = nullptr;
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
    if (OHOS::g_isInited) {
        OHOS::DelayedSingleton<CoreService>::GetInstance()->OnStop();
        OHOS::g_isInited = false;
    }
    usleep(OHOS::SLEEP_TIME_SECONDS);
    return 0;
}