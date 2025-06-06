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

#include "sendenvelopecmd_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <thread>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "core_service_stub.h"
#include "napi_util.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "unistd.h"
#include "tel_ril_manager.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t SLEEP_TIME_SECONDS = 3;
constexpr int32_t NETWORK_CAPABILITY_TYPE = 2;
constexpr int32_t NETWORK_CAPABILITY_STATE = 2;

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

void GetUniqueDeviceId(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetUniqueDeviceId(dataMessageParcel, reply);
}

void GetMeid(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetMeid(dataMessageParcel, reply);
}

void GetBasebandVersion(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetBasebandVersion(dataMessageParcel, reply);
}

void SetNetworkCapability(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t networkCapabilityType = static_cast<int32_t>(*data % NETWORK_CAPABILITY_TYPE);
    int32_t networkCapabilityState = static_cast<int32_t>(*data % NETWORK_CAPABILITY_STATE);
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(networkCapabilityType);
    dataMessageParcel.WriteInt32(networkCapabilityState);
    int32_t error = DelayedSingleton<CoreService>::GetInstance()->OnSetNetworkCapability(dataMessageParcel, reply);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SetNetworkCapability failed, error code is %{public}d \n", error);
    }
}

void GetNetworkCapability(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t networkCapabilityType = static_cast<int32_t>(*data % NETWORK_CAPABILITY_TYPE);
    int32_t networkCapabilityState = static_cast<int32_t>(*data % NETWORK_CAPABILITY_STATE);
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(networkCapabilityType);
    dataMessageParcel.WriteInt32(networkCapabilityState);
    int32_t error = DelayedSingleton<CoreService>::GetInstance()->OnGetNetworkCapability(dataMessageParcel, reply);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE(
            "GetNetworkAbilitySwitch failed, error code is %{public}d \n, networkCapabilityState is %{public}d", error,
            networkCapabilityState);
    }
}

void GetOperatorNumeric(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetOperatorNumeric(dataMessageParcel, reply);
}

void GetResidentNetworkNumeric(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetResidentNetworkNumeric(dataMessageParcel, reply);
}

void GetOperatorName(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetOperatorName(dataMessageParcel, reply);
}

void SendEnvelopeCmd(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    std::string cmd(reinterpret_cast<const char *>(data), size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteString(cmd);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSendEnvelopeCmd(dataMessageParcel, reply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    GetUniqueDeviceId(data, size);
    GetMeid(data, size);
    GetBasebandVersion(data, size);
    GetOperatorNumeric(data, size);
    GetOperatorName(data, size);
    SendEnvelopeCmd(data, size);
    GetNetworkCapability(data, size);
    SetNetworkCapability(data, size);
    GetResidentNetworkNumeric(data, size);
    auto telRilManager = std::static_pointer_cast<TelRilManager>(
        DelayedSingleton<CoreService>::GetInstance()->telRilManager_);
    if (telRilManager == nullptr || telRilManager->handler_ == nullptr) {
        return;
    }
    auto handler = telRilManager->handler_;
    if (handler != nullptr) {
        handler->RemoveAllEvents();
        handler->SendEvent(0, 0, AppExecFwk::EventQueue::Priority::HIGH);
        sleep(SLEEP_TIME_SECONDS);
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
    OHOS::DelayedSingleton<CoreService>::DestroyInstance();
    return 0;
}
