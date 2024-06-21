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

#include "satellitecore_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <thread>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "satellite_core_callback.h"
#include "tel_event_handler.h"
#include "unistd.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t RESPONSE_TYPE = 2;
constexpr int32_t SATELLITE_TYPE = 3;
constexpr int32_t SATELLITE_CORE = 4;

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

void OnRemoteRequest(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(SatelliteCoreCallbackStub::GetDescriptor())) {
        return;
    }
    int32_t code = static_cast<int32_t>(size % SATELLITE_CORE);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<SatelliteCoreCallback> callback = std::make_shared<SatelliteCoreCallback>(nullptr);
    if (callback == nullptr) {
        return;
    }
    callback->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void SetRadioStateResponse(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t eventId = static_cast<int32_t>(size % SATELLITE_CORE);
    dataMessageParcel.WriteInt32(eventId);
    int32_t dataType = static_cast<int32_t>(size % SATELLITE_TYPE);
    dataMessageParcel.WriteInt32(dataType);
    if (dataType == 1) {
        int32_t flag = static_cast<int32_t>(size % SATELLITE_CORE);
        dataMessageParcel.WriteInt32(flag);
        int32_t serial = static_cast<int32_t>(size % SATELLITE_CORE);
        dataMessageParcel.WriteInt32(serial);
        int32_t error = static_cast<int32_t>(size % SATELLITE_CORE);
        dataMessageParcel.WriteInt32(error);
        int32_t type = static_cast<int32_t>(size % SATELLITE_TYPE);
        dataMessageParcel.WriteInt32(type);
    } else if (dataType == RESPONSE_TYPE) {
        int64_t flag = static_cast<int64_t>(size % SATELLITE_CORE);
        dataMessageParcel.WriteInt64(flag);
        int32_t state = static_cast<int32_t>(size % SATELLITE_TYPE);
        dataMessageParcel.WriteInt32(state);
    }
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    std::shared_ptr<SatelliteCoreCallback> callback = std::make_shared<SatelliteCoreCallback>(nullptr);
    if (callback == nullptr) {
        return;
    }
    callback->OnSetRadioStateResponse(dataMessageParcel, reply);
}

void RadioStateChanged(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t eventId = static_cast<int32_t>(size % SATELLITE_CORE);
    dataMessageParcel.WriteInt32(eventId);
    int32_t dataType = static_cast<int32_t>(size % SATELLITE_TYPE);
    dataMessageParcel.WriteInt32(dataType);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    std::shared_ptr<SatelliteCoreCallback> callback = std::make_shared<SatelliteCoreCallback>(nullptr);
    if (callback == nullptr) {
        return;
    }
    callback->OnRadioStateChanged(dataMessageParcel, reply);
}

void SatelliteStatusChanged(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t eventId = static_cast<int32_t>(size % SATELLITE_CORE);
    dataMessageParcel.WriteInt32(eventId);
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    int32_t mode = static_cast<int32_t>(size % SATELLITE_TYPE);
    dataMessageParcel.WriteInt32(mode);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    std::shared_ptr<SatelliteCoreCallback> callback = std::make_shared<SatelliteCoreCallback>(nullptr);
    if (callback == nullptr) {
        return;
    }
    callback->OnSatelliteStatusChanged(dataMessageParcel, reply);
}

void SimStateChanged(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t eventId = static_cast<int32_t>(size % SATELLITE_CORE);
    dataMessageParcel.WriteInt32(eventId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    std::shared_ptr<SatelliteCoreCallback> callback = std::make_shared<SatelliteCoreCallback>(nullptr);
    if (callback == nullptr) {
        return;
    }
    callback->OnSimStateChanged(dataMessageParcel, reply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OnRemoteRequest(data, size);
    SetRadioStateResponse(data, size);
    RadioStateChanged(data, size);
    SatelliteStatusChanged(data, size);
    SimStateChanged(data, size);
    auto telRilManager = DelayedSingleton<CoreService>::GetInstance()->telRilManager_;
    if (telRilManager == nullptr || telRilManager->handler_ == nullptr) {
        return;
    }
    telRilManager->handler_->ClearFfrt(false);
    telRilManager->handler_->queue_ = nullptr;
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    OHOS::DelayedSingleton<CoreService>::DestroyInstance();
    return 0;
}
