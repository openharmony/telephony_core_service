/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#include "satellitestatuschanged_fuzzer.h"
 
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
#include "tel_ril_manager.h"
 
using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t RESPONSE_TYPE = 2;
constexpr int32_t SATELLITE_TYPE = 3;
constexpr int32_t SATELLITE_CORE = 4;
constexpr int32_t SLEEP_TIME_SECONDS = 100000;
 
bool IsServiceInited()
{
    auto service = DelayedSingleton<CoreService>::GetInstance();
    if (service == nullptr) {
        return g_isInited;
    }
    if (service->GetServiceRunningState() !=
        static_cast<int32_t>(ServiceRunningState::STATE_RUNNING)) {
        service->OnStart();
    }
    if (!g_isInited && service->GetServiceRunningState() ==
        static_cast<int32_t>(ServiceRunningState::STATE_RUNNING)) {
        g_isInited = true;
    }
    return g_isInited;
}
 
void SetRadioStateResponse(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }
 
    MessageParcel dataMessageParcel;
    int32_t eventId = static_cast<int32_t>(*data % SATELLITE_CORE);
    dataMessageParcel.WriteInt32(eventId);
    int32_t dataType = static_cast<int32_t>(*data % SATELLITE_TYPE);
    dataMessageParcel.WriteInt32(dataType);
    int32_t offset = 0;
    if (dataType == 1) {
        int32_t flag = static_cast<int32_t>(*data + offset);
        dataMessageParcel.WriteInt32(flag);
        offset += sizeof(int32_t);
        int32_t serial = static_cast<int32_t>(*data + offset);
        dataMessageParcel.WriteInt32(serial);
        offset += sizeof(int32_t);
        int32_t error = static_cast<int32_t>(*data + offset);
        dataMessageParcel.WriteInt32(error);
        offset += sizeof(int32_t);
        int32_t type = static_cast<int32_t>(*data + offset);
        dataMessageParcel.WriteInt32(type);
    } else if (dataType == RESPONSE_TYPE) {
        int64_t flag = static_cast<int64_t>(*data + offset);
        dataMessageParcel.WriteInt64(flag);
        offset += sizeof(int32_t);
        int32_t state = static_cast<int32_t>(*data + offset);
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
    int32_t eventId = static_cast<int32_t>(*data % SATELLITE_CORE);
    dataMessageParcel.WriteInt32(eventId);
    int32_t dataType = static_cast<int32_t>(*data % SATELLITE_TYPE);
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
    int32_t eventId = static_cast<int32_t>(*data % SATELLITE_CORE);
    dataMessageParcel.WriteInt32(eventId);
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    int32_t mode = static_cast<int32_t>(*data % SATELLITE_TYPE);
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
    int32_t eventId = static_cast<int32_t>(*data % SATELLITE_CORE);
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
 
    SetRadioStateResponse(data, size);
    RadioStateChanged(data, size);
    SatelliteStatusChanged(data, size);
    SimStateChanged(data, size);
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