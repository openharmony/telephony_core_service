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

#include "simauthentication_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <thread>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "sim_file.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "unistd.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t TYPE_NUM = 2;
constexpr int32_t SLEEP_TIME_SECONDS = 10;
constexpr int32_t SIM_AUTH_EAP_SIM_TYPE = 128;
constexpr int32_t SIM_AUTH_EAP_AKA_TYPE = 129;
bool g_flag = false;

bool IsServiceInited()
{
    if (!g_isInited) {
        auto onStart = [] { DelayedSingleton<CoreService>::GetInstance()->OnStart(); };
        std::thread startThread(onStart);
        pthread_setname_np(startThread.native_handle(), "simauthentication_fuzzer");
        startThread.join();

        sleep(SLEEP_TIME_SECONDS);
        if (DelayedSingleton<CoreService>::GetInstance()->GetServiceRunningState() ==
            static_cast<int32_t>(ServiceRunningState::STATE_RUNNING)) {
            g_isInited = true;
        }
    }
    return g_isInited;
}

void GetSimTelephoneNumber(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimPhoneNumber(dataMessageParcel, reply);
}

void GetVoiceMailIdentifier(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetVoiceMailInfor(dataMessageParcel, reply);
}

void GetVoiceMailNumber(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetVoiceMailNumber(dataMessageParcel, reply);
}

void QueryIccDiallingNumbers(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(static_cast<int32_t>(size % TYPE_NUM));
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnDiallingNumbersGet(dataMessageParcel, reply);
}

void SimAuthentication(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    std::string authData(reinterpret_cast<const char *>(data), size);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    int32_t authType = static_cast<int32_t>(size % TYPE_NUM);
    if (authType) {
        dataMessageParcel.WriteInt32(SIM_AUTH_EAP_AKA_TYPE);
    } else {
        dataMessageParcel.WriteInt32(SIM_AUTH_EAP_SIM_TYPE);
    }
    dataMessageParcel.WriteString(authData);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSimAuthentication(dataMessageParcel, reply);
}

void ParseOpl5g(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    if (g_flag) {
        return;
    }
    g_flag = true;

    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<SimFile> simFile = std::make_shared<SimFile>(simStateManager);
    std::string fileData(reinterpret_cast<const char *>(data), size);
    std::vector<std::string> records;
    records.push_back(fileData);
    simFile->ParseOpl5g(records);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    GetSimTelephoneNumber(data, size);
    GetVoiceMailIdentifier(data, size);
    GetVoiceMailNumber(data, size);
    QueryIccDiallingNumbers(data, size);
    SimAuthentication(data, size);
    ParseOpl5g(data, size);
    auto telRilManager = DelayedSingleton<CoreService>::GetInstance()->telRilManager_;
    if (telRilManager == nullptr || telRilManager->handler_ == nullptr) {
        return;
    }
    telRilManager->handler_->ClearFfrt(true);
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
