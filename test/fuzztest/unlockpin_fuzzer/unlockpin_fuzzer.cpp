/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "unlockpin_fuzzer.h"

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

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t SLEEP_TIME_SECONDS = 3;

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

void UnlockPin(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    std::string pin(reinterpret_cast<const char *>(data), size);
    std::u16string pinStr = Str8ToStr16(pin);
    dataMessageParcel.WriteString16(pinStr);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnUnlockPin(dataMessageParcel, reply);
}

void UnlockPuk(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    std::string pin(reinterpret_cast<const char *>(data), size);
    std::u16string pinStr = Str8ToStr16(pin);
    dataMessageParcel.WriteString16(pinStr);
    std::string puk(reinterpret_cast<const char *>(data), size);
    std::u16string pukStr = Str8ToStr16(puk);
    dataMessageParcel.WriteString16(pukStr);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnUnlockPuk(dataMessageParcel, reply);
}

void AlterPin(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    std::string newPin(reinterpret_cast<const char *>(data), size);
    std::u16string newPinStr = Str8ToStr16(newPin);
    dataMessageParcel.WriteString16(newPinStr);
    std::string oldPin(reinterpret_cast<const char *>(data), size);
    std::u16string oldPinStr = Str8ToStr16(oldPin);
    dataMessageParcel.WriteString16(oldPinStr);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnAlterPin(dataMessageParcel, reply);
}

void UnlockPin2(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    std::string pin2(reinterpret_cast<const char *>(data), size);
    std::u16string pin2Str = Str8ToStr16(pin2);
    dataMessageParcel.WriteString16(pin2Str);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnUnlockPin2(dataMessageParcel, reply);
}

void UnlockPuk2(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    std::string pin2(reinterpret_cast<const char *>(data), size);
    std::u16string pin2Str = Str8ToStr16(pin2);
    dataMessageParcel.WriteString16(pin2Str);
    std::string puk2(reinterpret_cast<const char *>(data), size);
    std::u16string puk2Str = Str8ToStr16(puk2);
    dataMessageParcel.WriteString16(puk2Str);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnUnlockPuk2(dataMessageParcel, reply);
}

void AlterPin2(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    std::string newPin2(reinterpret_cast<const char *>(data), size);
    std::u16string newPin2Str = Str8ToStr16(newPin2);
    dataMessageParcel.WriteString16(newPin2Str);
    std::string oldPin2(reinterpret_cast<const char *>(data), size);
    std::u16string oldPin2Str = Str8ToStr16(oldPin2);
    dataMessageParcel.WriteString16(oldPin2Str);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnAlterPin2(dataMessageParcel, reply);
}

void SetLockState(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    int32_t lockType = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(lockType);
    int32_t lockState = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(lockState);
    std::string password(reinterpret_cast<const char *>(data), size);
    std::u16string passwordStr = Str8ToStr16(password);
    dataMessageParcel.WriteString16(passwordStr);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetLockState(dataMessageParcel, reply);
}

void SetActiveSim(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    int32_t enable = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(enable);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetActiveSim(dataMessageParcel, reply);
}

void DiallingNumbersGet(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    int32_t type = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(type);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnDiallingNumbersGet(dataMessageParcel, reply);
}

void DelIccDiallingNumbers(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    int32_t type = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(type);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnDelIccDiallingNumbers(dataMessageParcel, reply);
}

void UnlockSimLock(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    int32_t lockType = static_cast<int32_t>(size % SLOT_NUM);
    dataMessageParcel.WriteInt32(lockType);
    std::string password(reinterpret_cast<const char *>(data), size);
    std::u16string passwordStr = Str8ToStr16(password);
    dataMessageParcel.WriteString16(passwordStr);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnUnlockSimLock(dataMessageParcel, reply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    UnlockPin(data, size);
    UnlockPuk(data, size);
    AlterPin(data, size);
    UnlockPin2(data, size);
    UnlockPuk2(data, size);
    AlterPin2(data, size);
    SetLockState(data, size);
    SetActiveSim(data, size);
    DiallingNumbersGet(data, size);
    DelIccDiallingNumbers(data, size);
    UnlockSimLock(data, size);
    auto telRilManager = DelayedSingleton<CoreService>::GetInstance()->telRilManager_;
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
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    OHOS::DelayedSingleton<CoreService>::DestroyInstance();
    return 0;
}
