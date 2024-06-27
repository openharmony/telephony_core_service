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

#include "setradiostate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <thread>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "get_network_search_info_callback.h"
#include "napi_util.h"
#include "set_nr_option_mode_callback.h"
#include "set_preferred_network_callback.h"
#include "set_radio_state_callback.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "unistd.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t IMS_TYPE = 3;
constexpr int32_t NR_MODE = 4;
constexpr int32_t NETWORK_MODE = 7;

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

void SetRadioState(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    std::unique_ptr<SetRadioStateCallback> callbackWrap = std::make_unique<SetRadioStateCallback>(nullptr);
    if (callbackWrap == nullptr) {
        return;
    }
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteRemoteObject(callbackWrap.release()->AsObject().GetRefPtr());
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetRadioState(dataMessageParcel, reply);
}

void GetRadioState(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    std::unique_ptr<SetRadioStateCallback> callbackWrap = std::make_unique<SetRadioStateCallback>(nullptr);
    if (callbackWrap == nullptr) {
        return;
    }
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteRemoteObject(callbackWrap.release()->AsObject().GetRefPtr());
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetRadioState(dataMessageParcel, reply);
}

void SetNrOptionMode(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    std::unique_ptr<SetRadioStateCallback> callbackWrap = std::make_unique<SetRadioStateCallback>(nullptr);
    if (callbackWrap == nullptr) {
        return;
    }
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t nrMode = static_cast<int32_t>(*data % NR_MODE);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(nrMode);
    dataMessageParcel.WriteRemoteObject(callbackWrap.release()->AsObject().GetRefPtr());
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetNrOptionMode(dataMessageParcel, reply);
}

void GetNrOptionMode(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    DelayedSingleton<CoreService>::GetInstance()->GetNrOptionMode(slotId, nullptr);
}

void GetNetworkSearchInformation(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    std::unique_ptr<GetNetworkSearchInfoCallback> callbackWrap =
        std::make_unique<GetNetworkSearchInfoCallback>(nullptr);
    if (callbackWrap == nullptr) {
        return;
    }
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteRemoteObject(callbackWrap.release()->AsObject().GetRefPtr());
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetNetworkSearchInformation(dataMessageParcel, reply);
}

void SetNetworkSelectionMode(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    std::unique_ptr<GetNetworkSearchInfoCallback> callbackWrap =
        std::make_unique<GetNetworkSearchInfoCallback>(nullptr);
    if (callbackWrap == nullptr) {
        return;
    }
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t selectionMode = static_cast<int32_t>(*data + sizeof(int32_t));
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(selectionMode);
    dataMessageParcel.WriteBool(false);
    dataMessageParcel.WriteRemoteObject(callbackWrap.release()->AsObject().GetRefPtr());
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetNetworkSelectionMode(dataMessageParcel, reply);
}

void SetPreferredNetwork(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    std::unique_ptr<SetPreferredNetworkCallback> callbackWrap = std::make_unique<SetPreferredNetworkCallback>(nullptr);
    if (callbackWrap == nullptr) {
        return;
    }
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t networkMode = static_cast<int32_t>(*data % NETWORK_MODE);
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(networkMode);
    dataMessageParcel.WriteRemoteObject(callbackWrap.release()->AsObject().GetRefPtr());
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetPreferredNetwork(dataMessageParcel, reply);
}

void SetVoiceCallForwarding(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBool(true);
    std::string number(reinterpret_cast<const char *>(data), size);
    dataMessageParcel.WriteString(number);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnSetVoiceCallForwarding(dataMessageParcel, reply);
}

void GetMaxSimCount(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetMaxSimCount(dataMessageParcel, reply);
}

void GetImsRegStatus(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    int32_t imsRegType = static_cast<int32_t>(*data % IMS_TYPE);
    dataMessageParcel.WriteInt32(imsRegType);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetImsRegStatus(dataMessageParcel, reply);
}

void GetCellLocation(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetCellLocation(dataMessageParcel, reply);
}

void RegisterImsRegInfoCallback(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t imsRegType = static_cast<int32_t>(*data % IMS_TYPE);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(imsRegType);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnRegisterImsRegInfoCallback(dataMessageParcel, reply);
}

void UnRegisterImsRegInfoCallback(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t imsRegType = static_cast<int32_t>(*data % IMS_TYPE);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(imsRegType);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnUnregisterImsRegInfoCallback(dataMessageParcel, reply);
}

void GetSimOperatorNumeric(const uint8_t *data, size_t size)
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
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimOperatorNumeric(dataMessageParcel, reply);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    SetRadioState(data, size);
    GetRadioState(data, size);
    SetNrOptionMode(data, size);
    GetNrOptionMode(data, size);
    GetNetworkSearchInformation(data, size);
    SetNetworkSelectionMode(data, size);
    SetPreferredNetwork(data, size);
    SetVoiceCallForwarding(data, size);
    GetMaxSimCount(data, size);
    GetImsRegStatus(data, size);
    GetCellLocation(data, size);
    RegisterImsRegInfoCallback(data, size);
    UnRegisterImsRegInfoCallback(data, size);
    GetSimOperatorNumeric(data, size);
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
