/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "telephony_state_registry_proxy.h"
#include "telephony_errors.h"

namespace OHOS {
namespace TelephonyState {
int32_t TelephonyStateRegistryProxy::UpdateCallState(int32_t callStatus, const std::u16string &number)
{
    int32_t result = TELEPHONY_NO_ERROR;
    MessageOption option;
    MessageParcel in, out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        result = TELEPHONY_FAIL;
        return result;
    }
    if (!in.WriteInt32(callStatus)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteString16(number)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    result = Remote()->SendRequest(CALL_STATE, in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return result;
}

int32_t TelephonyStateRegistryProxy::UpdateCallStateForSlotIndex(
    int32_t simId, int32_t slotIndex, int32_t callStatus, const std::u16string &number)
{
    int32_t result = TELEPHONY_NO_ERROR;
    MessageOption option;
    MessageParcel in, out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        result = TELEPHONY_FAIL;
        return result;
    }
    if (!in.WriteInt32(simId)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteInt32(slotIndex)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteInt32(callStatus)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteString16(number)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    result = Remote()->SendRequest(CALL_STATE_FOR_ID, in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return result;
}

int32_t TelephonyStateRegistryProxy::UpdateSignalInfo(
    int32_t simId, int32_t slotIndex, const std::vector<sptr<SignalInformation>> &vec)
{
    printf("TelephonyStateRegistryProxy::UpdateSignalInfo start.\n");
    int32_t result = TELEPHONY_NO_ERROR;
    MessageOption option;
    MessageParcel in, out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        result = TELEPHONY_FAIL;
        return result;
    }
    if (!in.WriteInt32(simId)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteInt32(slotIndex)) {
        result = TELEPHONY_FAIL;
        return result;
    }
    printf("TelephonyStateRegistryProxy::UpdateSignalInfo##vec.size = %zu\n", vec.size());
    if (!in.WriteInt32(static_cast<int32_t>(vec.size()))) {
        result = TELEPHONY_FAIL;
        return result;
    }

    for (const auto &v : vec) {
        v->Marshalling(in);
    }

    result = Remote()->SendRequest(SIGNAL_INFO, in, out, option);
    printf("TelephonyStateRegistryProxy::UpdateSignalInfo##result = %d\n", result);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return result;
}

int32_t TelephonyStateRegistryProxy::UpdateNetworkState(
    int32_t simId, int32_t slotIndex, const sptr<NetworkState> &networkState)
{
    int32_t result = TELEPHONY_NO_ERROR;
    MessageOption option;
    MessageParcel in, out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteInt32(simId)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteInt32(slotIndex)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (networkState != nullptr) {
        networkState->Marshalling(in);
    }

    result = Remote()->SendRequest(NET_WORK_STATE, in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return result;
}

int32_t TelephonyStateRegistryProxy::RegisterStateChange(const sptr<TelephonyObserverBroker> &callback,
    int32_t simId, uint32_t mask, const std::u16string &package, bool isUpdate)
{
    int32_t result = TELEPHONY_NO_ERROR;
    MessageOption option;
    MessageParcel in, out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        result = TELEPHONY_FAIL;
        return result;
    }
    if (!in.WriteInt32(simId)) {
        result = TELEPHONY_FAIL;
        return result;
    }
    if (!in.WriteInt32(mask)) {
        result = TELEPHONY_FAIL;
        return result;
    }
    if (!in.WriteBool(isUpdate)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteString16(package)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        result = TELEPHONY_FAIL;
        return result;
    }
    result = Remote()->SendRequest(ADD_OBSERVER, in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return result;
}

int32_t TelephonyStateRegistryProxy::UnregisterStateChange(int32_t simId, uint32_t mask)
{
    int32_t result = TELEPHONY_NO_ERROR;
    MessageOption option;
    MessageParcel in, out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        result = TELEPHONY_FAIL;
        return result;
    }
    if (!in.WriteInt32(simId)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    if (!in.WriteInt32(mask)) {
        result = TELEPHONY_FAIL;
        return result;
    }

    result = Remote()->SendRequest(REMOVE_OBSERVER, in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return result;
}
} // namespace TelephonyState
} // namespace OHOS
