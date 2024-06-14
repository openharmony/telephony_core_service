/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include <cstdint>

#include "cell_information.h"
#include "i_telephony_state_notify.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"
#include "network_state.h"
#include "refbase.h"
#include "signal_information.h"
#include "sim_state_type.h"
#include "string"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_observer_broker.h"
#include "vector"

namespace OHOS {
namespace Telephony {
int32_t TelephonyStateRegistryProxy::UpdateCellularDataConnectState(
    int32_t slotId, int32_t dataStatus, int32_t networkForm)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(dataStatus)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(networkForm)) {
        return TELEPHONY_ERR_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::CELLULAR_DATA_STATE), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UpdateCellularDataFlow(
    int32_t slotId, int32_t dataFlowType)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(dataFlowType)) {
        return TELEPHONY_ERR_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::CELLULAR_DATA_FLOW), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UpdateCallState(
    int32_t slotId, int32_t callStatus, const std::u16string &number)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(callStatus)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteString16(number)) {
        return TELEPHONY_ERR_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::CALL_STATE), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UpdateCallStateForSlotId(
    int32_t slotId, int32_t callId, int32_t callStatus, const std::u16string &number)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(callId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(callStatus)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteString16(number)) {
        return TELEPHONY_ERR_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::CALL_STATE_FOR_ID), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UpdateSignalInfo(
    int32_t slotId, const std::vector<sptr<SignalInformation>> &vec)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write interface token failed");
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        TELEPHONY_LOGE("[slot%{public}d] write slotId fail", slotId);
        return TELEPHONY_ERR_FAIL;
    }
    int32_t size = vec.size();
    if (size < 0 || size > SignalInformation::MAX_SIGNAL_NUM) {
        TELEPHONY_LOGE("signal size error, size=%{public}d", size);
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(size)) {
        TELEPHONY_LOGE("write size failed");
        return TELEPHONY_ERR_FAIL;
    }
    for (const auto &v : vec) {
        v->Marshalling(in);
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("Remote() return nullptr!");
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::SIGNAL_INFO), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UpdateCellInfo(
    int32_t slotId, const std::vector<sptr<CellInformation>> &vec)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    int32_t size = vec.size();
    if (size <= 0 || size > CellInformation::MAX_CELL_NUM) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(size)) {
        return TELEPHONY_ERR_FAIL;
    }
    for (const auto &v : vec) {
        v->Marshalling(in);
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::CELL_INFO), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UpdateNetworkState(
    int32_t slotId, const sptr<NetworkState> &networkState)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (networkState == nullptr || !networkState->Marshalling(in)) {
        return TELEPHONY_ERR_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::NET_WORK_STATE), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UpdateSimState(
    int32_t slotId, CardType type, SimState state, LockReason reason)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(static_cast<int32_t>(type))) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(static_cast<int32_t>(state))) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(static_cast<int32_t>(reason))) {
        return TELEPHONY_ERR_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::SIM_STATE), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::RegisterStateChange(
    const sptr<TelephonyObserverBroker> &callback, int32_t slotId, uint32_t mask, bool isUpdate)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(mask)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteBool(isUpdate)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (callback == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return TELEPHONY_ERR_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::ADD_OBSERVER), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UnregisterStateChange(
    int32_t slotId, uint32_t mask)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_FAIL;
    }
    if (!in.WriteInt32(mask)) {
        return TELEPHONY_ERR_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::REMOVE_OBSERVER), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_SUCCESS;
}

int32_t TelephonyStateRegistryProxy::UpdateCfuIndicator(int32_t slotId, bool cfuResult)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteBool(cfuResult)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::CFU_INDICATOR), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t TelephonyStateRegistryProxy::UpdateVoiceMailMsgIndicator(int32_t slotId, bool voiceMailMsgResult)
{
    MessageOption option;
    MessageParcel in;
    MessageParcel out;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    if (!in.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!in.WriteBool(voiceMailMsgResult)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    int result = remote->SendRequest(
        static_cast<uint32_t>(StateNotifyInterfaceCode::VOICE_MAIL_MSG_INDICATOR), in, out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}

int32_t TelephonyStateRegistryProxy::UpdateIccAccount()
{
    MessageParcel in;
    if (!in.WriteInterfaceToken(TelephonyStateRegistryProxy::GetDescriptor())) {
        return TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    MessageOption option;
    MessageParcel out;
    int result = remote->SendRequest(static_cast<uint32_t>(StateNotifyInterfaceCode::ICC_ACCOUNT_CHANGE), in,
        out, option);
    if (result == ERR_NONE) {
        result = out.ReadInt32();
        return result;
    }
    return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
}
} // namespace Telephony
} // namespace OHOS
