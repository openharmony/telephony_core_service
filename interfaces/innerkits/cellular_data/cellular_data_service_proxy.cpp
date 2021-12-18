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

#include "cellular_data_service_proxy.h"

#include "message_parcel.h"

#include "cellular_data_types.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
int32_t CellularDataServiceProxy::IsCellularDataEnabled()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::IS_CELLULAR_DATA_ENABLED, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function IsCellularDataEnabled call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::EnableCellularData(bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteBool(enable);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::ENABLE_CELLULAR_DATA, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function EnableCellularData call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::GetCellularDataState()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::GET_CELLULAR_DATA_STATE, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetCellularDataState call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::IsCellularDataRoamingEnabled(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::IS_DATA_ROAMING_ENABLED, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function IsCellularDataRoamingEnabled call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::EnableCellularDataRoaming(int32_t slotId, bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    data.WriteBool(enable);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::ENABLE_DATA_ROAMING, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function EnableCellularDataRoaming call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::ReleaseNet(std::string ident, uint64_t capability)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteString(ident);
    data.WriteUint64(capability);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::RELEASE_CELLULAR_DATA, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("ReleaseNet call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::RequestNet(std::string ident, uint64_t capability)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteString(ident);
    data.WriteUint64(capability);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::REQUEST_CELLULAR_DATA, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("RequestNet call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::HandleApnChanged(int32_t slotId, std::string apns)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    data.WriteString(apns);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::APN_DATA_CHANGED, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("HandleApnChanged call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::GetDefaultCellularDataSlotId()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::GET_DEFAULT_SLOT_ID, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetDefaultCellularDataSlotId call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::SetDefaultCellularDataSlotId(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::SET_DEFAULT_SLOT_ID, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function SetDefaultCellularDataSlotId call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::GetCellularDataFlowType()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::GET_FLOW_TYPE_ID, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetCellularDataFlowType call failed! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::StrategySwitch(bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteBool(enable);
    if (Remote() == nullptr) {
        TELEPHONY_LOGE("remote is null");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto error = Remote()->SendRequest((uint32_t)FuncCode::STRATEGY_SWITCH, data, reply, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Strategy switch fail! errCode:%{public}d", error);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    auto result = reply.ReadInt32();
    return result;
}
} // namespace Telephony
} // namespace OHOS