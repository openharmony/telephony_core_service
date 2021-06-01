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
#include "parcel.h"

namespace OHOS {
namespace CellularData {
bool CellularDataServiceProxy::IsCellularDataEnabled(int32_t slotId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    Remote()->SendRequest(IS_CELLULAR_DATA_ENABLED, data, reply, option);
    bool result = reply.ReadBool();
    return result;
}

int32_t CellularDataServiceProxy::EnableCellularData(int32_t slotId, bool enable)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    data.WriteBool(enable);
    int32_t result = Remote()->SendRequest(ENABLE_CELLULAR_DATA, data, reply, option);
    result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::GetCellularDataState(int32_t slotId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    Remote()->SendRequest(GET_CELLULAR_DATA_STATE, data, reply, option);
    int32_t result = reply.ReadInt32();
    return result;
}

bool CellularDataServiceProxy::IsDataRoamingEnabled(int32_t slotId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    Remote()->SendRequest(IS_DATA_ROAMING_ENABLED, data, reply, option);
    bool result = reply.ReadBool();
    return result;
}

int32_t CellularDataServiceProxy::EnableDataRoaming(int32_t slotId, bool enable)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    data.WriteBool(enable);
    Remote()->SendRequest(ENABLE_DATA_ROAMING, data, reply, option);
    int32_t result = reply.ReadInt32();
    return result;
}
} // namespace CellularData
} // namespace OHOS
