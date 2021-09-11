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
#include "cellular_data_types.h"

namespace OHOS {
namespace Telephony {
int32_t CellularDataServiceProxy::IsCellularDataEnabled(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        return CellularData::H_CODE_FAILED;
    }
    Remote()->SendRequest(IS_CELLULAR_DATA_ENABLED, data, reply, option);
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::EnableCellularData(int32_t slotId, bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    data.WriteBool(enable);
    if (Remote() == nullptr) {
        return CellularData::H_CODE_FAILED;
    }
    auto result = Remote()->SendRequest(ENABLE_CELLULAR_DATA, data, reply, option);
    result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::GetCellularDataState(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        return CellularData::H_CODE_FAILED;
    }
    Remote()->SendRequest(GET_CELLULAR_DATA_STATE, data, reply, option);
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::IsDataRoamingEnabled(int32_t slotId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    if (Remote() == nullptr) {
        return CellularData::H_CODE_FAILED;
    }
    Remote()->SendRequest(IS_DATA_ROAMING_ENABLED, data, reply, option);
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::EnableDataRoaming(int32_t slotId, bool enable)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteInt32(slotId);
    data.WriteBool(enable);
    if (Remote() == nullptr) {
        return CellularData::H_CODE_FAILED;
    }
    Remote()->SendRequest(ENABLE_DATA_ROAMING, data, reply, option);
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::ReleaseNet(std::string ident, uint32_t capability)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteString(ident);
    data.WriteUint32(capability);
    if (Remote() == nullptr) {
        return CellularData::H_CODE_FAILED;
    }
    Remote()->SendRequest(RELEASE_CELLULAR_DATA, data, reply, option);
    auto result = reply.ReadInt32();
    return result;
}

int32_t CellularDataServiceProxy::RequestNet(std::string ident, uint32_t capability)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(CellularDataServiceProxy::GetDescriptor());
    data.WriteString(ident);
    data.WriteUint32(capability);
    if (Remote() == nullptr) {
        return CellularData::H_CODE_FAILED;
    }
    Remote()->SendRequest(REQUEST_CELLULAR_DATA, data, reply, option);
    auto result = reply.ReadInt32();
    return result;
}
} // namespace Telephony
} // namespace OHOS
