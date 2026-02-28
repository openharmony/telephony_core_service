/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "satellite_service_proxy.h"

#include "satellite_service_ipc_interface_code.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
bool SatelliteServiceProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(SatelliteServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write interface token failed");
        return false;
    }
    return true;
}

__attribute__((noinline)) int32_t SatelliteServiceProxy::SendRequest(uint32_t msgId, MessageParcel &dataParcel,
    MessageParcel &replyParcel, MessageOption &option)
{
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SatelliteServiceProxy Remote is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return remote->SendRequest(msgId, dataParcel, replyParcel, option);
}

bool SatelliteServiceProxy::IsSatelliteEnabled()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool result = false;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("IsSatelliteEnabled WriteInterfaceToken is false");
        return result;
    }

    int32_t error = SendRequest(uint32_t(SatelliteServiceInterfaceCode::IS_SATELLITE_ENABLED), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("IsSatelliteEnabled failed, error code is %{public}d ", error);
        return result;
    }

    if (!reply.ReadBool(result)) {
        TELEPHONY_LOGE("IsSatelliteEnabled ReadBool failed");
    }
    TELEPHONY_LOGD("Satellite IsSatelliteEnabled %{public}d", result);
    return result;
}

int32_t SatelliteServiceProxy::GetSatelliteCapability()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = 0;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSatelliteCapability WriteInterfaceToken is false");
        return result;
    }

    int32_t error = SendRequest(uint32_t(SatelliteServiceInterfaceCode::GET_SATELLITE_CAPABILITY), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetSatelliteCapability failed, error code is %{public}d ", error);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        TELEPHONY_LOGE("GetSatelliteCapability ReadInt32 failed");
    }
    TELEPHONY_LOGD("Satellite GetSatelliteCapability %{public}d", result);
    return result;
}

int32_t SatelliteServiceProxy::RegisterCoreNotify(
    int32_t slotId, int32_t what, const sptr<ISatelliteCoreCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t error = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    if (callback == nullptr) {
        TELEPHONY_LOGE("RegisterCoreNotify callback is null");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RegisterCoreNotify WriteInterfaceToken is false");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(what)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    error = SendRequest(uint32_t(SatelliteServiceInterfaceCode::REGISTER_CORE_NOTIFY), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("RegisterCoreNotify failed, error code is %{public}d ", error);
        return result;
    }

    TELEPHONY_LOGD("Satellite RegisterCoreNotify slotId: %{public}d, what: %{public}d", slotId, what);
    if (!reply.ReadInt32(error)) {
        TELEPHONY_LOGE("RegisterCoreNotify read reply failed");
    }
    return error;
}

int32_t SatelliteServiceProxy::UnRegisterCoreNotify(int32_t slotId, int32_t what)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t error = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnRegisterCoreNotify WriteInterfaceToken is false");
        return error;
    }
    if (!data.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(what)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    error = SendRequest(uint32_t(SatelliteServiceInterfaceCode::UNREGISTER_CORE_NOTIFY), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("UnRegisterCoreNotify failed, error code is %{public}d ", error);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    TELEPHONY_LOGD("Satellite UnRegisterCoreNotify slotId: %{public}d, what: %{public}d", slotId, what);
    if (!reply.ReadInt32(error)) {
        TELEPHONY_LOGE("UnRegisterCoreNotify read reply failed");
    }
    return error;
}

int32_t SatelliteServiceProxy::SetRadioState(int32_t slotId, int32_t isRadioOn, int32_t rst)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t error = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetRadioState WriteInterfaceToken is false");
        return error;
    }
    if (!data.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(isRadioOn)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(rst)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    error = SendRequest(uint32_t(SatelliteServiceInterfaceCode::SET_RADIO_STATE), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("SetRadioState failed, error code is %{public}d ", error);
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    TELEPHONY_LOGD("Satellite SetRadioState slotId: %{public}d", slotId);
    if (!reply.ReadInt32(error)) {
        TELEPHONY_LOGE("SetRadioState read reply failed");
    }
    return error;
}

std::string SatelliteServiceProxy::GetImei()
{
    MessageParcel data;
    std::string imei = "";
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetImei WriteInterfaceToken is false");
        return imei;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t error = SendRequest(uint32_t(SatelliteServiceInterfaceCode::GET_IMEI), data, reply, option);
    if (error != ERR_NONE) {
        TELEPHONY_LOGE("GetImei failed, error code is %{public}d ", error);
        return imei;
    }
    if (!reply.ReadString(imei)) {
        TELEPHONY_LOGE("GetImei read reply failed");
    }
    return imei;
}

int32_t SatelliteServiceProxy::GetSatelliteSlotId()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = 0;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetSatelliteSlotId WriteInterfaceToken is false");
        return result;
    }
    result = SendRequest(uint32_t(SatelliteServiceInterfaceCode::GET_SATELLITE_SLOT_ID), data, reply, option);
    if (result != ERR_NONE) {
        TELEPHONY_LOGE("GetSatelliteSlotId failed, error code is %{public}d ", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        TELEPHONY_LOGE("GetSatelliteSlotId read reply failed");
    }
    TELEPHONY_LOGD("Satellite GetSatelliteSlotId %{public}d", result);
    return result;
}

sptr<IRemoteObject> SatelliteServiceProxy::GetProxyObjectPtr(SatelliteServiceProxyType proxyType)
{
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(SatelliteServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return nullptr;
    }
    dataParcel.WriteInt32(static_cast<int32_t>(proxyType));
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = SendRequest(
        uint32_t(SatelliteServiceInterfaceCode::GET_PROXY_OBJECT_PTR), dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetProxyObjectPtr failed, error code is %{public}d ", error);
        return nullptr;
    }
    return replyParcel.ReadRemoteObject();
}
} // namespace Telephony
} // namespace OHOS
