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

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("IsSatelliteEnabled Remote is null");
        return result;
    }
    int32_t ret =
        remote->SendRequest(uint32_t(SatelliteServiceInterfaceCode::IS_SATELLITE_ENABLED), data, reply, option);
    if (ret != ERR_NONE) {
        TELEPHONY_LOGE("IsSatelliteEnabled failed, error code is %{public}d ", ret);
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

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetSatelliteCapability Remote is null");
        return result;
    }
    int32_t ret =
        remote->SendRequest(uint32_t(SatelliteServiceInterfaceCode::GET_SATELLITE_CAPABILITY), data, reply, option);
    if (ret != ERR_NONE) {
        TELEPHONY_LOGE("GetSatelliteCapability failed, error code is %{public}d ", ret);
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
    int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    if (callback == nullptr) {
        TELEPHONY_LOGE("RegisterCoreNotify callback is null");
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("RegisterCoreNotify WriteInterfaceToken is false");
        return ret;
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

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("RegisterCoreNotify Remote is null");
        return ret;
    }

    TELEPHONY_LOGD("Satellite RegisterCoreNotify slotId: %{public}d, what: %{public}d", slotId, what);
    ret = remote->SendRequest(uint32_t(SatelliteServiceInterfaceCode::REGISTER_CORE_NOTIFY), data, reply, option);
    if (ret != ERR_NONE) {
        TELEPHONY_LOGE("RegisterCoreNotify failed, error code is %{public}d ", ret);
        return ret;
    }

    if (!reply.ReadInt32(ret)) {
        TELEPHONY_LOGE("RegisterCoreNotify read reply failed");
    }
    return ret;
}

int32_t SatelliteServiceProxy::UnRegisterCoreNotify(int32_t slotId, int32_t what)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("UnRegisterCoreNotify WriteInterfaceToken is false");
        return ret;
    }
    if (!data.WriteInt32(slotId)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }
    if (!data.WriteInt32(what)) {
        return TELEPHONY_ERR_WRITE_DATA_FAIL;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("UnRegisterCoreNotify Remote is null");
        return ret;
    }

    TELEPHONY_LOGD("Satellite UnRegisterCoreNotify slotId: %{public}d, what: %{public}d", slotId, what);
    ret = remote->SendRequest(uint32_t(SatelliteServiceInterfaceCode::UNREGISTER_CORE_NOTIFY), data, reply, option);
    if (ret != ERR_NONE) {
        TELEPHONY_LOGE("UnRegisterCoreNotify failed, error code is %{public}d ", ret);
        return ret;
    }

    if (!reply.ReadInt32(ret)) {
        TELEPHONY_LOGE("UnRegisterCoreNotify read reply failed");
    }
    return ret;
}

int32_t SatelliteServiceProxy::SetRadioState(int32_t slotId, int32_t isRadioOn, int32_t rst)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("SetRadioState WriteInterfaceToken is false");
        return ret;
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

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("SetRadioState Remote is null");
        return ret;
    }

    TELEPHONY_LOGD("Satellite SetRadioState slotId: %{public}d", slotId);
    ret = remote->SendRequest(uint32_t(SatelliteServiceInterfaceCode::SET_RADIO_STATE), data, reply, option);
    if (ret != ERR_NONE) {
        TELEPHONY_LOGE("SetRadioState failed, error code is %{public}d ", ret);
        return ret;
    }

    if (!reply.ReadInt32(ret)) {
        TELEPHONY_LOGE("SetRadioState read reply failed");
    }
    return ret;
}

std::string SatelliteServiceProxy::GetImei()
{
    MessageParcel data;
    std::string imei = "";
    if (!WriteInterfaceToken(data)) {
        TELEPHONY_LOGE("GetImei WriteInterfaceToken is false");
        return imei;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("GetImei Remote is null");
        return imei;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(uint32_t(SatelliteServiceInterfaceCode::GET_IMEI), data, reply, option);
    if (ret != ERR_NONE) {
        TELEPHONY_LOGE("GetImei failed, error code is %{public}d ", ret);
        return imei;
    }
    if (!reply.ReadString(imei)) {
        TELEPHONY_LOGE("GetImei read reply failed");
    }
    return imei;
}

sptr<IRemoteObject> SatelliteServiceProxy::GetProxyObjectPtr(SatelliteServiceProxyType proxyType)
{
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(SatelliteServiceProxy::GetDescriptor())) {
        TELEPHONY_LOGE("write descriptor fail");
        return nullptr;
    }
    dataParcel.WriteInt32(static_cast<int32_t>(proxyType));
    auto remote = Remote();
    if (remote == nullptr) {
        TELEPHONY_LOGE("function Remote() return nullptr!");
        return nullptr;
    }
    MessageParcel replyParcel;
    MessageOption option;
    int32_t error = remote->SendRequest(
        static_cast<int32_t>(SatelliteServiceInterfaceCode::GET_PROXY_OBJECT_PTR), dataParcel, replyParcel, option);
    if (error != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function GetProxyObjectPtr failed! errCode:%{public}d", error);
        return nullptr;
    }
    return replyParcel.ReadRemoteObject();
}
} // namespace Telephony
} // namespace OHOS
