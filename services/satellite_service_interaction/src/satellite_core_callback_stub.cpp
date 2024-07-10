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

#include "satellite_core_callback_stub.h"

#include "tel_ril_base_parcel.h"
#include "radio_event.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"


namespace OHOS {
namespace Telephony {
SatelliteCoreCallbackStub::SatelliteCoreCallbackStub()
{
    TELEPHONY_LOGD("SatelliteCoreCallbackStub");
    InitFuncMap();
}

void SatelliteCoreCallbackStub::InitFuncMap()
{
    requestFuncMap_[static_cast<uint32_t>(SatelliteCoreCallbackInterfaceCode::SET_RADIO_STATE_RESPONSE)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSetRadioStateResponse(data, reply); };
    requestFuncMap_[static_cast<uint32_t>(SatelliteCoreCallbackInterfaceCode::RADIO_STATE_CHANGED)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnRadioStateChanged(data, reply); };
    requestFuncMap_[static_cast<uint32_t>(SatelliteCoreCallbackInterfaceCode::SATELLITE_STATUS_CHANGED)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSatelliteStatusChanged(data, reply); };
    requestFuncMap_[static_cast<uint32_t>(SatelliteCoreCallbackInterfaceCode::SIM_STATE_CHANGED)] =
        [this](MessageParcel &data, MessageParcel &reply) { return OnSimStateChanged(data, reply); };
}

SatelliteCoreCallbackStub::~SatelliteCoreCallbackStub()
{
    requestFuncMap_.clear();
}

int32_t SatelliteCoreCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string myDescriptor = SatelliteCoreCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (myDescriptor != remoteDescriptor) {
        TELEPHONY_LOGE("Descriptor check failed, return");
        return TELEPHONY_ERR_DESCRIPTOR_MISMATCH;
    }
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return requestFunc(data, reply);
        }
    }
    TELEPHONY_LOGD("Do not found the requestFunc of code=%{public}d, need to check", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SatelliteCoreCallbackStub::OnSetRadioStateResponse(MessageParcel &data, MessageParcel &reply)
{
    int32_t eventCode = data.ReadInt32();
    int32_t dataType = data.ReadInt32();
    if (dataType == SatelliteRadioResponseType::DEFAULT_RADIO_RESPONSE) {
        int32_t flag = data.ReadInt32();
        int32_t serial = data.ReadInt32();
        int32_t error = data.ReadInt32();
        int32_t type = data.ReadInt32();
        auto info = std::make_shared<RadioResponseInfo>();
        if (info == nullptr) {
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        info->flag = flag;
        info->serial = serial;
        info->error = static_cast<ErrType>(error);
        info->type = static_cast<ResponseTypes>(type);
        AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventCode, info);
        if (response == nullptr) {
            TELEPHONY_LOGE("hril response is null!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        reply.WriteInt32(SetRadioStateResponse(response));
        return TELEPHONY_SUCCESS;
    }

    if (dataType == SatelliteRadioResponseType::RADIO_STATE_INFO) {
        int64_t flag = data.ReadInt64();
        int32_t state = data.ReadInt32();
        auto info = std::make_unique<RadioStateInfo>();
        if (info == nullptr) {
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        info->flag = flag;
        info->state = state;
        AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventCode, info);
        if (response == nullptr) {
            TELEPHONY_LOGE("radio info response is null!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        reply.WriteInt32(SetRadioStateResponse(response));
        return TELEPHONY_SUCCESS;
    }

    TELEPHONY_LOGE("SatelliteCoreCallbackStub: radio response is null!");
    return TELEPHONY_ERR_READ_DATA_FAIL;
}

int32_t SatelliteCoreCallbackStub::OnRadioStateChanged(MessageParcel &data, MessageParcel &reply)
{
    int32_t eventCode = data.ReadInt32();

    auto info = std::make_shared<Int32Parcel>();
    if (!data.ReadInt32(info->data)) {
        TELEPHONY_LOGE("Int32Parcel is null!");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }

    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventCode, info);
    if (response == nullptr) {
        TELEPHONY_LOGE("response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    reply.WriteInt32(RadioStateChanged(response));
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCoreCallbackStub::OnSatelliteStatusChanged(MessageParcel &data, MessageParcel &reply)
{
    int32_t eventCode = data.ReadInt32();
    std::shared_ptr<SatelliteStatus> satelliteStatus = std::make_shared<SatelliteStatus>();
    satelliteStatus->slotId = data.ReadInt32();
    satelliteStatus->mode = data.ReadInt32();
    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventCode, satelliteStatus);
    if (response == nullptr) {
        TELEPHONY_LOGE("response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    reply.WriteInt32(SatelliteStatusChanged(response));
    return TELEPHONY_SUCCESS;
}

int32_t SatelliteCoreCallbackStub::OnSimStateChanged(MessageParcel &data, MessageParcel &reply)
{
    int32_t eventCode = data.ReadInt32();

    AppExecFwk::InnerEvent::Pointer response = AppExecFwk::InnerEvent::Get(eventCode);
    if (response == nullptr) {
        TELEPHONY_LOGE("response is null!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    reply.WriteInt32(SimStateChanged(response));
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS
