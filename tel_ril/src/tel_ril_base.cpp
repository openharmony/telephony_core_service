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

#include "tel_ril_base.h"

namespace OHOS {
std::atomic_int TelRilBase::nextSerialId_(1);
std::unordered_map<int32_t, std::shared_ptr<TelRilRequest>> TelRilBase::requestMap_;

TelRilBase::TelRilBase(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
{
    observerHandler_ = observerHandler;
    cellularRadio_ = cellularRadio;
}

std::shared_ptr<TelRilRequest> TelRilBase::CreateTelRilRequest(
    int request, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        std::make_shared<TelRilRequest>(GetNextSerialId(), request, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_DEBUG_LOG("TelRilBase telRilRequest is nullptr");
        return nullptr;
    }

    TelRilBase::requestMap_.insert(std::make_pair(telRilRequest->serialId_, telRilRequest));
    return telRilRequest;
}

int32_t TelRilBase::SendInt32Event(int32_t dispatchId, int32_t value)
{
    TELEPHONY_DEBUG_LOG("TelRilBase SendInt32Event, dispatchId:%{public}d, value:%{public}d", dispatchId, value);
    int status = 0;
    if (cellularRadio_ != nullptr) {
        OHOS::MessageParcel data;
        OHOS::MessageParcel reply;
        data.WriteInt32(value);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        status = cellularRadio_->SendRequest(dispatchId, data, reply, option);
        TELEPHONY_INFO_LOG(
            "TelRilBase SendInt32Event, dispatchId:%{public}d, status:%{public}d", dispatchId, status);
    }
    return status;
}

int32_t TelRilBase::SendStringEvent(int32_t dispatchId, const char *value)
{
    TELEPHONY_DEBUG_LOG("TelRilBase SendStringEvent, dispatchId:%d, status:%c", dispatchId, *value);
    int status = HDF_FAILURE;
    if (cellularRadio_ != nullptr) {
        OHOS::MessageParcel data;
        OHOS::MessageParcel reply;
        data.WriteCString(value);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        status = cellularRadio_->SendRequest(dispatchId, data, reply, option);
        TELEPHONY_INFO_LOG("TelRilBase SendStringEvent, dispatchId:%d, status:%d", dispatchId, status);
    }
    return status;
}

int32_t TelRilBase::SendBufferEvent(int32_t dispatchId, OHOS::MessageParcel &eventData)
{
    TELEPHONY_INFO_LOG("TelRilBase SendBufferEvent, dispatchId:%{public}d", dispatchId);
    int status = HDF_FAILURE;
    if (cellularRadio_ != nullptr) {
        OHOS::MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        status = cellularRadio_->SendRequest(dispatchId, eventData, reply, option);
        TELEPHONY_INFO_LOG(
            "TelRilBase SendBufferEvent, dispatchId:%{public}d, status:%{public}d", dispatchId, status);
    }
    return status;
}

int32_t TelRilBase::SendCommonBufferEvent(int32_t dispatchId, const void *eventData, const size_t dataLength)
{
    TELEPHONY_INFO_LOG("TelRilBase SendCommonBufferEvent, dispatchId:%{public}d", dispatchId);
    int status = HDF_FAILURE;
    if (cellularRadio_ != nullptr) {
        OHOS::MessageParcel data;
        OHOS::MessageParcel reply;
        data.WriteUnpadBuffer(eventData, dataLength);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        status = cellularRadio_->SendRequest(dispatchId, data, reply, option);
        TELEPHONY_INFO_LOG(
            "TelRilBase SendCommonBufferEvent, dispatchId:%{public}d, status:%{public}d", dispatchId, status);
    }
    return status;
}

void TelRilBase::SendRespOrNotiAck()
{
    TELEPHONY_DEBUG_LOG("TelRilBase SendRespOrNotiAck -> ");
    SendInt32Event(HRIL_RESPONSE_ACKNOWLEDGEMENT, 0);
}

std::shared_ptr<TelRilRequest> TelRilBase::FindTelRilRequest(const HRilRadioResponseInfo &responseInfo)
{
    int32_t serial = responseInfo.serial;
    HRilResponseType type = responseInfo.type;
    TELEPHONY_INFO_LOG("TelRilBase FindTelRilRequest type: %{public}d", type);
    std::shared_ptr<TelRilRequest> telRilRequest;

    auto iter = TelRilBase::requestMap_.find(serial);
    if (iter == TelRilBase::requestMap_.end()) {
        TELEPHONY_DEBUG_LOG("FindTelRilRequest not found serial:%{public}d", serial);
    } else {
        telRilRequest = iter->second;
    }
    TELEPHONY_DEBUG_LOG("RilProcessResponseserial : %{public}d", serial);
    if (telRilRequest == nullptr || type == HRilResponseType::HRIL_RESP_ACK) {
        TELEPHONY_ERR_LOG("Unexpected solicited ack response! sn: %{public}d", serial);
        return telRilRequest;
    }

    // Remove telRilRequest from map.
    TelRilBase::requestMap_.erase(serial);

    return telRilRequest;
}

void TelRilBase::RilProcessIndication(int32_t indicationType)
{
    if (indicationType != static_cast<int>(HRilNotiType::HRIL_NOTIFICATION_ACK_NEED)) {
        TELEPHONY_DEBUG_LOG("TelRilBase RilProcessIndication Unsol response received; Sending ack to ril.cp");
        return;
    }

    SendRespOrNotiAck();
}
} // namespace OHOS
