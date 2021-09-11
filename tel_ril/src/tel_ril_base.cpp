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
namespace Telephony {
std::atomic_int TelRilBase::nextSerialId_(1);
std::unordered_map<int32_t, std::shared_ptr<TelRilRequest>> TelRilBase::requestMap_;
std::mutex TelRilBase::requestLock_;

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
        TELEPHONY_LOGE("TelRilBase telRilRequest is nullptr");
        return nullptr;
    }
    std::lock_guard<std::mutex> lockRequest(TelRilBase::requestLock_);
    TelRilBase::requestMap_.insert(std::make_pair(telRilRequest->serialId_, telRilRequest));
    return telRilRequest;
}

int32_t TelRilBase::SendInt32Event(int32_t dispatchId, int32_t value)
{
    TELEPHONY_LOGD("TelRilBase SendInt32Event, dispatchId:%{public}d, value:%{public}d", dispatchId, value);
    int status = 0;
    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(value);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        status = cellularRadio_->SendRequest(dispatchId, data, reply, option);
        TELEPHONY_LOGD("TelRilBase SendInt32Event, dispatchId:%{public}d, status:%{public}d", dispatchId, status);
    }
    return status;
}

int32_t TelRilBase::SendStringEvent(int32_t dispatchId, const char *value)
{
    if (value == nullptr) {
        TELEPHONY_LOGD("value is nullptr");
    }
    TELEPHONY_LOGD("TelRilBase SendStringEvent, dispatchId:%d, status:%c", dispatchId, *value);
    int32_t status = HDF_FAILURE;
    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteCString(value);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        status = cellularRadio_->SendRequest(dispatchId, data, reply, option);
        TELEPHONY_LOGD("TelRilBase SendStringEvent, dispatchId:%d, status:%d", dispatchId, status);
    }
    return status;
}

int32_t TelRilBase::SendBufferEvent(int32_t dispatchId, MessageParcel &eventData)
{
    TELEPHONY_LOGD("TelRilBase SendBufferEvent, dispatchId:%{public}d", dispatchId);
    int32_t status = HDF_FAILURE;
    if (cellularRadio_ != nullptr) {
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        status = cellularRadio_->SendRequest(dispatchId, eventData, reply, option);
        TELEPHONY_LOGD("TelRilBase SendBufferEvent, dispatchId:%{public}d, status:%{public}d", dispatchId, status);
    }
    return status;
}

int32_t TelRilBase::SendCommonBufferEvent(int32_t dispatchId, const void *eventData, const size_t dataLength)
{
    if (eventData == nullptr) {
        TELEPHONY_LOGE("eventData is nullptr");
    }
    TELEPHONY_LOGD("TelRilBase SendCommonBufferEvent, dispatchId:%{public}d", dispatchId);
    int32_t status = HDF_FAILURE;
    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteUnpadBuffer(eventData, dataLength);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        status = cellularRadio_->SendRequest(dispatchId, data, reply, option);
        TELEPHONY_LOGD(
            "TelRilBase SendCommonBufferEvent, dispatchId:%{public}d, status:%{public}d", dispatchId, status);
    }
    return status;
}

std::shared_ptr<TelRilRequest> TelRilBase::FindTelRilRequest(const HRilRadioResponseInfo &responseInfo)
{
    int32_t serial = responseInfo.serial;
    std::shared_ptr<TelRilRequest> telRilRequest;
    std::lock_guard<std::mutex> lockRequest(TelRilBase::requestLock_);
    auto iter = TelRilBase::requestMap_.find(serial);
    if (iter == TelRilBase::requestMap_.end()) {
        TELEPHONY_LOGD("FindTelRilRequest not found serial:%{public}d", serial);
    } else {
        telRilRequest = iter->second;
    }
    TELEPHONY_LOGD("RilProcessResponseSerial : %{public}d", serial);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("Unexpected ack response! sn: %{public}d", serial);
        return telRilRequest;
    }

    // Remove telRilRequest from map.
    TelRilBase::requestMap_.erase(serial);
    return telRilRequest;
}

void TelRilBase::ErrorResponse(const int32_t serial, const HRilErrType err)
{
    TELEPHONY_LOGD("======>enter");
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = std::make_shared<HRilRadioResponseInfo>();
    if (responseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : responseInfo == nullptr failed !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*responseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : ErrorResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        responseInfo->serial = serial;
        responseInfo->error = err;
        responseInfo->flag = telRilRequest->pointer_->GetParam();
        handler->SendEvent(eventId, responseInfo);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilBase::ErrorResponse(
    std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo)
{
    TELEPHONY_LOGD("======>enter");
    std::shared_ptr<HRilRadioResponseInfo> respInfo = std::make_shared<HRilRadioResponseInfo>();
    if (respInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : responseInfo == nullptr failed !!!");
        return;
    }
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : ErrorResponse --> handler == nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        respInfo->serial = responseInfo.serial;
        respInfo->error = responseInfo.error;
        respInfo->flag = telRilRequest->pointer_->GetParam();
        handler->SendEvent(eventId, respInfo);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}
} // namespace Telephony
} // namespace OHOS
