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
std::atomic_uint TelRilBase::nextSerialId_(1);
std::unordered_map<int32_t, std::shared_ptr<TelRilRequest>> TelRilBase::requestMap_;
std::mutex TelRilBase::requestLock_;
std::shared_ptr<TelRilHandler> TelRilBase::handler_;

TelRilBase::TelRilBase(int32_t slotId, sptr<IRemoteObject> rilAdapterObj, sptr<HDI::Ril::V1_0::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : observerHandler_(observerHandler), cellularRadio_(rilAdapterObj), rilInterface_(rilInterface), slotId_(slotId)
{
    handler_ = handler;
}

void TelRilBase::ResetRemoteObject(sptr<IRemoteObject> rilAdapterObj)
{
    cellularRadio_ = rilAdapterObj;
}

void TelRilBase::ResetRilInterface(sptr<HDI::Ril::V1_0::IRil> rilInterface)
{
    rilInterface_ = rilInterface;
}

std::shared_ptr<TelRilRequest> TelRilBase::CreateTelRilRequest(
    int32_t request, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = std::make_shared<TelRilRequest>(GetNextSerialId(), request, result);
    std::lock_guard<std::mutex> lockRequest(TelRilBase::requestLock_);
    TelRilBase::requestMap_.insert(std::make_pair(telRilRequest->serialId_, telRilRequest));
    if (handler_ != nullptr) {
        handler_->ApplyRunningLock(TelRilHandler::NORMAL_RUNNING_LOCK);
    } else {
        TELEPHONY_LOGE("handler_ is nullptr!!!");
    }
    return telRilRequest;
}

int32_t TelRilBase::SendInt32Event(int32_t dispatchId, int32_t value)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr!!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(slotId_);
    data.WriteInt32(value);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    TELEPHONY_LOGI("Send Event %{public}d", dispatchId);
    return cellularRadio_->SendRequest(dispatchId, data, reply, option);
}

int32_t TelRilBase::SendInt32sEvent(int32_t dispatchId, int32_t argCount, ...)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr!!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    MessageParcel data;
    MessageParcel reply;
    va_list list;
    va_start(list, argCount);
    int32_t i = 0;
    data.WriteInt32(slotId_);
    while (i < argCount) {
        int32_t value = va_arg(list, int32_t);
        data.WriteInt32(value);
        i++;
    }
    va_end(list);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    TELEPHONY_LOGI("Send Event %{public}d", dispatchId);
    return cellularRadio_->SendRequest(dispatchId, data, reply, option);
}

int32_t TelRilBase::SendCommonBufferEvent(int32_t dispatchId, const void *eventData, const size_t dataLength)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr!!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (eventData == nullptr) {
        TELEPHONY_LOGE("eventData is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(slotId_);
    data.WriteUnpadBuffer(eventData, dataLength);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    TELEPHONY_LOGI("Send Event %{public}d", dispatchId);
    return cellularRadio_->SendRequest(dispatchId, data, reply, option);
}

int32_t TelRilBase::GetNextSerialId(void)
{
    if (nextSerialId_ >= UINT32_MAX) {
        nextSerialId_ = 1;
    }
    return nextSerialId_++;
}

std::shared_ptr<TelRilRequest> TelRilBase::FindTelRilRequest(const HRilRadioResponseInfo &responseInfo)
{
    int32_t serial = responseInfo.serial;
    std::shared_ptr<TelRilRequest> telRilRequest = nullptr;
    std::lock_guard<std::mutex> lockRequest(TelRilBase::requestLock_);
    auto iter = TelRilBase::requestMap_.find(serial);
    if (iter == TelRilBase::requestMap_.end()) {
        TELEPHONY_LOGI("FindTelRilRequest not found serial:%{public}d", serial);
    } else {
        telRilRequest = iter->second;
        if (handler_ != nullptr) {
            handler_->ReduceRunningLock(TelRilHandler::NORMAL_RUNNING_LOCK);
        }
    }
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("Unexpected ack response! sn: %{public}d", serial);
        return telRilRequest;
    }
    // Remove telRilRequest from map.
    TelRilBase::requestMap_.erase(serial);
    return telRilRequest;
}

int32_t TelRilBase::GetSerialId(const AppExecFwk::InnerEvent::Pointer &response, uint32_t requestId)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(requestId, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr, eventId=%{public}d", requestId);
            return -TELEPHONY_ERR_LOCAL_PTR_NULL;
        }

        return telRilRequest->serialId_;
    } else {
        TELEPHONY_LOGE("ERROR : eventId=%{public}d --> cellularRadio_ == nullptr !!!", requestId);
    }
    return -TELEPHONY_ERR_ARGUMENT_INVALID;
}

TelRilBase::SendEvent &TelRilBase::SelfSendEvent(void)
{
    thread_local SendEvent sendEvent = nullptr;
    return sendEvent;
}

int32_t TelRilBase::Response(const char *funcName, MessageParcel &data, UserSendEvent send)
{
    const auto &radioResponseInfo = GetHRilRadioResponse(data);
    if (radioResponseInfo.IsInvalid()) {
        TELEPHONY_LOGE("ERROR: get failed for Radio response, flag: %{public}d!!!", radioResponseInfo.flag);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo.error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }

            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            UserEvent userEvent = {funcName, *this, *handler, data, eventId, radioResponseInfo, *telRilRequest};
            return (*send)(userEvent);
        } else {
            return ErrorResponse(telRilRequest, radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
    return TELEPHONY_ERR_ARGUMENT_INVALID;
}

int32_t TelRilBase::Response(const char *funcName, MessageParcel &data, SendEvent send)
{
    SelfSendEvent() = send;
    auto response = [](UserEvent &event) -> int32_t {
        return ((event.this_).*((event.this_).SelfSendEvent()))(event.funcName_, event.handler_, event.data_,
            event.eventId_);
    };
    int32_t ret = Response(funcName, data, (UserSendEvent)response);
    SelfSendEvent() = nullptr;
    return ret;
}

int32_t TelRilBase::ErrorResponse(const int32_t serial, const HRilErrType err)
{
    std::shared_ptr<HRilRadioResponseInfo> responseInfo = std::make_shared<HRilRadioResponseInfo>();
    responseInfo->serial = serial;
    responseInfo->error = err;
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*responseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : ErrorResponse --> handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        responseInfo->flag = telRilRequest->pointer_->GetParam();
        return handler->SendEvent(eventId, responseInfo);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest  == %p !!!", telRilRequest.get());
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilBase::ErrorResponse(
    std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo)
{
    std::shared_ptr<HRilRadioResponseInfo> respInfo = std::make_shared<HRilRadioResponseInfo>();
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : ErrorResponse --> handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        respInfo->serial = responseInfo.serial;
        respInfo->error = responseInfo.error;
        respInfo->flag = telRilRequest->pointer_->GetParam();
        return handler->SendEvent(eventId, respInfo);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest  == %p !!!", telRilRequest.get());
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilBase::TelRilOnlyReportResponseInfo(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilCall DialResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);

    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    result->flag = telRilRequest->pointer_->GetParam();
    result->error = radioResponseInfo->error;
    result->serial = radioResponseInfo->serial;
    if (!handler->SendEvent(eventId, result)) {
        TELEPHONY_LOGE("Send eventId:%{public}d is failed!", eventId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilBase::TelRilOnlyReportResponseInfo(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    const struct HRilRadioResponseInfo radioResponseInfo = BuildHRilRadioResponseInfo(responseInfo);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::shared_ptr<HRilRadioResponseInfo> result = std::make_shared<HRilRadioResponseInfo>();
    if (result == nullptr) {
        TELEPHONY_LOGE("ERROR : result is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    result->flag = telRilRequest->pointer_->GetParam();
    result->error = radioResponseInfo.error;
    result->serial = radioResponseInfo.serial;
    if (!handler->SendEvent(eventId, result)) {
        TELEPHONY_LOGE("Send eventId:%{public}d is failed!", eventId);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

void TelRilBase::PrintErrorForEmptyPointer(void)
{
    TELEPHONY_LOGE("ERROR : it is empty pointer!!!");
}

const HRilRadioResponseInfo &TelRilBase::GetHRilRadioResponse(MessageParcel &data)
{
    thread_local HRilRadioResponseInfo invalidResponse {};
    const size_t readSpSize = sizeof(HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return invalidResponse;
    }
    const HRilRadioResponseInfo *radioResponseInfo = reinterpret_cast<const HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return invalidResponse;
    }
    return *radioResponseInfo;
}
} // namespace Telephony
} // namespace OHOS
