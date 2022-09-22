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

#include "core_service_hisysevent.h"

namespace OHOS {
namespace Telephony {
std::atomic_uint TelRilBase::nextSerialId_(1);
std::unordered_map<int32_t, std::shared_ptr<TelRilRequest>> TelRilBase::requestMap_;
std::mutex TelRilBase::requestLock_;
std::shared_ptr<TelRilHandler> TelRilBase::handler_;

TelRilBase::TelRilBase(int32_t slotId, sptr<HDI::Ril::V1_0::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : observerHandler_(observerHandler), rilInterface_(rilInterface), slotId_(slotId)
{
    handler_ = handler;
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
    if (rilInterface_ == nullptr) {
        TELEPHONY_LOGE("ERROR : eventId=%{public}d --> rilInterface_ == nullptr !!!", requestId);
        return -TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(requestId, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr, eventId=%{public}d", requestId);
        return -TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilRequest->serialId_;
}

void TelRilBase::DfxWriteCallFaultEvent(std::shared_ptr<TelRilRequest> telRilRequest, const int32_t error)
{
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("telRilRequest or telRilRequest->pointer_  is nullptr");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    switch (eventId) {
        case RadioEvent::RADIO_DIAL:
            CoreServiceHiSysEvent::WriteDialCallFaultEvent(slotId_,
                static_cast<int32_t>(CallErrorCode::CALL_ERROR_RADIO_RESPONSEINFO_ERROR),
                "HRilErrType " + std::to_string(error));
            break;
        case RadioEvent::RADIO_ACCEPT_CALL:
            CoreServiceHiSysEvent::WriteAnswerCallFaultEvent(slotId_,
                static_cast<int32_t>(CallErrorCode::CALL_ERROR_RADIO_RESPONSEINFO_ERROR),
                "HRilErrType " + std::to_string(error));
            break;
        case RadioEvent::RADIO_REJECT_CALL:
        case RadioEvent::RADIO_HANGUP_CONNECT:
            CoreServiceHiSysEvent::WriteHangUpFaultEvent(slotId_,
                static_cast<int32_t>(CallErrorCode::CALL_ERROR_RADIO_RESPONSEINFO_ERROR),
                "HRilErrType " + std::to_string(error));
            break;
        default:
            break;
    }
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
        DfxWriteCallFaultEvent(telRilRequest, static_cast<int32_t>(responseInfo.error));
        return handler->SendEvent(eventId, respInfo);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest  == %p !!!", telRilRequest.get());
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}
} // namespace Telephony
} // namespace OHOS
