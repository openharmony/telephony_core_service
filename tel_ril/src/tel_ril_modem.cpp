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

#include "tel_ril_modem.h"

namespace OHOS {
namespace Telephony {
void TelRilModem::AddHandlerToMap()
{
    // indication
    memberFuncMap_[HNOTI_MODEM_RADIO_STATE_UPDATED] = &TelRilModem::RadioStateUpdated;
    // response
    memberFuncMap_[HREQ_MODEM_SET_RADIO_STATUS] = &TelRilModem::SetRadioStatusResponse;
    memberFuncMap_[HREQ_MODEM_GET_RADIO_STATUS] = &TelRilModem::GetRadioStatusResponse;
}

TelRilModem::TelRilModem(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilModem::IsCommonRespOrNotify(uint32_t code)
{
    return IsCommonResponse(code) || IsCommonNotification(code);
}
void TelRilModem::ProcessCommonRespOrNotify(uint32_t code, MessageParcel &data)
{
    TELEPHONY_LOGD("TelRilModem ProcessCommonRespOrNotify code:%{public}d, GetDataSize:%{public}zu", code,
        data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

bool TelRilModem::IsCommonResponse(uint32_t code)
{
    return code >= HREQ_COMMON_BASE;
}

bool TelRilModem::IsCommonNotification(uint32_t code)
{
    return code >= HREQ_COMMON_BASE;
}

void TelRilModem::SetRadioStatusResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilModem SetRadioStatusResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetRadioStatusResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD("SetRadioStatusResponse serial:%{public}d, error:%{public}d ", radioResponseInfo->serial,
        radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGD("SetRadioStatusResponse serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_,
        telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGW("WARNING : SetRadioStatusResponse --> handler == nullptr !!!");
                return;
            }

            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGD("message id:%{public}d", eventId);
            std::unique_ptr<HRilRadioStateInfo> radioState = std::make_unique<HRilRadioStateInfo>();
            radioState->flag = telRilRequest->pointer_->GetParam();
            radioState->state = (int32_t)(radioResponseInfo->error);
            handler->SendEvent(eventId, radioState);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilModem::GetRadioStatusResponse(MessageParcel &data)
{
    int32_t radioStatus = data.ReadInt32();
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilModem GetRadioStatusResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetRadioStatusResponse --> radioResponseInfo == nullptr !!!");
        return;
    }

    TELEPHONY_LOGD("GetRadioStatusResponse serial:%{public}d, error:%{public}d ", radioResponseInfo->serial,
        radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGD("GetRadioStatusResponse serialId_:%{public}d, requestId_:%{public}d,",
            telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGW("WARNING : GetRadioStatusResponse --> handler == nullptr !!!");
                return;
            }

            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGD("message id:%{public}d", eventId);
            std::unique_ptr<HRilRadioStateInfo> state = std::make_unique<HRilRadioStateInfo>();
            state->flag = telRilRequest->pointer_->GetParam();
            state->state = radioStatus;
            handler->SendEvent(eventId, state);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilModem::SetRadioStatus(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_MODEM_SET_RADIO_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilModem SetRadioStatus:telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(fun);
        data.WriteInt32(rst);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_MODEM_SET_RADIO_STATUS, data, reply, option);
        TELEPHONY_LOGD(
            "SetRadioStatus --> SendBufferEvent(HREQ_MODEM_SET_RADIO_STATUS, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_MODEM_SET_RADIO_STATUS --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilModem::GetRadioStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_MODEM_GET_RADIO_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilModem GetRadioStatus:telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_MODEM_GET_RADIO_STATUS, data, reply, option);
        TELEPHONY_LOGD(
            "GetRadioStatus --> SendBufferEvent(HREQ_MODEM_GET_RADIO_STATUS, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_MODEM_GET_RADIO_STATUS --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilModem::RadioStateUpdated(MessageParcel &data)
{
    int32_t radioState = data.ReadInt32();
    int32_t indicationType = data.ReadInt32();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("observerHandler_ is nullptr, tpye:%{public}d", indicationType);
        return;
    }
    std::shared_ptr<int> state = std::make_shared<int>();
    *state = radioState;
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_STATE_CHANGED, state);
}
} // namespace Telephony
} // namespace OHOS
