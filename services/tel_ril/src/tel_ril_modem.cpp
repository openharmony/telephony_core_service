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

#include "hril_notification.h"
#include "hril_request.h"

namespace OHOS {
namespace Telephony {
void TelRilModem::AddHandlerToMap()
{
    // indication
    memberFuncMap_[HNOTI_MODEM_RADIO_STATE_UPDATED] = &TelRilModem::RadioStateUpdated;
    memberFuncMap_[HNOTI_MODEM_VOICE_TECH_UPDATED] = &TelRilModem::VoiceRadioTechUpdated;
    // response
    memberFuncMap_[HNOTI_MODEM_VOICE_TECH_UPDATED] = &TelRilModem::VoiceRadioTechUpdated;
    memberFuncMap_[HREQ_MODEM_SET_RADIO_STATUS] = &TelRilModem::SetRadioStateResponse;
    memberFuncMap_[HREQ_MODEM_GET_RADIO_STATUS] = &TelRilModem::GetRadioStateResponse;
    memberFuncMap_[HREQ_MODEM_GET_IMEI] = &TelRilModem::GetImeiResponse;
    memberFuncMap_[HREQ_MODEM_GET_MEID] = &TelRilModem::GetMeidResponse;
    memberFuncMap_[HREQ_MODEM_GET_VOICE_RADIO] = &TelRilModem::GetVoiceRadioTechnologyResponse;
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
    TELEPHONY_LOGI("TelRilModem ProcessCommonRespOrNotify code:%{public}d, GetDataSize:%{public}zu", code,
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

void TelRilModem::SetRadioStateResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilModem SetRadioStateResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetRadioStateResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGI("SetRadioStateResponse serial:%{public}d, error:%{public}d ", radioResponseInfo->serial,
        radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGI("SetRadioStateResponse serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_,
        telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGW("WARNING : SetRadioStateResponse --> handler == nullptr !!!");
                return;
            }

            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("SetRadioStateResponse eventId:%{public}d", eventId);
            std::unique_ptr<HRilRadioStateInfo> radioState = std::make_unique<HRilRadioStateInfo>();
            radioState->flag = telRilRequest->pointer_->GetParam();
            radioState->state = (int32_t)(radioResponseInfo->error);
            handler->SendEvent(eventId, radioState);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilModem::GetRadioStateResponse(MessageParcel &data)
{
    int32_t radioState = data.ReadInt32();

    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilModem GetRadioStateResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetRadioStateResponse --> radioResponseInfo == nullptr !!!");
        return;
    }

    TELEPHONY_LOGI("GetRadioStateResponse serial:%{public}d, error:%{public}d ", radioResponseInfo->serial,
        radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        TELEPHONY_LOGI("GetRadioStateResponse serialId_:%{public}d, requestId_:%{public}d,",
            telRilRequest->serialId_, telRilRequest->requestId_);
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGW("WARNING : GetRadioStateResponse --> handler == nullptr !!!");
                return;
            }

            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("GetRadioStateResponse eventId:%{public}d", eventId);
            std::unique_ptr<HRilRadioStateInfo> state = std::make_unique<HRilRadioStateInfo>();
            state->flag = telRilRequest->pointer_->GetParam();
            state->state = radioState;
            handler->SendEvent(eventId, state);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilModem::SetRadioState(int fun, int rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_MODEM_SET_RADIO_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilModem SetRadioState:telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(fun);
        data.WriteInt32(rst);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_MODEM_SET_RADIO_STATUS, data, reply, option);
        TELEPHONY_LOGI(
            "SetRadioState --> SendBufferEvent(HREQ_MODEM_SET_RADIO_STATUS, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_MODEM_SET_RADIO_STATUS --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilModem::GetRadioState(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_MODEM_GET_RADIO_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilModem GetRadioState:telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_MODEM_GET_RADIO_STATUS, data, reply, option);
        TELEPHONY_LOGI(
            "GetRadioState --> SendBufferEvent(HREQ_MODEM_GET_RADIO_STATUS, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_MODEM_GET_RADIO_STATUS --> cellularRadio_ == nullptr !!!");
    }
}


void TelRilModem::GetImei(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_MODEM_GET_IMEI, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilModem GetImei::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilModem GetImei:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_MODEM_GET_IMEI, telRilRequest->serialId_);
    }
}

void TelRilModem::GetMeid(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_MODEM_GET_MEID, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilModem GetMeid::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilModem GetMeid:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_MODEM_GET_MEID, telRilRequest->serialId_);
    }
}

void TelRilModem::GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_MODEM_GET_VOICE_RADIO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("GetVoiceRadioTechnology::telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("GetVoiceRadioTechnology:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_MODEM_GET_VOICE_RADIO, telRilRequest->serialId_);
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
}

void TelRilModem::GetImeiResponse(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    if (buffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetImeiResponse --> buffer == nullptr !!!");
        return;
    }
    std::shared_ptr<std::string> imeiId = std::make_shared<std::string>(buffer);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetImeiResponse --> spBuffer == nullptr!!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetImeiResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, imeiId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetImeiResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilModem::GetMeidResponse(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    if (buffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetMeidResponse --> buffer == nullptr !!!");
        return;
    }
    std::shared_ptr<std::string> meidId = std::make_shared<std::string>(buffer);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetMeidResponse --> spBuffer == nullptr!!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI(
        "GetMeidResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetMeidResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, meidId);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetMeidResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}


void TelRilModem::GetVoiceRadioTechnologyResponse(MessageParcel &data)
{
    std::shared_ptr<VoiceRadioTechnology> voiceRadioTechnology = std::make_shared<VoiceRadioTechnology>();
    if (voiceRadioTechnology == nullptr) {
        TELEPHONY_LOGE("voiceRadioTechnology == nullptr");
        return;
    }
    voiceRadioTechnology->ReadFromParcel(data);
    const size_t readSpSize = sizeof(HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetVoiceRadioTechnologyResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("radioResponseInfo == nullptr");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("GetVoiceRadioTechnologyResponse eventId:%{public}d", eventId);
            voiceRadioTechnology->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, voiceRadioTechnology);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilModem::RadioStateUpdated(MessageParcel &data)
{
    int32_t radioState = data.ReadInt32();
    int32_t indicationType = data.ReadInt32();
    TELEPHONY_LOGI(
        "func :%{public}s indicationType: %{public}d state:%{public}d", __func__, indicationType, radioState);
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("observerHandler_ is nullptr");
        return;
    }
    std::shared_ptr<int32_t> state = std::make_shared<int32_t>();
    *state = radioState;
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_STATE_CHANGED, state);
}

void TelRilModem::VoiceRadioTechUpdated(MessageParcel &data)
{
    std::shared_ptr<VoiceRadioTechnology> voiceInfo = std::make_shared<VoiceRadioTechnology>();
    if (voiceInfo == nullptr) {
        TELEPHONY_LOGE("voiceInfo == nullptr");
        return;
    }
    voiceInfo->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_VOICE_TECH_CHANGED, voiceInfo);
    }
}
} // namespace Telephony
} // namespace OHOS
