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

#include "tel_ril_sim.h"

#include "hril_notification.h"
#include "hril_request.h"
#include "radio_event.h"
#include "sim_data_type.h"
#include "sim_utils.h"

namespace OHOS {
namespace Telephony {
void TelRilSim::AddHandlerToMap()
{
    // Notification
    memberFuncMap_[HNOTI_SIM_STATUS_CHANGED] = &TelRilSim::SimStateUpdated;
    memberFuncMap_[HNOTI_SIM_STK_SESSION_END_NOTIFY] = &TelRilSim::SimStkSessionEndNotify;
    memberFuncMap_[HNOTI_SIM_STK_PROACTIVE_NOTIFY] = &TelRilSim::SimStkProactiveNotify;
    memberFuncMap_[HNOTI_SIM_STK_ALPHA_NOTIFY] = &TelRilSim::SimStkAlphaNotify;

    // response
    memberFuncMap_[HREQ_SIM_GET_SIM_IO] = &TelRilSim::GetSimIOResponse;
    memberFuncMap_[HREQ_SIM_GET_SIM_STATUS] = &TelRilSim::GetSimStatusResponse;
    memberFuncMap_[HREQ_SIM_GET_IMSI] = &TelRilSim::GetImsiResponse;
    memberFuncMap_[HREQ_SIM_GET_SIM_LOCK_STATUS] = &TelRilSim::GetSimLockStatusResponse;
    memberFuncMap_[HREQ_SIM_SET_SIM_LOCK] = &TelRilSim::SetSimLockResponse;
    memberFuncMap_[HREQ_SIM_CHANGE_SIM_PASSWORD] = &TelRilSim::ChangeSimPasswordResponse;
    memberFuncMap_[HREQ_SIM_UNLOCK_PIN] = &TelRilSim::UnlockPinResponse;
    memberFuncMap_[HREQ_SIM_UNLOCK_PUK] = &TelRilSim::UnlockPukResponse;
    memberFuncMap_[HREQ_SIM_GET_SIM_PIN_INPUT_TIMES] = &TelRilSim::GetSimPinInputTimesResponse;
    memberFuncMap_[HREQ_SIM_UNLOCK_PIN2] = &TelRilSim::UnlockPin2Response;
    memberFuncMap_[HREQ_SIM_UNLOCK_PUK2] = &TelRilSim::UnlockPuk2Response;
    memberFuncMap_[HREQ_SIM_GET_SIM_PIN2_INPUT_TIMES] = &TelRilSim::GetSimPin2InputTimesResponse;
    memberFuncMap_[HREQ_SIM_SET_ACTIVE_SIM] = &TelRilSim::SetActiveSimResponse;
    memberFuncMap_[HREQ_SIM_STK_SEND_TERMINAL_RESPONSE] = &TelRilSim::SimStkSendTerminalResponseResponse;
    memberFuncMap_[HREQ_SIM_STK_SEND_ENVELOPE] = &TelRilSim::SimStkSendEnvelopeResponse;
    memberFuncMap_[HREQ_SIM_STK_IS_READY] = &TelRilSim::SimStkIsReadyResponse;
    memberFuncMap_[HREQ_SIM_RADIO_PROTOCOL] = &TelRilSim::SetRadioProtocolResponse;
    memberFuncMap_[HREQ_SIM_OPEN_LOGICAL_CHANNEL] = &TelRilSim::SimOpenLogicalChannelResponse;
    memberFuncMap_[HREQ_SIM_CLOSE_LOGICAL_CHANNEL] = &TelRilSim::SimCloseLogicalChannelResponse;
    memberFuncMap_[HREQ_SIM_TRANSMIT_APDU_LOGICAL_CHANNEL] = &TelRilSim::SimTransmitApduLogicalChannelResponse;
    memberFuncMap_[HREQ_SIM_UNLOCK_SIM_LOCK] = &TelRilSim::UnlockSimLockResponse;
}

TelRilSim::TelRilSim(int32_t slotId, sptr<IRemoteObject> cellularRadio,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, observerHandler, handler)
{
    AddHandlerToMap();
}

bool TelRilSim::IsSimResponse(uint32_t code)
{
    return ((code >= HREQ_SIM_BASE) && (code < HREQ_DATA_BASE));
}

bool TelRilSim::IsSimNotification(uint32_t code)
{
    return ((code >= HNOTI_SIM_BASE) && (code < HNOTI_DATA_BASE));
}

bool TelRilSim::IsSimRespOrNotify(uint32_t code)
{
    return IsSimResponse(code) || IsSimNotification(code);
}

int32_t TelRilSim::SimStateUpdated(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilSim observerHandler_ is null!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_STATE_CHANGE);
    return TELEPHONY_ERR_SUCCESS;
}

// response
int32_t TelRilSim::GetSimIOResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :read spBuffer(HRilRadioResponseInfo) failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<IccIoResultInfo> iccIoResult = std::make_shared<IccIoResultInfo>();
    iccIoResult->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d,radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            return ProcessIccIoInfo(telRilRequest, iccIoResult);
        } else {
            ErrorIccIoResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo  error");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::ErrorIccIoResponse(
    std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo)
{
    std::shared_ptr<HRilRadioResponseInfo> respInfo = std::make_shared<HRilRadioResponseInfo>();
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        respInfo->serial = responseInfo.serial;
        respInfo->error = responseInfo.error;
        respInfo->flag = telRilRequest->pointer_->GetParam();

        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        std::unique_ptr<Telephony::IccToRilMsg> toMsg =
            telRilRequest->pointer_->GetUniqueObject<Telephony::IccToRilMsg>();
        if (toMsg == nullptr) {
            TELEPHONY_LOGE("ERROR :toMsg == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        std::shared_ptr<Telephony::IccFromRilMsg> object =
            std::make_shared<Telephony::IccFromRilMsg>(toMsg->controlHolder);
        object->controlHolder = toMsg->controlHolder;
        object->fileData.exception = static_cast<std::shared_ptr<void>>(respInfo);
        handler->SendEvent(eventId, object);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::ProcessIccIoInfo(
    std::shared_ptr<TelRilRequest> telRilRequest, std::shared_ptr<IccIoResultInfo> iccIoResult)
{
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest== nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest->pointer_== nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (telRilRequest->pointer_->GetOwner() == nullptr || iccIoResult == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest->pointer_->GetOwner() or iccIoResult == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::unique_ptr<Telephony::IccToRilMsg> toMsg = telRilRequest->pointer_->GetUniqueObject<Telephony::IccToRilMsg>();
    if (toMsg == nullptr) {
        TELEPHONY_LOGE("ERROR :GetUniqueObject<IccToRilMsg>() failed !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_ptr<Telephony::IccFromRilMsg> object =
        std::make_unique<Telephony::IccFromRilMsg>(toMsg->controlHolder);
    object->fileData.resultData = iccIoResult->response;
    object->fileData.sw1 = iccIoResult->sw1;
    object->fileData.sw2 = iccIoResult->sw2;
    object->controlHolder = toMsg->controlHolder;
    object->arg1 = toMsg->arg1;
    object->arg2 = toMsg->arg2;
    handler->SendEvent(eventId, object);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimStatusResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :spBuffer == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<CardStatusInfo> cardStatusInfo = std::make_unique<CardStatusInfo>();
    cardStatusInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, cardStatusInfo);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo error !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetImsiResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :spBuffer == nullptr!!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const char *buffer = data.ReadCString();
    if (buffer == nullptr) {
        TELEPHONY_LOGE("ERROR : buffer == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<std::string> imsi = std::make_shared<std::string>(buffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, imsi);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo error !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimLockStatusResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :spBuffer == nullptr!!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<int32_t> SimLockStatus = std::make_shared<int32_t>();
    *SimLockStatus = data.ReadInt32();

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d,radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, SimLockStatus);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest == nullptr || radioResponseInfo error !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SetSimLockResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo error !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::ChangeSimPasswordResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("pBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockPinResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockPukResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimPinInputTimesResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<SimPinInputTimes> pSimPinInputTimes = std::make_shared<SimPinInputTimes>();
    if (pSimPinInputTimes == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    pSimPinInputTimes->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, pSimPinInputTimes);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetSimPinInputTimesResponse or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}
int32_t TelRilSim::UnlockPin2Response(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockPuk2Response(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimPin2InputTimesResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<SimPinInputTimes> pSimPin2InputTimes = std::make_shared<SimPinInputTimes>();
    if (pSimPin2InputTimes == nullptr) {
        TELEPHONY_LOGE("ERROR :callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    pSimPin2InputTimes->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, pSimPin2InputTimes);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetSimPin2InputTimesResponse or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SetActiveSimResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimStkSendTerminalResponseResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimStkSendEnvelopeResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimStkIsReadyResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SetRadioProtocolResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<SimProtocolResponse> protocol = std::make_shared<SimProtocolResponse>();
    if (protocol == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    protocol->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, protocol);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimOpenLogicalChannelResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimCloseLogicalChannelResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimTransmitApduLogicalChannelResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_ptr<IccIoResultInfo> iccIoResult = std::make_unique<IccIoResultInfo>();
    iccIoResult->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo  error");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, iccIoResult);
    } else {
        return ErrorResponse(telRilRequest, *radioResponseInfo);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockSimLockResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :read spBuffer(HRilRadioResponseInfo) failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<LockStatusResp> lockStatus = std::make_shared<LockStatusResp>();
    lockStatus->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, lockStatus);
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo error");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}
// request

int32_t TelRilSim::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_STATUS, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
    if (SendInt32Event(HREQ_SIM_GET_SIM_STATUS, telRilRequest->serialId_) != 0) {
        TELEPHONY_LOGE("SendInt32Event fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimIO(SimIoRequestInfo simIoInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_IO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    SimIoRequestInfo iccIoRequestInfo;
    iccIoRequestInfo.serial = telRilRequest->serialId_;
    iccIoRequestInfo.command = simIoInfo.command;
    iccIoRequestInfo.fileId = simIoInfo.fileId;
    iccIoRequestInfo.p1 = simIoInfo.p1;
    iccIoRequestInfo.p2 = simIoInfo.p2;
    iccIoRequestInfo.p3 = simIoInfo.p3;
    iccIoRequestInfo.data = simIoInfo.data;
    iccIoRequestInfo.path = simIoInfo.path;
    iccIoRequestInfo.pin2 = simIoInfo.pin2;
    iccIoRequestInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_GET_SIM_IO, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetImsi(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_IMSI, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (SendInt32Event(HREQ_SIM_GET_IMSI, telRilRequest->serialId_) != 0) {
        TELEPHONY_LOGE("SendInt32Event fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_LOCK_STATUS, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const int32_t MODE = 2;

    MessageParcel data;
    data.WriteInt32(slotId_);
    SimLockInfo simLockInfo;
    simLockInfo.serial = telRilRequest->serialId_;
    simLockInfo.fac = fac;
    simLockInfo.mode = MODE;
    simLockInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_GET_SIM_LOCK_STATUS, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SetSimLock(
    std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_SET_SIM_LOCK, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    SimLockInfo simLockInfo;
    simLockInfo.serial = telRilRequest->serialId_;
    simLockInfo.fac = fac;
    simLockInfo.mode = mode;
    simLockInfo.passwd = passwd;
    simLockInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_SET_SIM_LOCK, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
    int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_CHANGE_SIM_PASSWORD, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    SimPasswordInfo simPwdInfo;
    simPwdInfo.serial = telRilRequest->serialId_;
    simPwdInfo.fac = fac;
    simPwdInfo.oldPassword = oldPassword;
    simPwdInfo.newPassword = newPassword;
    simPwdInfo.passwordLength = passwordLength;
    simPwdInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_CHANGE_SIM_PASSWORD, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PIN, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(pin.c_str());
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PIN, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PUK, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(puk.c_str());
    data.WriteCString(pin.c_str());
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PUK, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_PIN_INPUT_TIMES, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
    if (SendInt32sEvent(HREQ_SIM_GET_SIM_PIN_INPUT_TIMES, HRIL_EVENT_COUNT_1, telRilRequest->serialId_) != 0) {
        TELEPHONY_LOGE("SendInt32Event fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PIN2, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(pin2.c_str());
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PIN2, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PUK2, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(puk2.c_str());
    data.WriteCString(pin2.c_str());
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PUK2, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimPin2InputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_PIN2_INPUT_TIMES, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
    if (SendInt32Event(HREQ_SIM_GET_SIM_PIN2_INPUT_TIMES, telRilRequest->serialId_) != 0) {
        TELEPHONY_LOGE("SendInt32Event fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}
int32_t TelRilSim::SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_SET_ACTIVE_SIM, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(index);
    data.WriteInt32(enable);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_SET_ACTIVE_SIM, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

// stk call back
int32_t TelRilSim::SimStkSessionEndNotify(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilSim::SimStkSessionEndNotify() observerHandler_ is null!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    observerHandler_->NotifyObserver(RadioEvent::RADIO_STK_SESSION_END);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimStkProactiveNotify(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilSim::SimStkProactiveNotify() observerHandler_ is null!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> stkMessage = std::make_shared<std::string>(buffer);
    TELEPHONY_LOGI("TelRilSim::StkProactiveCommandNotify(), stkMessage = %{public}s\n", stkMessage->c_str());
    observerHandler_->NotifyObserver(RadioEvent::RADIO_STK_PROACTIVE_COMMAND, stkMessage);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimStkAlphaNotify(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilSim::SimStkAlphaNotify() observerHandler_ is null!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    observerHandler_->NotifyObserver(RadioEvent::RADIO_STK_ALPHA_NOTIFY);
    return TELEPHONY_ERR_SUCCESS;
}

// ril interface
int32_t TelRilSim::SimStkSendTerminalResponse(
    const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_STK_SEND_TERMINAL_RESPONSE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(strCmd.c_str());
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_STK_SEND_TERMINAL_RESPONSE, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimStkSendEnvelope(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_STK_SEND_ENVELOPE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(strCmd.c_str());
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_STK_SEND_ENVELOPE, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimStkIsReady(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_STK_IS_READY, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (SendInt32Event(HREQ_SIM_STK_IS_READY, telRilRequest->serialId_) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SetRadioProtocol(
    SimProtocolRequest simProtocolData, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_RADIO_PROTOCOL, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    SimProtocolRequest protocolRequestInfo;
    protocolRequestInfo.serial = telRilRequest->serialId_;
    protocolRequestInfo.phase = simProtocolData.phase;
    protocolRequestInfo.protocol = simProtocolData.protocol;
    protocolRequestInfo.slotId = simProtocolData.slotId;
    protocolRequestInfo.Marshalling(data);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_RADIO_PROTOCOL, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimOpenLogicalChannel(
    std::string appID, int32_t p2, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_OPEN_LOGICAL_CHANNEL, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteCString(appID.c_str());
    data.WriteInt32(p2);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_OPEN_LOGICAL_CHANNEL, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimCloseLogicalChannel(int32_t channelId, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_CLOSE_LOGICAL_CHANNEL, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(channelId);
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_CLOSE_LOGICAL_CHANNEL, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::SimTransmitApduLogicalChannel(
    ApduSimIORequestInfo reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_SIM_TRANSMIT_APDU_LOGICAL_CHANNEL, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    ApduSimIORequestInfo ApduRequestInfo;
    ApduRequestInfo.serial = telRilRequest->serialId_;
    ApduRequestInfo.channelId = reqInfo.channelId;
    ApduRequestInfo.type = reqInfo.type;
    ApduRequestInfo.instruction = reqInfo.instruction;
    ApduRequestInfo.p1 = reqInfo.p1;
    ApduRequestInfo.p2 = reqInfo.p2;
    ApduRequestInfo.p3 = reqInfo.p3;
    ApduRequestInfo.data = reqInfo.data;
    if (SendBufferEvent(HREQ_SIM_TRANSMIT_APDU_LOGICAL_CHANNEL, ApduRequestInfo) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::UnlockSimLock(
    int32_t lockType, std::string password, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_SIM_LOCK, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    MessageParcel data;
    data.WriteInt32(slotId_);
    data.WriteInt32(telRilRequest->serialId_);
    data.WriteInt32(lockType);
    data.WriteCString(password.c_str());
    MessageParcel reply;
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_SIM_LOCK, data, reply, option) != 0) {
        TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
    }
    return TELEPHONY_ERR_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS