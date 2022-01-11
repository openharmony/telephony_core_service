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

#include "sim_data_type.h"

// test add
#include "sim_utils.h"

#include "hril_notification.h"
#include "hril_request.h"

namespace OHOS {
namespace Telephony {
void TelRilSim::AddHandlerToMap()
{
    // Notification
    memberFuncMap_[HNOTI_SIM_STATUS_CHANGED] = &TelRilSim::SimStateUpdated;
    memberFuncMap_[HNOTI_SIM_STK_SESSION_END_NOTIFY] = &TelRilSim::StkSessionEndNotify;
    memberFuncMap_[HNOTI_SIM_STK_PROACTIVE_CMD_NOTIFY] = &TelRilSim::StkProactiveCommandNotify;
    memberFuncMap_[HNOTI_SIM_STK_ALPHA_NOTIFY] = &TelRilSim::StkAlphaNotify;

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
    memberFuncMap_[HREQ_SIM_SEND_TERMINAL_RESPONSE_CMD] = &TelRilSim::SendTerminalResponseCmdResponse;
    memberFuncMap_[HREQ_SIM_SEND_ENVELOPE_CMD] = &TelRilSim::SendEnvelopeCmdResponse;
    memberFuncMap_[HREQ_SIM_STK_CONTROLLER_IS_READY] = &TelRilSim::StkControllerIsReadyResponse;
    memberFuncMap_[HREQ_SIM_STK_CMD_CALL_SETUP] = &TelRilSim::StkCmdCallSetupResponse;
    memberFuncMap_[HREQ_SIM_RADIO_PROTOCOL] = &TelRilSim::SetRadioProtocolResponse;
    memberFuncMap_[HREQ_SIM_OPEN_LOGICAL_SIM_IO] = &TelRilSim::OpenLogicalSimIOResponse;
    memberFuncMap_[HREQ_SIM_CLOSE_LOGICAL_SIM_IO] = &TelRilSim::CloseLogicalSimIOResponse;
    memberFuncMap_[HREQ_SIM_TRANSMIT_APDU_SIM_IO] = &TelRilSim::TransmitApduSimIOResponse;
    memberFuncMap_[HREQ_SIM_UNLOCK_SIM_LOCK] = &TelRilSim::UnlockSimLockResponse;
}

TelRilSim::TelRilSim(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
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

void TelRilSim::ProcessSimRespOrNotify(uint32_t code, MessageParcel &data)
{
    TELEPHONY_LOGI("code:%{public}d, GetDataSize:%{public}zu", code, data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

void TelRilSim::SimStateUpdated(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilSim observerHandler_ is null!!");
        return;
    }

    observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIM_STATE_CHANGE);
}

// response
void TelRilSim::GetSimIOResponse(MessageParcel &data)
{
    std::shared_ptr<IccIoResultInfo> iccIoResult = std::make_shared<IccIoResultInfo>();
    iccIoResult->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :read spBuffer(HRilRadioResponseInfo) failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d,radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            ProcessIccIoInfo(telRilRequest, iccIoResult);
        } else {
            ErrorIccIoResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo  error");
    }
}

void TelRilSim::ErrorIccIoResponse(
    std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo)
{
    std::shared_ptr<HRilRadioResponseInfo> respInfo = std::make_shared<HRilRadioResponseInfo>();
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
            return;
        }
        respInfo->serial = responseInfo.serial;
        respInfo->error = responseInfo.error;
        respInfo->flag = telRilRequest->pointer_->GetParam();

        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        std::unique_ptr<Telephony::IccToRilMsg> toMsg =
            telRilRequest->pointer_->GetUniqueObject<Telephony::IccToRilMsg>();
        if (toMsg == nullptr) {
            TELEPHONY_LOGE("ERROR :toMsg == nullptr !!!");
            return;
        }
        std::shared_ptr<Telephony::IccFromRilMsg> object =
            std::make_shared<Telephony::IccFromRilMsg>(toMsg->controlHolder);
        object->controlHolder = toMsg->controlHolder;
        object->fileData.exception = static_cast<std::shared_ptr<void>>(respInfo);
        handler->SendEvent(eventId, object);
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilSim::ProcessIccIoInfo(
    std::shared_ptr<TelRilRequest> telRilRequest, std::shared_ptr<IccIoResultInfo> iccIoResult)
{
    if (telRilRequest == nullptr && telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest or telRilRequest->pointer_== nullptr !!!");
        return;
    }
    if (telRilRequest->pointer_->GetOwner() == nullptr || iccIoResult == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest->pointer_->GetOwner() or iccIoResult == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::unique_ptr<Telephony::IccToRilMsg> toMsg =
        telRilRequest->pointer_->GetUniqueObject<Telephony::IccToRilMsg>();
    if (toMsg == nullptr) {
        TELEPHONY_LOGE("ERROR :GetUniqueObject<IccToRilMsg>() failed !!!");
        return;
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
}

void TelRilSim::GetSimStatusResponse(MessageParcel &data)
{
    std::shared_ptr<CardStatusInfo> cardStatusInfo = std::make_unique<CardStatusInfo>();
    cardStatusInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :spBuffer == nullptr !!!");
        return;
    }
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
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, cardStatusInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::GetImsiResponse(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> imsi = std::make_shared<std::string>(buffer);
    if (buffer == nullptr) {
        TELEPHONY_LOGE("ERROR : buffer == nullptr !!!");
        return;
    }
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :spBuffer == nullptr!!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, imsi);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::GetSimLockStatusResponse(MessageParcel &data)
{
    std::shared_ptr<int32_t> SimLockStatus = std::make_shared<int32_t>();
    *SimLockStatus = data.ReadInt32();

    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :spBuffer == nullptr!!!");
        return;
    }
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
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, SimLockStatus);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::SetSimLockResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::ChangeSimPasswordResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("pBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::UnlockPinResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::UnlockPukResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::GetSimPinInputTimesResponse(MessageParcel &data)
{
    std::shared_ptr<SimPinInputTimes> pSimPinInputTimes = std::make_shared<SimPinInputTimes>();
    if (pSimPinInputTimes == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return;
    }
    pSimPinInputTimes->ReadFromParcel(data);

    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, pSimPinInputTimes);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetSimPinInputTimesResponse or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}
void TelRilSim::UnlockPin2Response(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::UnlockPuk2Response(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::GetSimPin2InputTimesResponse(MessageParcel &data)
{
    std::shared_ptr<SimPinInputTimes> pSimPin2InputTimes = std::make_shared<SimPinInputTimes>();
    if (pSimPin2InputTimes == nullptr) {
        TELEPHONY_LOGE("ERROR :callInfo == nullptr !!!");
        return;
    }
    pSimPin2InputTimes->ReadFromParcel(data);

    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, pSimPin2InputTimes);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetSimPin2InputTimesResponse or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
}

void TelRilSim::SetActiveSimResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::SendTerminalResponseCmdResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::SendEnvelopeCmdResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::StkControllerIsReadyResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::StkCmdCallSetupResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::SetRadioProtocolResponse(MessageParcel &data)
{
    std::shared_ptr<SimProtocolResponse> protocol = std::make_shared<SimProtocolResponse>();
    if (protocol == nullptr) {
        TELEPHONY_LOGE("ERROR : callInfo == nullptr !!!");
        return;
    }
    protocol->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, protocol);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::OpenLogicalSimIOResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::CloseLogicalSimIOResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            std::shared_ptr<HRilErrType> errorCode = std::make_shared<HRilErrType>();
            *errorCode = radioResponseInfo->error;
            handler->SendEvent(eventId, errorCode);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilSim::TransmitApduSimIOResponse(MessageParcel &data)
{
    std::unique_ptr<IccIoResultInfo> iccIoResult = std::make_unique<IccIoResultInfo>();
    iccIoResult->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR :radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo  error");
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR :handler == nullptr");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, iccIoResult);
        return;
    }
    ErrorResponse(telRilRequest, *radioResponseInfo);
}

void TelRilSim::UnlockSimLockResponse(MessageParcel &data)
{
    std::shared_ptr<LockStatusResp> lockStatus = std::make_shared<LockStatusResp>();
    lockStatus->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR :read spBuffer(HRilRadioResponseInfo) failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR :handler == nullptr");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, lockStatus);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR :telRilRequest == nullptr || radioResponseInfo error");
    }
}
// request

void TelRilSim::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_STATUS, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
        if (SendInt32Event(HREQ_SIM_GET_SIM_STATUS, telRilRequest->serialId_) < 0) {
            TELEPHONY_LOGE("SendInt32Event fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetSimIO(SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_IO, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel wData;
        SimIoRequestInfo iccIoRequestInfo;
        iccIoRequestInfo.serial = telRilRequest->serialId_;
        iccIoRequestInfo.command = data.command;
        iccIoRequestInfo.fileId = data.fileId;
        iccIoRequestInfo.p1 = data.p1;
        iccIoRequestInfo.p2 = data.p2;
        iccIoRequestInfo.p3 = data.p3;
        iccIoRequestInfo.data = data.data;
        iccIoRequestInfo.path = data.path;
        iccIoRequestInfo.pin2 = data.pin2;
        iccIoRequestInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_GET_SIM_IO, wData, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetImsi(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_IMSI, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }

        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        if (SendBufferEvent(HREQ_SIM_GET_IMSI, data) < 0) {
            TELEPHONY_LOGE("SendBufferEvent fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_LOCK_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        int32_t mode = 2;

        MessageParcel wData;
        SimLockInfo simLockInfo;
        simLockInfo.serial = telRilRequest->serialId_;
        simLockInfo.fac = fac;
        simLockInfo.mode = mode;
        simLockInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_GET_SIM_LOCK_STATUS, wData, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_GET_SIM_LOCK_STATUS --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::SetSimLock(
    std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_SET_SIM_LOCK, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel wData;
        SimLockInfo simLockInfo;
        simLockInfo.serial = telRilRequest->serialId_;
        simLockInfo.fac = fac;
        simLockInfo.mode = mode;
        simLockInfo.passwd = passwd;
        simLockInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_SET_SIM_LOCK, wData, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_SET_SIM_LOCK --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
    int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_CHANGE_SIM_PASSWORD, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel wData;
        SimPasswordInfo simPwdInfo;
        simPwdInfo.serial = telRilRequest->serialId_;
        simPwdInfo.fac = fac;
        simPwdInfo.oldPassword = oldPassword;
        simPwdInfo.newPassword = newPassword;
        simPwdInfo.passwordLength = passwordLength;
        simPwdInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_CHANGE_SIM_PASSWORD, wData, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_CHANGE_SIM_PASSWORD --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PIN, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(pin.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PIN, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_ENTER_PIN --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PUK, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(puk.c_str());
        data.WriteCString(pin.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PUK, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_UNLOCK_PUK --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_SIM_GET_SIM_PIN_INPUT_TIMES, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
        if (SendInt32Event(HREQ_SIM_GET_SIM_PIN_INPUT_TIMES, telRilRequest->serialId_) < 0) {
            TELEPHONY_LOGE("SendInt32Event fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PIN2, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(pin2.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PIN2, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_UNLOCK_PIN2 --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PUK2, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(puk2.c_str());
        data.WriteCString(pin2.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PUK2, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_UNLOCK_PUK2 --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetSimPin2InputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_SIM_GET_SIM_PIN2_INPUT_TIMES, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
        if (SendInt32Event(HREQ_SIM_GET_SIM_PIN2_INPUT_TIMES, telRilRequest->serialId_) < 0) {
            TELEPHONY_LOGE("SendInt32Event fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}
void TelRilSim::SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_SET_ACTIVE_SIM, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(index);
        data.WriteInt32(enable);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_SET_ACTIVE_SIM, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}

// stk call back
void TelRilSim::StkSessionEndNotify(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilSim::StkSessionEndNotify() observerHandler_ is null!!");
        return;
    }
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_STK_SESSION_END);
}

void TelRilSim::StkProactiveCommandNotify(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilSim::StkProactiveCommandNotify() observerHandler_ is null!!");
        return;
    }
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> stkMessage = std::make_shared<std::string>(buffer);
    TELEPHONY_LOGI("TelRilSim::StkProactiveCommandNotify(), stkMessage = %{public}s\n", stkMessage->c_str());
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_STK_PROACTIVE_COMMAND, stkMessage);
}

void TelRilSim::StkAlphaNotify(MessageParcel &data)
{
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("TelRilSim::StkAlphaNotify() observerHandler_ is null!!");
        return;
    }
    observerHandler_->NotifyObserver(ObserverHandler::RADIO_STK_ALPHA_NOTIFY);
}

// ril interface
void TelRilSim::SendTerminalResponseCmd(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_SIM_SEND_TERMINAL_RESPONSE_CMD, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(strCmd.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_SEND_TERMINAL_RESPONSE_CMD, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_SEND_TERMINAL_RESPONSE_CMD --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::SendEnvelopeCmd(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_SEND_ENVELOPE_CMD, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(strCmd.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_SEND_ENVELOPE_CMD, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_SEND_ENVELOPE_CMD --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::StkControllerIsReady(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_SIM_STK_CONTROLLER_IS_READY, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        if (SendBufferEvent(HREQ_SIM_STK_CONTROLLER_IS_READY, data) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::StkCmdCallSetup(int32_t flagAccept, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_STK_CMD_CALL_SETUP, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(flagAccept);
        if (SendBufferEvent(HREQ_SIM_STK_CMD_CALL_SETUP, data) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::SetRadioProtocol(SimProtocolRequest data, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_RADIO_PROTOCOL, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel Wdata;
        SimProtocolRequest protocolRequestInfo;
        protocolRequestInfo.serial = telRilRequest->serialId_;
        protocolRequestInfo.phase = data.phase;
        protocolRequestInfo.protocol = data.protocol;
        protocolRequestInfo.slotId = data.slotId;
        protocolRequestInfo.Marshalling(Wdata);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_RADIO_PROTOCOL, Wdata, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::OpenLogicalSimIO(std::string appID, int32_t p2, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_OPEN_LOGICAL_SIM_IO, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(appID.c_str());
        data.WriteInt32(p2);
        if (SendBufferEvent(HREQ_SIM_OPEN_LOGICAL_SIM_IO, data) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr");
    }
}

void TelRilSim::CloseLogicalSimIO(int chanID, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_CLOSE_LOGICAL_SIM_IO, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(chanID);
        if (SendBufferEvent(HREQ_SIM_CLOSE_LOGICAL_SIM_IO, data) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr");
    }
}

void TelRilSim::TransmitApduSimIO(ApduSimIORequestInfo reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_TRANSMIT_APDU_SIM_IO, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }

        MessageParcel data;
        ApduSimIORequestInfo ApduRequestInfo;
        ApduRequestInfo.serial = telRilRequest->serialId_;
        ApduRequestInfo.chanId = reqInfo.chanId;
        ApduRequestInfo.type = reqInfo.type;
        ApduRequestInfo.instruction = reqInfo.instruction;
        ApduRequestInfo.p1 = reqInfo.p1;
        ApduRequestInfo.p2 = reqInfo.p2;
        ApduRequestInfo.p3 = reqInfo.p3;
        ApduRequestInfo.data = reqInfo.data;
        if (!ApduRequestInfo.Marshalling(data)) {
            TELEPHONY_LOGE("ApduRequestInfo.Marshalling fail");
            return;
        }

        if (SendBufferEvent(HREQ_SIM_TRANSMIT_APDU_SIM_IO, data) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR :cellularRadio_ == nullptr");
    }
}

void TelRilSim::UnlockSimLock(
    int32_t lockType, std::string password, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_SIM_LOCK, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(lockType);
        data.WriteCString(password.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        if (cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_SIM_LOCK, data, reply, option) < 0) {
            TELEPHONY_LOGE("cellularRadio_->SendRequest fail");
        }
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_UNLOCK_SIM_LOCK --> cellularRadio_ == nullptr");
    }
}
} // namespace Telephony
} // namespace OHOS