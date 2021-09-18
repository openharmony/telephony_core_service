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

namespace OHOS {
namespace Telephony {
void TelRilSim::AddHandlerToMap()
{
    // Notification
    memberFuncMap_[HNOTI_SIM_STATUS_CHANGED] = &TelRilSim::SimStateUpdated;

    // response
    memberFuncMap_[HREQ_SIM_IO] = &TelRilSim::RequestSimIOResponse;
    memberFuncMap_[HREQ_SIM_GET_SIM_STATUS] = &TelRilSim::GetSimStatusResponse;
    memberFuncMap_[HREQ_SIM_GET_IMSI] = &TelRilSim::GetImsiResponse;
    memberFuncMap_[HREQ_SIM_GET_ICCID] = &TelRilSim::GetIccIDResponse;
    memberFuncMap_[HREQ_SIM_GET_LOCK_STATUS] = &TelRilSim::GetSimLockStatusResponse;
    memberFuncMap_[HREQ_SIM_SET_LOCK] = &TelRilSim::SetSimLockResponse;
    memberFuncMap_[HREQ_SIM_CHANGE_PASSWD] = &TelRilSim::ChangeSimPasswordResponse;
    memberFuncMap_[HREQ_SIM_ENTER_PIN] = &TelRilSim::EnterSimPinResponse;
    memberFuncMap_[HREQ_SIM_UNLOCK_PIN] = &TelRilSim::UnlockSimPinResponse;
    memberFuncMap_[HREQ_SIM_GET_PIN_INPUT_TIMES] = &TelRilSim::GetSimPinInputTimesResponse;
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
    TELEPHONY_LOGD(
        "TelRilSim ProcessSimRespOrNotify code:%{public}d, GetDataSize:%{public}zu", code, data.GetDataSize());
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
void TelRilSim::RequestSimIOResponse(MessageParcel &data)
{
    std::shared_ptr<IccIoResultInfo> iccIoResult = std::make_shared<IccIoResultInfo>();
    if (iccIoResult == nullptr) {
        TELEPHONY_LOGE("ERROR : RequestSimIOResponse --> iccIoResult == nullptr !!!");
        return;
    }
    iccIoResult->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : RequestSimIOResponse --> read spBuffer(HRilRadioResponseInfo) failed !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : RequestSimIOResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "RequestSimIOResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            ProcessIccIoInfo(telRilRequest, iccIoResult);
        } else {
            ErrorIccIoResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE(
            "ERROR : RequestSimIOResponse --> telRilRequest == nullptr || radioResponseInfo  error  !!!");
    }
}

void TelRilSim::ErrorIccIoResponse(
    std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo)
{
    std::shared_ptr<HRilRadioResponseInfo> respInfo = std::make_shared<HRilRadioResponseInfo>();
    if (respInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ErrorIccIoResponse == nullptr failed !!!");
        return;
    }
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : ErrorIccIoResponse --> handler == nullptr !!!");
            return;
        }
        respInfo->serial = responseInfo.serial;
        respInfo->error = responseInfo.error;
        respInfo->flag = telRilRequest->pointer_->GetParam();

        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        std::unique_ptr<Telephony::IccToRilMsg> toMsg =
            telRilRequest->pointer_->GetUniqueObject<Telephony::IccToRilMsg>();
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
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("ERROR : ProcessIccIoInfo --> telRilRequest == nullptr !!!");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : ProcessIccIoInfo --> handler == nullptr !!!");
        return;
    }
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::unique_ptr<Telephony::IccToRilMsg> toMsg =
        telRilRequest->pointer_->GetUniqueObject<Telephony::IccToRilMsg>();
    if (toMsg == nullptr) {
        TELEPHONY_LOGE("ERROR : ProcessIccIoInfo --> GetUniqueObject<IccToRilMsg>() failed !!!");
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
    if (telRilRequest == nullptr || iccIoResult == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest == nullptr || iccIoResult == nullptr !!!");
        return;
    }
    handler->SendEvent(eventId, object);
}

void TelRilSim::GetSimStatusResponse(MessageParcel &data)
{
    std::shared_ptr<CardStatusInfo> cardStatusInfo = std::make_unique<CardStatusInfo>();
    if (cardStatusInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetSimStatusResponse --> cardStatusInfo == nullptr !!!");
        return;
    }
    cardStatusInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetSimStatusResponse --> spBuffer == nullptr !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetSimStatusResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "GetSimStatusResponse -->  radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetSimStatusResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, cardStatusInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetSimStatusResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::GetImsiResponse(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> imsi = std::make_shared<std::string>(buffer);
    if (buffer == nullptr || imsi == nullptr) {
        TELEPHONY_LOGE("ERROR : GetImsiResponse --> buffer == nullptr || imsi == nullptr !!!");
        return;
    }
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetImsiResponse --> spBuffer == nullptr!!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetImsiResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "GetImsiResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            TELEPHONY_LOGD("GetImsiResponse --> data.ReadCString() success");
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetImsiResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, imsi);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE(
            "ERROR : GetSimLockStatusResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::GetIccIDResponse(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> iccID = std::make_shared<std::string>(buffer);
    if (buffer == nullptr || iccID == nullptr) {
        TELEPHONY_LOGE("ERROR : GetIccIDResponse --> buffer == nullptr || IccID == nullptr !!!");
        return;
    }
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetIccIDResponse --> spBuffer == nullptr!!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetIccIDResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "GetIccIDResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            TELEPHONY_LOGD("GetIccIDResponse --> data.ReadCString() success");
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetIccIDResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, iccID);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetIccIDResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::GetSimLockStatusResponse(MessageParcel &data)
{
    std::shared_ptr<int> SimLockStatus = std::make_shared<int>();
    *SimLockStatus = data.ReadInt32();

    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetSimLockStatusResponse --> spBuffer == nullptr!!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetSimLockStatusResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "GetSimLockStatusResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            TELEPHONY_LOGD("GetSimLockStatusResponse --> data.ReadCString() success");
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetSimLockStatusResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, SimLockStatus);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE(
            "ERROR : GetSimLockStatusResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::SetSimLockResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ChangeSimPasswordResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : ChangeSimPasswordResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : ChangeSimPasswordResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("ERROR : SetSimLockResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}

void TelRilSim::ChangeSimPasswordResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("SetSimLockResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetSimLockResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : EnterSimPinResponse --> handler == nullptr !!!");
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

void TelRilSim::EnterSimPinResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("EnterSimPinResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : EnterSimPinResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SetSimLockResponse --> handler == nullptr !!!");
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

void TelRilSim::UnlockSimPinResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("UnlockSimPinResponse -->spBuffer == nullptr");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : UnlockSimPinResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : UnlockSimPinResponse --> handler == nullptr !!!");
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
        TELEPHONY_LOGE("ERROR : GetSimPinInputTimesResponse --> callInfo == nullptr !!!");
        return;
    }
    pSimPinInputTimes->ReadFromParcel(data);

    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetSimPinInputTimesResponse -->spBuffer == nullptr");
        return;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetSimPinInputTimesResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetSimPinInputTimesResponse --> handler == nullptr !!!");
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
// request

void TelRilSim::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_SIM_STATUS, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim GetSimStatus::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("GetSimStatus --> telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
        int32_t ret = SendInt32Event(HREQ_SIM_GET_SIM_STATUS, telRilRequest->serialId_);
        TELEPHONY_LOGD("GetSimStatus --> HREQ_SIM_GET_SIM_STATUS ret = %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : GetSimStatus --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::RequestSimIO(int32_t command, int32_t fileId, int32_t p1, int32_t p2, int32_t p3, std::string data,
    std::string path, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_IO, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim RequestSimIO::telRilRequest is nullptr");
            return;
        }
        MessageParcel wData;
        SimIoRequestInfo iccIoRequestInfo;
        iccIoRequestInfo.serial = telRilRequest->serialId_;
        iccIoRequestInfo.command = command;
        iccIoRequestInfo.fileId = fileId;
        iccIoRequestInfo.p1 = p1;
        iccIoRequestInfo.p2 = p2;
        iccIoRequestInfo.p3 = p3;
        iccIoRequestInfo.data = ChangeNullToEmptyString(data);
        iccIoRequestInfo.path = ChangeNullToEmptyString(path);
        iccIoRequestInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SIM_IO, wData, reply, option);
        TELEPHONY_LOGD("RequestSimIO --> SendBufferEvent(HREQ_SIM_IO, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : RequestSimIO --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetImsi(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_IMSI, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim GetImsi::telRilRequest is nullptr");
            return;
        }

        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);

        int32_t ret = SendBufferEvent(HREQ_SIM_GET_IMSI, data);
        TELEPHONY_LOGD("GetImsi --> SendBufferEvent(HREQ_SIM_GET_IMSI, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : GetImsi --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetIccID(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_ICCID, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim GetIccID::telRilRequest is nullptr");
            return;
        }

        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);

        int32_t ret = SendBufferEvent(HREQ_SIM_GET_ICCID, data);
        TELEPHONY_LOGD("GetIccID --> SendBufferEvent(HREQ_SIM_GET_ICCID, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : GetIccID --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_LOCK_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim GetSimLockStatus::telRilRequest is nullptr");
            return;
        }
        int mode = 2;

        MessageParcel wData;
        SimLockInfo simLockInfo;
        simLockInfo.serial = telRilRequest->serialId_;
        simLockInfo.fac = ChangeNullToEmptyString(fac);
        simLockInfo.mode = mode;
        simLockInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SIM_GET_LOCK_STATUS, wData, reply, option);
        TELEPHONY_LOGD(
            "GetSimLockStatus --> SendBufferEvent(HREQ_SIM_GET_LOCK_STATUS, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_GET_LOCK_STATUS --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::SetSimLock(
    std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_SET_LOCK, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim SetSimLock:t:elRilRequest is nullptr");
            return;
        }
        MessageParcel wData;
        SimLockInfo simLockInfo;
        simLockInfo.serial = telRilRequest->serialId_;
        simLockInfo.fac = ChangeNullToEmptyString(fac);
        simLockInfo.mode = mode;
        simLockInfo.passwd = ChangeNullToEmptyString(passwd);
        simLockInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SIM_SET_LOCK, wData, reply, option);
        TELEPHONY_LOGD("SetSimLock --> SendBufferEvent(HREQ_SIM_SET_LOCK, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_SET_LOCK --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
    int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_CHANGE_PASSWD, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim ChangeSimPassword::telRilRequest is nullptr");
            return;
        }
        MessageParcel wData;
        SimPasswordInfo simPasswordInfo;
        simPasswordInfo.serial = telRilRequest->serialId_;
        simPasswordInfo.fac = ChangeNullToEmptyString(fac);
        simPasswordInfo.oldPassword = ChangeNullToEmptyString(oldPassword);
        simPasswordInfo.newPassword = ChangeNullToEmptyString(newPassword);
        simPasswordInfo.passwordLength = passwordLength;
        simPasswordInfo.Marshalling(wData);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SIM_CHANGE_PASSWD, wData, reply, option);
        TELEPHONY_LOGD(
            "ChangeSimPassword --> SendBufferEvent(HREQ_SIM_CHANGE_PASSWD, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_CHANGE_PASSWD --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::EnterSimPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_ENTER_PIN, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim EnterSimPin::telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(pin.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SIM_ENTER_PIN, data, reply, option);
        TELEPHONY_LOGD("EnterSimPin --> SendBufferEvent(HREQ_SIM_ENTER_PIN, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_ENTER_PIN --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::UnlockSimPin(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_UNLOCK_PIN, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim UnlockSimPin::telRilRequest is nullptr");
            return;
        }
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteCString(puk.c_str());
        data.WriteCString(pin.c_str());
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_SIM_UNLOCK_PIN, data, reply, option);
        TELEPHONY_LOGD("UnlockSimPin --> SendBufferEvent(HREQ_SIM_UNLOCK_PIN, wData) return ID: %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_SIM_UNLOCK_PIN --> cellularRadio_ == nullptr !!!");
    }
}

void TelRilSim::GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_SIM_GET_PIN_INPUT_TIMES, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilSim GetSimPinInputTimes::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("GetSimPinInputTimes --> telRilRequest->mSerial = %{public}d", telRilRequest->serialId_);
        int32_t ret = SendInt32Event(HREQ_SIM_GET_PIN_INPUT_TIMES, telRilRequest->serialId_);
        TELEPHONY_LOGD("GetSimPinInputTimes --> HREQ_SIM_GET_PIN_INPUT_TIMES ret = %{public}d", ret);
    } else {
        TELEPHONY_LOGE("ERROR : GetSimPinInputTimes --> cellularRadio_ == nullptr !!!");
    }
}

std::string TelRilSim::ChangeNullToEmptyString(std::string str)
{
    return !str.empty() ? str : "";
}
} // namespace Telephony
} // namespace OHOS
