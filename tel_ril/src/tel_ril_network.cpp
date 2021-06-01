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
#include "tel_ril_network.h"
#include <limits>
#include <securec.h>
#include "hril_modem_parcel.h"
#include "hril_network_parcel.h"
#include "tel_ril_modem.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
using namespace OHOS;

void TelRilNetwork::AddHandlerToMap()
{
    // indication
    memberFuncMap_[HNOTI_NETWORK_CS_REG_STATUS_UPDATED] = &TelRilNetwork::CsRegStatusUpdated;
    memberFuncMap_[HNOTI_NETWORK_SIGNAL_STRENGTH_UPDATED] = &TelRilNetwork::SignalStrengthUpdated;

    // reponse
    memberFuncMap_[HREQ_NETWORK_GET_SIGNAL_STRENGTH] = &TelRilNetwork::GetSignalStrengthResponse;
    memberFuncMap_[HREQ_NETWORK_GET_CS_REG_STATUS] = &TelRilNetwork::GetCsRegStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PS_REG_STATUS] = &TelRilNetwork::GetPsRegStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_OPERATOR_INFO] = &TelRilNetwork::GetOperatorInfoResponse;
}

TelRilNetwork::TelRilNetwork(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilNetwork::IsNetworkResponse(uint32_t code)
{
    return code >= HREQ_NETWORK_BASE && code < HREQ_COMMON_BASE;
}

bool TelRilNetwork::IsNetworkNotification(uint32_t code)
{
    return code >= HNOTI_NETWORK_BASE && code < HNOTI_COMMON_BASE;
}

bool TelRilNetwork::IsNetworkRespOrNotify(uint32_t code)
{
    return IsNetworkResponse(code) || IsNetworkNotification(code);
}

void TelRilNetwork::ProcessNetworkRespOrNotify(uint32_t code, OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilNetwork ProcessNetworkRespOrNotify code:%{public}d, GetDataSize:%{public}d", code,
        data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

void TelRilNetwork::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_PS_REG_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilNetwork GetPsRegStatus:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("TelRilNetwork GetPsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_PS_REG_STATUS, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("TelRilNetwork GetSignalStrength --> ");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_SIGNAL_STRENGTH, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilNetwork GetSignalStrength:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("TelRilNetwork GetSignalStrength:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_SIGNAL_STRENGTH, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("TelRilNetwork GetCsRegStatus --> ");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_CS_REG_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilNetwork GetCsRegStatus:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("TelRilNetwork GetCsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_CS_REG_STATUS, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("TelRilNetwork GetOperatorInfo --> ");
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_OPERATOR_INFO, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("TelRilNetwork GetPsRegStatus:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_DEBUG_LOG("TelRilNetwork GetPsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_OPERATOR_INFO, telRilRequest->serialId_);
    }
}

void TelRilNetwork::SignalStrengthUpdated(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilNetwork SignalStrengthUpdated --> ");
    const size_t readSize = sizeof(struct Rssi);
    const uint8_t *buffer = data.ReadBuffer(readSize);
    if (buffer == nullptr) {
        TELEPHONY_ERR_LOG("SignalStrengthUpdated MessageParcel read buffer failed");
        return;
    }
    const struct Rssi *rssi = reinterpret_cast<const struct Rssi *>(buffer);
    if (rssi == nullptr) {
        TELEPHONY_ERR_LOG("SignalStrengthUpdated rssi is nullptr");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "SignalStrengthUpdated OnRemoteRequest "
        " absoluteRssi:%{public}d, slotId%{public}d",
        rssi->cdma.absoluteRssi, rssi->slotId);
    int32_t indicationType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        RilProcessIndication(indicationType);
        TELEPHONY_DEBUG_LOG("TelRilNetwork::SignalStrengthUpdated indicationType:%{public}d", indicationType);
        std::shared_ptr<Rssi> signalIntensity = std::make_shared<Rssi>();
        if (signalIntensity == nullptr) {
            TELEPHONY_ERR_LOG("SignalStrengthUpdated signalIntensity is nullptr");
            return;
        }
        if (memcpy_s(signalIntensity.get(), readSize, rssi, readSize) != 0) {
            TELEPHONY_ERR_LOG("fail to copy memory");
            return;
        }
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE, signalIntensity);
    }
}

void TelRilNetwork::CsRegStatusUpdated(OHOS::MessageParcel &data)
{
    int32_t indicationType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        RilProcessIndication(indicationType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_NETWORK_STATE);
    }
}

void TelRilNetwork::GetSignalStrengthResponse(OHOS::MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("TelRilNetwork GetSignalStrengthResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_DEBUG_LOG(
        "TelRilNetwork GetSignalStrengthResponse serial:%{public}d,  error:%{public}d, type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const size_t readSize = sizeof(struct Rssi);
        const uint8_t *buffer = data.ReadBuffer(readSize);
        if (buffer == nullptr) {
            TELEPHONY_ERR_LOG("TelRilNetwork MessageParcel read buffer failed");
            return;
        }
        const struct Rssi *rssi = reinterpret_cast<const struct Rssi *>(buffer);
        if (rssi == nullptr) {
            TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> rssi == nullptr !!!");
            return;
        }
        TELEPHONY_DEBUG_LOG("TelRilNetwork OnRemoteRequest absoluteRssi:%{public}d, slotId%{public}d",
            rssi->cdma.absoluteRssi, rssi->slotId);
        std::shared_ptr<Rssi> signalIntensity = std::make_shared<Rssi>();
        if (signalIntensity == nullptr) {
            TELEPHONY_ERR_LOG("ERROR : GetSignalStrengthResponse --> signalIntensity == nullptr !!!");
            return;
        }
        if (memcpy_s(signalIntensity.get(), readSize, rssi, readSize) != 0) {
            TELEPHONY_ERR_LOG("fail to copy memory");
            return;
        }
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : GetSignalStrengthResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_INFO_LOG("TelRilNetwork::GetSignalStrengthResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, signalIntensity);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilNetwork::GetCsRegStatusResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilNetwork::GetCsRegStatusResponse start ");
    std::shared_ptr<CsRegStatusInfo> csRegStatusInfo = std::make_shared<CsRegStatusInfo>();
    if (csRegStatusInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : GetCsRegStatusResponse --> data.ReadUnpadBuffer(readSpSize) failed !!!");
        return;
    }
    csRegStatusInfo->ReadFromParcel(data);
    TELEPHONY_DEBUG_LOG(
        "ReadIccFileResponse --> csRegStatusInfo.size:%{public}d,"
        " csRegStatusInfo->regStatus:%{public}d, csRegStatusInfo->radioTechnology:%{public}d",
        sizeof(csRegStatusInfo), csRegStatusInfo->regStatus, csRegStatusInfo->radioTechnology);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("ReadIccFileResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "ReadIccFileResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d, radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : ReadIccFileResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_DEBUG_LOG("CellularRadioResponse::GetCsRegStatusResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, csRegStatusInfo);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilNetwork::GetPsRegStatusResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilNetwork::GetPsRegStatusResponse start , but need struct");
    std::shared_ptr<PsRegStatusResultInfo> psRegStateResult = std::make_shared<PsRegStatusResultInfo>();
    if (psRegStateResult == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : GetPsRegStatusResponse --> psRegStateResult == nullptr !!!");
        return;
    }
    psRegStateResult->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("GetPsRegStatusResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SendSmsMoreModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "GetPsRegStatusResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d, radioResponseInfo->type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_ERR_LOG("ERROR : GetPsRegStatusResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_DEBUG_LOG("TelRilNetwork::GetPsRegStatusResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, psRegStateResult);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

void TelRilNetwork::GetOperatorInfoResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilNetwork GetOperatorInfoResponse --> ");
    std::shared_ptr<OperatorInfoResult> operatorInfo = std::make_shared<OperatorInfoResult>();
    operatorInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("GetOperatorInfoResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_DEBUG_LOG(
        "GetOperatorInfoResponse longName:%{public}s,"
        " shortName:%{public}s, numeric:%{public}s",
        operatorInfo->longName.c_str(), operatorInfo->shortName.c_str(), operatorInfo->numeric.c_str());
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_ERR_LOG("TelRilNetwork::GetOperatorInfoResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, operatorInfo);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}
