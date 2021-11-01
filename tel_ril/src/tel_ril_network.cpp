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
#include <securec.h>
#include "hril_network_parcel.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
namespace OHOS {
namespace Telephony {
void TelRilNetwork::AddHandlerToMap()
{
    // indication
    memberFuncMap_[HNOTI_NETWORK_CS_REG_STATUS_UPDATED] = &TelRilNetwork::NetworkRegStatusUpdated;
    memberFuncMap_[HNOTI_NETWORK_SIGNAL_STRENGTH_UPDATED] = &TelRilNetwork::SignalStrengthUpdated;

    // response
    memberFuncMap_[HREQ_NETWORK_GET_SIGNAL_STRENGTH] = &TelRilNetwork::GetSignalStrengthResponse;
    memberFuncMap_[HREQ_NETWORK_GET_CS_REG_STATUS] = &TelRilNetwork::GetCsRegStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PS_REG_STATUS] = &TelRilNetwork::GetPsRegStatusResponse;

    memberFuncMap_[HREQ_NETWORK_GET_OPERATOR_INFO] = &TelRilNetwork::GetOperatorInfoResponse;
    memberFuncMap_[HREQ_NETWORK_GET_SEARCH_INFORMATION] = &TelRilNetwork::GetNetworkSearchInformationResponse;
    memberFuncMap_[HREQ_NETWORK_GET_SELECTION_MODE] = &TelRilNetwork::GetNetworkSelectionModeResponse;
    memberFuncMap_[HREQ_NETWORK_SET_SELECTION_MODE] = &TelRilNetwork::SetNetworkSelectionModeResponse;
    memberFuncMap_[HREQ_NETWORK_SET_LOCATION_UPDATE] = &TelRilNetwork::SetNetworkLocationUpdateResponse;
    memberFuncMap_[HREQ_NETWORK_GET_SLOT_IMEI] = &TelRilNetwork::GetSlotIMEIResponse;
}

TelRilNetwork::TelRilNetwork(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilNetwork::IsNetworkResponse(uint32_t code)
{
    return ((code >= HREQ_NETWORK_BASE) && (code < HREQ_COMMON_BASE));
}

bool TelRilNetwork::IsNetworkNotification(uint32_t code)
{
    return ((code >= HNOTI_NETWORK_BASE) && (code < HNOTI_COMMON_BASE));
}

bool TelRilNetwork::IsNetworkRespOrNotify(uint32_t code)
{
    return IsNetworkResponse(code) || IsNetworkNotification(code);
}

void TelRilNetwork::ProcessNetworkRespOrNotify(uint32_t code, MessageParcel &data)
{
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

void TelRilNetwork::SetNetworkLocationUpdate(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_SET_LOCATION_UPDATE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork SetNetworkLocationUpdate::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilNetwork SetNetworkLocationUpdate:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_SET_LOCATION_UPDATE, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_PS_REG_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetPsRegStatus::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilNetwork GetPsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_PS_REG_STATUS, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_SIGNAL_STRENGTH, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetSignalStrength::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilNetwork GetSignalStrength:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_SIGNAL_STRENGTH, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_CS_REG_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetCsRegStatus::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilNetwork GetCsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_CS_REG_STATUS, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_OPERATOR_INFO, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetOperatorInfo::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilNetwork GetOperatorInfo:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_OPERATOR_INFO, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetSlotIMEI(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_SLOT_IMEI, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetSlotIMEI::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilNetwork GetSlotIMEI:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_SLOT_IMEI, telRilRequest->serialId_);
    }
}

void TelRilNetwork::SignalStrengthUpdated(MessageParcel &data)
{
    const size_t readSize = sizeof(struct Rssi);
    const uint8_t *buffer = data.ReadBuffer(readSize);
    if (buffer == nullptr) {
        TELEPHONY_LOGE("SignalStrengthUpdated MessageParcel read buffer failed");
        return;
    }
    const struct Rssi *rssi = reinterpret_cast<const struct Rssi *>(buffer);
    TELEPHONY_LOGD(
        "SignalStrengthUpdated OnRemoteRequest "
        " absoluteRssi:%{public}d, slotId%{public}d",
        rssi->lte.rxlev, rssi->lte.rsrp);
    int32_t indicationType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGD("TelRilNetwork::SignalStrengthUpdated indicationType:%{public}d", indicationType);
        std::shared_ptr<Rssi> signalIntensity = std::make_shared<Rssi>();
        if (signalIntensity == nullptr) {
            TELEPHONY_LOGE("SignalStrengthUpdated signalIntensity is nullptr");
            return;
        }
        if (memcpy_s(signalIntensity.get(), readSize, rssi, readSize) != 0) {
            TELEPHONY_LOGE("fail to copy memory");
            return;
        }
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE, signalIntensity);
    }
}

void TelRilNetwork::NetworkRegStatusUpdated(MessageParcel &data)
{
    const size_t readSize = sizeof(struct CsRegStatusInfo);
    const uint8_t *buffer = data.ReadBuffer(readSize);
    if (buffer == nullptr) {
        TELEPHONY_LOGE("NetworkRegStatusUpdated MessageParcel read buffer failed");
        return;
    }
    const struct CsRegStatusInfo *regStatus = reinterpret_cast<const struct CsRegStatusInfo *>(buffer);
    if (regStatus == nullptr) {
        TELEPHONY_LOGE("NetworkRegStatusUpdated CsRegStatusInfo is nullptr");
        return;
    }
    TELEPHONY_LOGD(
        "NetworkRegStatusUpdated OnRemoteRequest "
        " regStatus:%{public}d, radioTechnology%{public}d",
        regStatus->regStatus, regStatus->radioTechnology);
    int32_t indicationType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGD("TelRilNetwork::NetworkRegStatusUpdated indicationType:%{public}d", indicationType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_NETWORK_STATE);
    }
}

void TelRilNetwork::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_SEARCH_INFORMATION, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetNetworkSearchInformation::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilNetwork GetNetworkSearchInformation:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_SEARCH_INFORMATION, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_SELECTION_MODE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetNetworkSelectionMode::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGD("TelRilNetwork GetNetworkSelectionMode:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_SELECTION_MODE, telRilRequest->serialId_);
    }
}

void TelRilNetwork::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &result)

{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_SELECTION_MODE, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork SetNetworkSelectionMode::telRilRequest is nullptr");
            return;
        }
        SetNetworkModeInfo setNetworkModeInfo;
        setNetworkModeInfo.selectMode = automaticFlag;
        setNetworkModeInfo.oper = oper;
        setNetworkModeInfo.serial = telRilRequest->serialId_;
        TELEPHONY_LOGD(
            "TelRilNetwork SetNetworkSelectionMode selectMode:%{public}d", setNetworkModeInfo.selectMode);
        MessageParcel wData;
        setNetworkModeInfo.Marshalling(wData);
        int32_t ret = SendBufferEvent(HREQ_NETWORK_SET_SELECTION_MODE, wData);
        TELEPHONY_LOGD("HREQ_NETWORK_SET_SELECTION_MODE ret %{public}d", ret);
    }
}

void TelRilNetwork::GetSignalStrengthResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetSignalStrengthResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);

    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const size_t readSize = sizeof(struct Rssi);
        const uint8_t *buffer = data.ReadBuffer(readSize);
        if (buffer == nullptr) {
            return;
        }
        const struct Rssi *rssi = reinterpret_cast<const struct Rssi *>(buffer);
        TELEPHONY_LOGD("TelRilNetwork GetSignalStrengthResponse lte.rxlev:%{public}d, lte.rsrp%{public}d",
            rssi->lte.rxlev, rssi->lte.rsrp);
        std::shared_ptr<Rssi> signalIntensity = std::make_shared<Rssi>();
        if (signalIntensity == nullptr) {
            TELEPHONY_LOGE("ERROR : GetSignalStrengthResponse --> signalIntensity == nullptr !!!");
            return;
        }
        if (memcpy_s(signalIntensity.get(), readSize, rssi, readSize) != 0) {
            TELEPHONY_LOGE("fail to copy memory");
            return;
        }
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetSignalStrengthResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGD("TelRilNetwork::GetSignalStrengthResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, signalIntensity);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetCsRegStatusResponse(MessageParcel &data)
{
    std::shared_ptr<CsRegStatusInfo> csRegStatusInfo = std::make_shared<CsRegStatusInfo>();
    if (csRegStatusInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetCsRegStatusResponse --> data.ReadUnpadBuffer(readSpSize) failed !!!");
        return;
    }
    csRegStatusInfo->ReadFromParcel(data);
    TELEPHONY_LOGD(
        "GetCsRegStatusResponse --> csRegStatusInfo.size:%{public}zu,"
        " csRegStatusInfo->regStatus:%{public}d, csRegStatusInfo->radioTechnology:%{public}d",
        sizeof(csRegStatusInfo), csRegStatusInfo->regStatus, csRegStatusInfo->radioTechnology);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetCsRegStatusResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "ReadIccFileResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : ReadIccFileResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGD("CellularRadioResponse::GetCsRegStatusResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, csRegStatusInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetPsRegStatusResponse(MessageParcel &data)
{
    std::shared_ptr<PsRegStatusResultInfo> psRegStateResult = std::make_shared<PsRegStatusResultInfo>();
    if (psRegStateResult == nullptr) {
        TELEPHONY_LOGE("ERROR : GetPsRegStatusResponse --> psRegStateResult == nullptr !!!");
        return;
    }
    psRegStateResult->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetPsRegStatusResponse --> read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : GetPsRegStatusResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "GetPsRegStatusResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetPsRegStatusResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGD("TelRilNetwork::GetPsRegStatusResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, psRegStateResult);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetOperatorInfoResponse(MessageParcel &data)
{
    std::shared_ptr<OperatorInfoResult> operatorInfo = std::make_shared<OperatorInfoResult>();
    if (operatorInfo == nullptr) {
        TELEPHONY_LOGE("operatorInfo == nullptr");
        return;
    }
    operatorInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetOperatorInfoResponse read spBuffer failed");
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
            TELEPHONY_LOGD("TelRilNetwork::GetOperatorInfoResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, operatorInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetNetworkSearchInformationResponse(MessageParcel &data)
{
    std::shared_ptr<AvailableNetworkList> availableNetworkList = std::make_shared<AvailableNetworkList>();
    if (availableNetworkList == nullptr) {
        TELEPHONY_LOGE("operatorInfo == nullptr");
        return;
    }
    availableNetworkList->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetNetworkSearchInformationResponse read spBuffer failed");
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
            TELEPHONY_LOGD("TelRilNetwork::GetNetworkSearchInformationResponse eventId:%{public}d", eventId);
            availableNetworkList->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, availableNetworkList);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetNetworkSelectionModeResponse(MessageParcel &data)
{
    std::shared_ptr<SetNetworkModeInfo> setNetworkModeInfo = std::make_shared<SetNetworkModeInfo>();
    if (setNetworkModeInfo == nullptr) {
        TELEPHONY_LOGE("operatorInfo == nullptr");
        return;
    }
    setNetworkModeInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetNetworkSelectionModeResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGD("TelRilNetwork::GetNetworkSelectionModeResponse eventId:%{public}d", eventId);
            setNetworkModeInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, setNetworkModeInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::SetNetworkSelectionModeResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork:: SetNetworkSelectionModeResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetNetworkSelectionModeResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGD(
        "SetNetworkSelectionModeResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SetNetworkSelectionModeResponse --> handler == nullptr !!!");
                return;
            }
            handler->SendEvent(telRilRequest->pointer_);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::SetNetworkLocationUpdateResponse(MessageParcel &data)
{
    std::shared_ptr<LocationUpdateResultInfo> locationUpdateResultInfo =
        std::make_shared<LocationUpdateResultInfo>();
    if (locationUpdateResultInfo == nullptr) {
        TELEPHONY_LOGE("operatorInfo == nullptr");
        return;
    }
    locationUpdateResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("SetNetworkLocationUpdateResponse read spBuffer failed");
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
            TELEPHONY_LOGD("TelRilNetwork::SetNetworkLocationUpdateResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, locationUpdateResultInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetSlotIMEIResponse(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    if (buffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetSlotIMEIResponse --> buffer == nullptr !!!");
        return;
    }
    std::shared_ptr<std::string> imeiID = std::make_shared<std::string>(buffer);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : GetSlotIMEIResponse --> spBuffer == nullptr!!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGD(
        "GetSlotIMEIResponse --> radioResponseInfo->serial:%{public}d, "
        "radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetSlotIMEIResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            handler->SendEvent(eventId, imeiID);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("ERROR : GetSlotIMEIResponse --> telRilRequest == nullptr || radioResponseInfo error !!!");
    }
}
} // namespace Telephony
} // namespace OHOS
