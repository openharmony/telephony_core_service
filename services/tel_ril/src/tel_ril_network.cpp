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

#include "hril_notification.h"
#include "hril_request.h"

using namespace std;
using OHOS::IRemoteObject;
using OHOS::sptr;
namespace OHOS {
namespace Telephony {
void TelRilNetwork::AddHandlerToMap()
{
    // indication
    memberFuncMap_[HNOTI_NETWORK_CS_REG_STATUS_UPDATED] = &TelRilNetwork::NetworkCsRegStatusUpdated;
    memberFuncMap_[HNOTI_NETWORK_SIGNAL_STRENGTH_UPDATED] = &TelRilNetwork::SignalStrengthUpdated;
    memberFuncMap_[HNOTI_NETWORK_TIME_UPDATED] = &TelRilNetwork::NetworkTimeUpdated;
    memberFuncMap_[HNOTI_NETWORK_TIME_ZONE_UPDATED] = &TelRilNetwork::NetworkTimeZoneUpdated;
    memberFuncMap_[HNOTI_NETWORK_IMS_REG_STATUS_UPDATED] = &TelRilNetwork::NetworkImsRegStatusUpdated;
    memberFuncMap_[HNOTI_NETWORK_PS_REG_STATUS_UPDATED] = &TelRilNetwork::NetworkPsRegStatusUpdated;
    memberFuncMap_[HNOTI_NETWORK_PHY_CHNL_CFG_UPDATED] = &TelRilNetwork::NetworkPhyChnlCfgUpdated;

    // response
    memberFuncMap_[HREQ_NETWORK_GET_IMS_REG_STATUS] = &TelRilNetwork::GetImsRegStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_SIGNAL_STRENGTH] = &TelRilNetwork::GetSignalStrengthResponse;
    memberFuncMap_[HREQ_NETWORK_GET_CS_REG_STATUS] = &TelRilNetwork::GetCsRegStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PS_REG_STATUS] = &TelRilNetwork::GetPsRegStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_OPERATOR_INFO] = &TelRilNetwork::GetOperatorInfoResponse;
    memberFuncMap_[HREQ_NETWORK_GET_NETWORK_SEARCH_INFORMATION] =
        &TelRilNetwork::GetNetworkSearchInformationResponse;
    memberFuncMap_[HREQ_NETWORK_GET_NETWORK_SELECTION_MODE] = &TelRilNetwork::GetNetworkSelectionModeResponse;
    memberFuncMap_[HREQ_NETWORK_SET_NETWORK_SELECTION_MODE] = &TelRilNetwork::SetNetworkSelectionModeResponse;
    memberFuncMap_[HREQ_NETWORK_GET_NEIGHBORING_CELLINFO_LIST] = &TelRilNetwork::GetNeighboringCellInfoListResponse;
    memberFuncMap_[HREQ_NETWORK_GET_CURRENT_CELL_INFO] = &TelRilNetwork::GetCurrentCellInfoResponse;
    memberFuncMap_[HREQ_NETWORK_SET_PREFERRED_NETWORK] = &TelRilNetwork::SetPreferredNetworkResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PREFERRED_NETWORK] = &TelRilNetwork::GetPreferredNetworkResponse;
    memberFuncMap_[HREQ_NETWORK_SET_PS_ATTACH_STATUS] = &TelRilNetwork::SetPsAttachStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PS_ATTACH_STATUS] = &TelRilNetwork::GetPsAttachStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_RADIO_CAPABILITY] = &TelRilNetwork::GetRadioCapabilityResponse;
    memberFuncMap_[HREQ_NETWORK_SET_RADIO_CAPABILITY] = &TelRilNetwork::SetRadioCapabilityResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PHYSICAL_CHANNEL_CONFIG] = &TelRilNetwork::GetPhysicalChannelConfigResponse;
    memberFuncMap_[HREQ_NETWORK_SET_LOCATE_UPDATES] = &TelRilNetwork::SetLocateUpdatesResponse;
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

void TelRilNetwork::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_PS_REG_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetPsRegStatus::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilNetwork GetPsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_PS_REG_STATUS, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_IMS_REG_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetImsRegStatus::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilNetwork GetImsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_IMS_REG_STATUS, telRilRequest->serialId_);
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
        TELEPHONY_LOGI("TelRilNetwork GetSignalStrength:%{public}d", telRilRequest->serialId_);
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
        TELEPHONY_LOGI("TelRilNetwork GetCsRegStatus:%{public}d", telRilRequest->serialId_);
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
        TELEPHONY_LOGI("TelRilNetwork GetOperatorInfo:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_OPERATOR_INFO, telRilRequest->serialId_);
    }
}

void TelRilNetwork::SetPsAttachStatus(int32_t psAttachStatus, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_PS_ATTACH_STATUS, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetPsAttachStatus::telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(psAttachStatus);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        cellularRadio_->SendRequest(HREQ_NETWORK_SET_PS_ATTACH_STATUS, data, reply, option);
        TELEPHONY_LOGI("PsAttachStatus: %{public}d", psAttachStatus);
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
}

void TelRilNetwork::GetPsAttachStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_PS_ATTACH_STATUS, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetPsAttachStatus::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilNetwork GetPsAttachStatus:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_PS_ATTACH_STATUS, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_NETWORK_GET_NEIGHBORING_CELLINFO_LIST, response);
    if (cellularRadio_ != nullptr) {
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetCellInfoList:telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilNetwork GetCellInfoList:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_NEIGHBORING_CELLINFO_LIST, telRilRequest->serialId_);
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
}

void TelRilNetwork::GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_CURRENT_CELL_INFO, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetCurrentCellInfo is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilNetwork GetCurrentCellInfo:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_CURRENT_CELL_INFO, telRilRequest->serialId_);
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
    TELEPHONY_LOGI(
        "SignalStrengthUpdated OnRemoteRequest "
        " absoluteRssi:%{public}d, slotId%{public}d",
        rssi->lte.rxlev, rssi->lte.rsrp);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::SignalStrengthUpdated indicationType:%{public}d", flagType);
        std::shared_ptr<Rssi> signalIntensity = std::make_shared<Rssi>();
        if (signalIntensity.get() == nullptr) {
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

void TelRilNetwork::GetNeighboringCellInfoListResponse(MessageParcel &data)
{
    std::shared_ptr<CellListNearbyInfo> cellListNearbyInfo = std::make_shared<CellListNearbyInfo>();

    if (cellListNearbyInfo == nullptr) {
        TELEPHONY_LOGE("cellListNearbyInfo == nullptr");
        return;
    }
    cellListNearbyInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetNeighboringCellInfoListResponse read spBuffer failed");
        return;
    }
    TELEPHONY_LOGI("GetNeighboringCellInfoListResponse enter--> cellListNearbyInfo.itemNum= %{public}d",
        cellListNearbyInfo->itemNum);
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
            TELEPHONY_LOGI("TelRilNetwork::GetNeighboringCellInfoListResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, cellListNearbyInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetCurrentCellInfoResponse(MessageParcel &data)
{
    std::shared_ptr<CurrentCellInfo> currentCellInfo = std::make_shared<CurrentCellInfo>();
    if (currentCellInfo == nullptr) {
        TELEPHONY_LOGE("currentCellInfo == nullptr");
        return;
    }
    currentCellInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetCurrentCellInfoResponse read spBuffer failed");
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
            TELEPHONY_LOGI("TelRilNetwork::GetCurrentCellInfoResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, currentCellInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::NetworkCsRegStatusUpdated(MessageParcel &data)
{
    std::shared_ptr<CsRegStatusInfo> regStatusInfo = std::make_shared<CsRegStatusInfo>();
    if (regStatusInfo == nullptr) {
        TELEPHONY_LOGE("regStatusInfo == nullptr");
        return;
    }
    regStatusInfo->ReadFromParcel(data);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkCsRegStatusUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_NETWORK_STATE, regStatusInfo);
    }
}

void TelRilNetwork::NetworkPsRegStatusUpdated(MessageParcel &data)
{
    std::shared_ptr<CsRegStatusInfo> regStatusInfo = std::make_shared<CsRegStatusInfo>();
    if (regStatusInfo == nullptr) {
        TELEPHONY_LOGE("regStatusInfo == nullptr");
        return;
    }
    regStatusInfo->ReadFromParcel(data);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkPsRegStatusUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_NETWORK_STATE, regStatusInfo);
    }
}

void TelRilNetwork::NetworkPhyChnlCfgUpdated(MessageParcel &data)
{
    std::shared_ptr<ChannelConfigInfoList> phyChnlCfgList = std::make_shared<ChannelConfigInfoList>();
    if (phyChnlCfgList == nullptr) {
        TELEPHONY_LOGE("phyChnlCfgList == nullptr");
        return;
    }
    phyChnlCfgList->ReadFromParcel(data);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkPhyChnlCfgUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_CHANNEL_CONFIG_UPDATE, phyChnlCfgList);
    }
}

void TelRilNetwork::NetworkTimeUpdated(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> timeStr = std::make_shared<std::string>(buffer);
    TELEPHONY_LOGI("TelRilNetwork::NetworkTimeUpdated time:%{public}s", timeStr->c_str());
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkTimeUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_NETWORK_TIME_UPDATE, timeStr);
    }
}

void TelRilNetwork::NetworkTimeZoneUpdated(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> timeZoneStr = std::make_shared<std::string>(buffer);
    TELEPHONY_LOGI("TelRilNetwork::NetworkTimeUpdated time:%{public}s", timeZoneStr->c_str());

    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkTimeZoneUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_NETWORK_TIME_ZONE_UPDATE, timeZoneStr);
    }
}

void TelRilNetwork::NetworkImsRegStatusUpdated(MessageParcel &data)
{
    std::shared_ptr<ImsRegStatusInfo> imsRegStatusInfo = std::make_shared<ImsRegStatusInfo>();
    if (imsRegStatusInfo == nullptr) {
        TELEPHONY_LOGE("imsRegStatusInfo == nullptr");
        return;
    }
    imsRegStatusInfo->ReadFromParcel(data);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkImsRegStatusUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_IMS_REG_STATUS_UPDATE, imsRegStatusInfo);
    }
}

void TelRilNetwork::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_NETWORK_SEARCH_INFORMATION, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetNetworkSearchInformation::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilNetwork GetNetworkSearchInformation:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_NETWORK_SEARCH_INFORMATION, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_GET_NETWORK_SELECTION_MODE, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetNetworkSelectionMode::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilNetwork GetNetworkSelectionMode:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_NETWORK_SELECTION_MODE, telRilRequest->serialId_);
    }
}

void TelRilNetwork::GetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_NETWORK_GET_PREFERRED_NETWORK, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetPreferredNetwork::telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetPreferredNetwork:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_PREFERRED_NETWORK, telRilRequest->serialId_);
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
}

void TelRilNetwork::GetImsRegStatusResponse(MessageParcel &data)
{
    std::shared_ptr<ImsRegStatusInfo> imsRegStatusInfo = std::make_shared<ImsRegStatusInfo>();
    if (imsRegStatusInfo == nullptr) {
        TELEPHONY_LOGE("GetImsRegStatusResponse imsRegStatusInfo  == nullptr");
        return;
    }
    imsRegStatusInfo->ReadFromParcel(data);
    TELEPHONY_LOGI("GetImsRegStatusResponse notifyType:%{public}d,regInfo:%{public}d,extInfo:%{public}d",
        imsRegStatusInfo->notifyType, imsRegStatusInfo->regInfo, imsRegStatusInfo->extInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(sizeof(HRilRadioResponseInfo));
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetImsRegStatusResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("GetImsRegStatusResponse radioResponseInfo == nullptr");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetImsRegStatusResponse eventId:%{public}d", eventId);
            imsRegStatusInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, imsRegStatusInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &result)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
            CreateTelRilRequest(HREQ_NETWORK_SET_NETWORK_SELECTION_MODE, result);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork SetNetworkSelectionMode::telRilRequest is nullptr");
            return;
        }
        SetNetworkModeInfo setNetworkModeInfo;
        setNetworkModeInfo.selectMode = automaticFlag;
        setNetworkModeInfo.oper = oper;
        setNetworkModeInfo.serial = telRilRequest->serialId_;
        TELEPHONY_LOGI(
            "TelRilNetwork SetNetworkSelectionMode selectMode:%{public}d", setNetworkModeInfo.selectMode);
        MessageParcel wData;
        setNetworkModeInfo.Marshalling(wData);
        int32_t ret = SendBufferEvent(HREQ_NETWORK_SET_NETWORK_SELECTION_MODE, wData);
        TELEPHONY_LOGI("HREQ_NETWORK_SET_NETWORK_SELECTION_MODE ret %{public}d", ret);
    }
}

void TelRilNetwork::SetPreferredNetwork(
    int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_NETWORK_SET_PREFERRED_NETWORK, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetPreferredNetwork::telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(preferredNetworkType);
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        cellularRadio_->SendRequest(HREQ_NETWORK_SET_PREFERRED_NETWORK, data, reply, option);
        TELEPHONY_LOGI("preferredNetworkType: %{public}d", preferredNetworkType);
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
}

void TelRilNetwork::GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest =
                CreateTelRilRequest(HREQ_NETWORK_GET_RADIO_CAPABILITY, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_LOGE("TelRilNetwork GetRadioCapability::telRilRequest is nullptr");
            return;
        }
        TELEPHONY_LOGI("TelRilNetwork GetRadioCapability:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_RADIO_CAPABILITY, telRilRequest->serialId_);
    }
}

void TelRilNetwork::SetRadioCapability(
    RadioCapabilityInfo &radioCapabilityInfo, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_RADIO_CAPABILITY, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetRadioCapability::telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(radioCapabilityInfo.ratfamily);
        data.WriteString(radioCapabilityInfo.modemId);
        MessageParcel reply;
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        int ret = cellularRadio_->SendRequest(HREQ_NETWORK_SET_RADIO_CAPABILITY, data, reply, option);
        TELEPHONY_LOGI(
            "SetRadioCapability --> SendBufferEvent(HREQ_NETWORK_SET_RADIO_CAPABILITY, wData) return ID: "
            "%{public}d",
            ret);
    } else {
        TELEPHONY_LOGE("ERROR : HREQ_NETWORK_SET_RADIO_CAPABILITY --> cellularRadio_ == nullptr !!!");
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
}

void TelRilNetwork::GetPhysicalChannelConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_NETWORK_GET_PHYSICAL_CHANNEL_CONFIG, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("GetPhysicalChannelConfig::telRilRequest is nullptr");
        return;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("GetPhysicalChannelConfig:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_PHYSICAL_CHANNEL_CONFIG, telRilRequest->serialId_);
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
}

void TelRilNetwork::SetLocateUpdates(HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_LOCATE_UPDATES, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetLocateUpdates::telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(static_cast<int32_t>(mode));
        OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
        cellularRadio_->SendRequest(HREQ_NETWORK_SET_LOCATE_UPDATES, data, reply, option);
        TELEPHONY_LOGI("locateUpdateMode: %{public}d", mode);
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
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

    if (telRilRequest.get() != nullptr && telRilRequest->pointer_ != nullptr) {
        const size_t readSize = sizeof(struct Rssi);
        const uint8_t *buffer = data.ReadBuffer(readSize);
        if (buffer == nullptr) {
            return;
        }
        const struct Rssi *rssi = reinterpret_cast<const struct Rssi *>(buffer);
        TELEPHONY_LOGI("TelRilNetwork GetSignalStrengthResponse lte.rxlev:%{public}d, lte.rsrp%{public}d",
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
            if (handler.get() == nullptr) {
                TELEPHONY_LOGE("ERROR : GetSignalStrengthResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetSignalStrengthResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, signalIntensity);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetCsRegStatusResponse(MessageParcel &data)
{
    std::shared_ptr<CsRegStatusInfo> regStatusInfo = std::make_shared<CsRegStatusInfo>();
    if (regStatusInfo == nullptr) {
        TELEPHONY_LOGE("GetCsRegStatusResponse regStatusInfo  == nullptr");
        return;
    }
    regStatusInfo->ReadFromParcel(data);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(sizeof(HRilRadioResponseInfo));
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetCsRegStatusResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("GetCsRegStatusResponse radioResponseInfo == nullptr");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetCsRegStatusResponse eventId:%{public}d", eventId);
            regStatusInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, regStatusInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetPsRegStatusResponse(MessageParcel &data)
{
    std::shared_ptr<PsRegStatusResultInfo> regStatusInfo = std::make_shared<PsRegStatusResultInfo>();
    if (regStatusInfo == nullptr) {
        TELEPHONY_LOGE("GetPsRegStatusResponse regStatusInfo  == nullptr");
        return;
    }
    regStatusInfo->ReadFromParcel(data);
    TELEPHONY_LOGI(
        "GetPsRegStatusResponse notifyType:%{public}d,regStatus:%{public}d,lacCode:%{public}d,"
        "cellId:%{public}d,radioTechnology:%{public}d",
        regStatusInfo->notifyType, regStatusInfo->regStatus, regStatusInfo->lacCode, regStatusInfo->cellId,
        regStatusInfo->radioTechnology);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(sizeof(HRilRadioResponseInfo));
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetPsRegStatusResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("GetPsRegStatusResponse radioResponseInfo == nullptr");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetPsRegStatusResponse eventId:%{public}d", eventId);
            regStatusInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, regStatusInfo);
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
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetOperatorInfoResponse eventId:%{public}d", eventId);
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
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetNetworkSearchInformationResponse eventId:%{public}d", eventId);
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
    if (setNetworkModeInfo.get() == nullptr) {
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
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("radioResponseInfo == nullptr");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetNetworkSelectionModeResponse eventId:%{public}d", eventId);
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

void TelRilNetwork::SetPreferredNetworkResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork:: SetPreferredNetworkResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetPreferredNetworkResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGI(
        "SetPreferredNetworkResponse --> radioResponseInfo->serial:%{public}d,"
        " radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SetPreferredNetworkResponse --> handler == nullptr !!!");
                return;
            }
            handler->SendEvent(telRilRequest->pointer_);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetPreferredNetworkResponse(MessageParcel &data)
{
    std::shared_ptr<PreferredNetworkTypeInfo> preferredNetworkTypeInfo =
        std::make_shared<PreferredNetworkTypeInfo>();
    if (preferredNetworkTypeInfo == nullptr) {
        TELEPHONY_LOGE("preferredNetworkTypeInfo == nullptr");
        return;
    }
    preferredNetworkTypeInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetPreferredNetworkResponse read spBuffer failed");
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
            TELEPHONY_LOGI("TelRilNetwork::GetPreferredNetworkResponse eventId:%{public}d", eventId);
            preferredNetworkTypeInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, preferredNetworkTypeInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetRadioCapabilityResponse(MessageParcel &data)
{
    std::shared_ptr<RadioCapabilityInfo> radioCapabilityInfo = std::make_shared<RadioCapabilityInfo>();
    if (radioCapabilityInfo == nullptr) {
        TELEPHONY_LOGE("GetRadioCapabilityResponse radioCapabilityInfo  == nullptr");
        return;
    }
    radioCapabilityInfo->ReadFromParcel(data);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(sizeof(HRilRadioResponseInfo));
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetRadioCapabilityResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
            reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("GetRadioCapabilityResponse radioResponseInfo == nullptr");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetRadioCapabilityResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, radioCapabilityInfo);
            TELEPHONY_LOGI(
                "TelRilNetwork::GetRadioCapabilityResponse ratfamily:%{public}d", radioCapabilityInfo->ratfamily);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
            TELEPHONY_LOGE("GetRadioCapabilityResponse handler fail");
        }
    }
}

void TelRilNetwork::SetRadioCapabilityResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetRadioCapabilityResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
            reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetRadioCapabilityResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_LOGI("SetRadioCapabilityResponse serial:%{public}d, error:%{public}d ", radioResponseInfo->serial,
                   radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_LOGI("SetRadioCapabilityResponse serialId_:%{public}d, requestId_:%{public}d,", telRilRequest->serialId_,
                   telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGW("WARNING : SetRadioCapabilityResponse --> handler == nullptr !!!");
                return;
            }
            handler->SendEvent(telRilRequest->pointer_);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::SetPsAttachStatusResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork:: SetPsAttachStatusResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetPsAttachStatusResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SetPsAttachStatusResponse --> handler == nullptr !!!");
                return;
            }
            handler->SendEvent(telRilRequest->pointer_);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetPsAttachStatusResponse(MessageParcel &data)
{
    std::shared_ptr<PsAttachStatusInfo> psAttachStatusInfo = std::make_shared<PsAttachStatusInfo>();
    if (psAttachStatusInfo == nullptr) {
        TELEPHONY_LOGE("psAttachStatusInfo == nullptr");
        return;
    }
    psAttachStatusInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetPsAttachStatusResponse read spBuffer failed");
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
            TELEPHONY_LOGI("TelRilNetwork::GetPsAttachStatusResponse eventId:%{public}d", eventId);
            psAttachStatusInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, psAttachStatusInfo);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::GetPhysicalChannelConfigResponse(MessageParcel &data)
{
    std::shared_ptr<ChannelConfigInfoList> channelConfigInfoList = std::make_shared<ChannelConfigInfoList>();
    if (channelConfigInfoList == nullptr) {
        TELEPHONY_LOGE("channelConfigInfoList == nullptr");
        return;
    }
    channelConfigInfoList->ReadFromParcel(data);
    const size_t readSpSize = sizeof(HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetPhysicalChannelConfigResponse read spBuffer failed");
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
            TELEPHONY_LOGI("GetPhysicalChannelConfigResponse eventId:%{public}d", eventId);
            channelConfigInfoList->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, channelConfigInfoList);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}

void TelRilNetwork::SetLocateUpdatesResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork:: SetLocateUpdatesResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetLocateUpdatesResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SetLocateUpdatesResponse --> handler == nullptr !!!");
                return;
            }
            handler->SendEvent(telRilRequest->pointer_);
        } else {
            ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    }
}
} // namespace Telephony
} // namespace OHOS
