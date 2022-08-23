/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "radio_event.h"

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
    memberFuncMap_[HNOTI_NETWORK_PS_REG_STATUS_UPDATED] = &TelRilNetwork::NetworkPsRegStatusUpdated;
    memberFuncMap_[HNOTI_NETWORK_PHY_CHNL_CFG_UPDATED] = &TelRilNetwork::NetworkPhyChnlCfgUpdated;
    memberFuncMap_[HNOTI_NETWORK_CURRENT_CELL_UPDATED] = &TelRilNetwork::NetworkCurrentCellUpdated;

    // response
    memberFuncMap_[HREQ_NETWORK_GET_SIGNAL_STRENGTH] = &TelRilNetwork::GetSignalStrengthResponse;
    memberFuncMap_[HREQ_NETWORK_GET_CS_REG_STATUS] = &TelRilNetwork::GetCsRegStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PS_REG_STATUS] = &TelRilNetwork::GetPsRegStatusResponse;
    memberFuncMap_[HREQ_NETWORK_GET_OPERATOR_INFO] = &TelRilNetwork::GetOperatorInfoResponse;
    memberFuncMap_[HREQ_NETWORK_GET_NETWORK_SEARCH_INFORMATION] = &TelRilNetwork::GetNetworkSearchInformationResponse;
    memberFuncMap_[HREQ_NETWORK_GET_NETWORK_SELECTION_MODE] = &TelRilNetwork::GetNetworkSelectionModeResponse;
    memberFuncMap_[HREQ_NETWORK_SET_NETWORK_SELECTION_MODE] = &TelRilNetwork::SetNetworkSelectionModeResponse;
    memberFuncMap_[HREQ_NETWORK_GET_NEIGHBORING_CELLINFO_LIST] = &TelRilNetwork::GetNeighboringCellInfoListResponse;
    memberFuncMap_[HREQ_NETWORK_GET_CURRENT_CELL_INFO] = &TelRilNetwork::GetCurrentCellInfoResponse;
    memberFuncMap_[HREQ_NETWORK_SET_PREFERRED_NETWORK] = &TelRilNetwork::SetPreferredNetworkResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PREFERRED_NETWORK] = &TelRilNetwork::GetPreferredNetworkResponse;
    memberFuncMap_[HREQ_NETWORK_GET_RADIO_CAPABILITY] = &TelRilNetwork::GetRadioCapabilityResponse;
    memberFuncMap_[HREQ_NETWORK_GET_PHYSICAL_CHANNEL_CONFIG] = &TelRilNetwork::GetPhysicalChannelConfigResponse;
    memberFuncMap_[HREQ_NETWORK_SET_LOCATE_UPDATES] = &TelRilNetwork::SetLocateUpdatesResponse;
    memberFuncMap_[HREQ_NETWORK_SET_NOTIFICATION_FILTER] = &TelRilNetwork::SetNotificationFilterResponse;
    memberFuncMap_[HREQ_NETWORK_SET_DEVICE_STATE] = &TelRilNetwork::SetDeviceStateResponse;
}

TelRilNetwork::TelRilNetwork(int32_t slotId, sptr<IRemoteObject> cellularRadio,
    sptr<HDI::Ril::V1_0::IRilInterface> rilInterface, std::shared_ptr<ObserverHandler> observerHandler,
    std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, rilInterface, observerHandler, handler)
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

int32_t TelRilNetwork::GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_GET_PS_REG_STATUS, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetPsRegStatus::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetPsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_PS_REG_STATUS, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_GET_SIGNAL_STRENGTH, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetSignalStrength::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetSignalStrength:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_SIGNAL_STRENGTH, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_GET_CS_REG_STATUS, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetCsRegStatus::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetCsRegStatus:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_CS_REG_STATUS, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_GET_OPERATOR_INFO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetOperatorInfo::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetOperatorInfo:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_OPERATOR_INFO, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_NETWORK_GET_NEIGHBORING_CELLINFO_LIST, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetCellInfoList:telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetCellInfoList:%{public}d", telRilRequest->serialId_);
        SendInt32Event(HREQ_NETWORK_GET_NEIGHBORING_CELLINFO_LIST, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_GET_CURRENT_CELL_INFO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetCurrentCellInfo is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetCurrentCellInfo:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_CURRENT_CELL_INFO, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::SignalStrengthUpdated(MessageParcel &data)
{
    const size_t readSize = sizeof(struct Rssi);
    const uint8_t *buffer = data.ReadBuffer(readSize);
    if (buffer == nullptr) {
        TELEPHONY_LOGE("SignalStrengthUpdated MessageParcel read buffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct Rssi *rssi = reinterpret_cast<const struct Rssi *>(buffer);
    TELEPHONY_LOGI("SignalStrengthUpdated absoluteRssi:%{public}d, %{public}d", rssi->lte.rxlev, rssi->lte.rsrp);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("observerHandler_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    } else {
        TELEPHONY_LOGI("TelRilNetwork::SignalStrengthUpdated indicationType:%{public}d", flagType);
        std::shared_ptr<Rssi> signalIntensity = std::make_shared<Rssi>();
        if (signalIntensity.get() == nullptr) {
            TELEPHONY_LOGE("SignalStrengthUpdated signalIntensity is nullptr");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        if (memcpy_s(signalIntensity.get(), readSize, rssi, readSize) != 0) {
            TELEPHONY_LOGE("fail to copy memory");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        observerHandler_->NotifyObserver(RadioEvent::RADIO_SIGNAL_STRENGTH_UPDATE, signalIntensity);
        return TELEPHONY_ERR_SUCCESS;
    }
}

int32_t TelRilNetwork::GetNeighboringCellInfoListResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetNeighboringCellInfoListResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<CellListNearbyInfo> cellListNearbyInfo = std::make_shared<CellListNearbyInfo>();
    if (cellListNearbyInfo == nullptr) {
        TELEPHONY_LOGE("cellListNearbyInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    cellListNearbyInfo->ReadFromParcel(data);

    TELEPHONY_LOGI("GetNeighboringCellInfoListResponse enter--> cellListNearbyInfo.itemNum= %{public}d",
        cellListNearbyInfo->itemNum);
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetNeighboringCellInfoListResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetNeighboringCellInfoListResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, cellListNearbyInfo);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetCurrentCellInfoResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetCurrentCellInfoResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<CellListCurrentInfo> currentCellList = std::make_shared<CellListCurrentInfo>();
    if (currentCellList == nullptr) {
        TELEPHONY_LOGE("currentCellList == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    currentCellList->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetCurrentCellInfoResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetCurrentCellInfoResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, currentCellList);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::NetworkCsRegStatusUpdated(MessageParcel &data)
{
    std::shared_ptr<CsRegStatusInfo> regStatusInfo = std::make_shared<CsRegStatusInfo>();
    if (regStatusInfo == nullptr) {
        TELEPHONY_LOGE("regStatusInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    regStatusInfo->ReadFromParcel(data);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("observerHandler_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    } else {
        TELEPHONY_LOGI("TelRilNetwork::NetworkCsRegStatusUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(RadioEvent::RADIO_NETWORK_STATE, regStatusInfo);
        return TELEPHONY_ERR_SUCCESS;
    }
}

int32_t TelRilNetwork::NetworkPsRegStatusUpdated(MessageParcel &data)
{
    std::shared_ptr<CsRegStatusInfo> regStatusInfo = std::make_shared<CsRegStatusInfo>();
    if (regStatusInfo == nullptr) {
        TELEPHONY_LOGE("regStatusInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    regStatusInfo->ReadFromParcel(data);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkPsRegStatusUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(RadioEvent::RADIO_NETWORK_STATE, regStatusInfo);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("observerHandler_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::NetworkPhyChnlCfgUpdated(MessageParcel &data)
{
    std::shared_ptr<ChannelConfigInfoList> phyChnlCfgList = std::make_shared<ChannelConfigInfoList>();
    if (phyChnlCfgList == nullptr) {
        TELEPHONY_LOGE("phyChnlCfgList == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    phyChnlCfgList->ReadFromParcel(data);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkPhyChnlCfgUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CHANNEL_CONFIG_UPDATE, phyChnlCfgList);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("observerHandler_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::NetworkCurrentCellUpdated(MessageParcel &data)
{
    std::shared_ptr<CellListCurrentInfo> currentCellList = std::make_shared<CellListCurrentInfo>();
    if (currentCellList == nullptr) {
        TELEPHONY_LOGE("currentCellList == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    currentCellList->ReadFromParcel(data);
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkCurrentCellUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(RadioEvent::RADIO_CURRENT_CELL_UPDATE, currentCellList);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("observerHandler_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::NetworkTimeUpdated(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> timeStr = std::make_shared<std::string>(buffer);
    TELEPHONY_LOGI("TelRilNetwork::NetworkTimeUpdated time:%{public}s", timeStr->c_str());
    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkTimeUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(RadioEvent::RADIO_NETWORK_TIME_UPDATE, timeStr);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("observerHandler_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::NetworkTimeZoneUpdated(MessageParcel &data)
{
    const char *buffer = data.ReadCString();
    std::shared_ptr<std::string> timeZoneStr = std::make_shared<std::string>(buffer);
    TELEPHONY_LOGI("TelRilNetwork::NetworkTimeUpdated time:%{public}s", timeZoneStr->c_str());

    int32_t flagType = data.ReadInt32();
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork::NetworkTimeZoneUpdated indicationType:%{public}d", flagType);
        observerHandler_->NotifyObserver(RadioEvent::RADIO_NETWORK_TIME_ZONE_UPDATE, timeZoneStr);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("observerHandler_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_NETWORK_GET_NETWORK_SEARCH_INFORMATION, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetNetworkSearchInformation::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetNetworkSearchInformation:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_NETWORK_SEARCH_INFORMATION, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_NETWORK_GET_NETWORK_SELECTION_MODE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetNetworkSelectionMode::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetNetworkSelectionMode:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_NETWORK_SELECTION_MODE, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_GET_PREFERRED_NETWORK, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetPreferredNetwork::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetPreferredNetwork:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_PREFERRED_NETWORK, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::SetNetworkSelectionMode(
    int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &result)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_NETWORK_SELECTION_MODE, result);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetNetworkSelectionMode::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        SetNetworkModeInfo setNetworkModeInfo;
        setNetworkModeInfo.selectMode = automaticFlag;
        setNetworkModeInfo.oper = oper;
        setNetworkModeInfo.serial = telRilRequest->serialId_;
        TELEPHONY_LOGI("TelRilNetwork SetNetworkSelectionMode selectMode:%{public}d", setNetworkModeInfo.selectMode);
        int32_t ret = SendBufferEvent(HREQ_NETWORK_SET_NETWORK_SELECTION_MODE, setNetworkModeInfo);
        TELEPHONY_LOGI("HREQ_NETWORK_SET_NETWORK_SELECTION_MODE ret %{public}d", ret);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::SetPreferredNetwork(
    int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_PREFERRED_NETWORK, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetPreferredNetwork::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(slotId_);
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(preferredNetworkType);
        OHOS::MessageOption option = { OHOS::MessageOption::TF_ASYNC };
        cellularRadio_->SendRequest(HREQ_NETWORK_SET_PREFERRED_NETWORK, data, reply, option);
        TELEPHONY_LOGI("preferredNetworkType: %{public}d", preferredNetworkType);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_GET_RADIO_CAPABILITY, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetRadioCapability::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("TelRilNetwork GetRadioCapability:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_RADIO_CAPABILITY, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetPhysicalChannelConfig(const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_NETWORK_GET_PHYSICAL_CHANNEL_CONFIG, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("GetPhysicalChannelConfig::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (cellularRadio_ != nullptr) {
        TELEPHONY_LOGI("GetPhysicalChannelConfig:%{public}d", telRilRequest->serialId_);
        SendInt32sEvent(HREQ_NETWORK_GET_PHYSICAL_CHANNEL_CONFIG, HRIL_EVENT_COUNT_1, telRilRequest->serialId_);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::SetLocateUpdates(HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_LOCATE_UPDATES, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetLocateUpdates::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(slotId_);
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(static_cast<int32_t>(mode));
        OHOS::MessageOption option = { OHOS::MessageOption::TF_ASYNC };
        cellularRadio_->SendRequest(HREQ_NETWORK_SET_LOCATE_UPDATES, data, reply, option);
        TELEPHONY_LOGI("locateUpdateMode: %{public}d", mode);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s  cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::SetNotificationFilter(int32_t newFilter, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_NOTIFICATION_FILTER, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetNotificationFilter::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(slotId_);
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(static_cast<int32_t>(newFilter));
        OHOS::MessageOption option = { OHOS::MessageOption::TF_ASYNC };
        cellularRadio_->SendRequest(HREQ_NETWORK_SET_NOTIFICATION_FILTER, data, reply, option);
        TELEPHONY_LOGI("TelRilNetwork::SetNotificationFilter: %{public}d", newFilter);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::SetDeviceState(
    int32_t deviceStateType, bool deviceStateOn, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_NETWORK_SET_DEVICE_STATE, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork SetDeviceState::telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ != nullptr) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteInt32(slotId_);
        data.WriteInt32(telRilRequest->serialId_);
        data.WriteInt32(static_cast<int32_t>(deviceStateType));
        data.WriteInt32(static_cast<int32_t>(deviceStateOn));
        OHOS::MessageOption option = { OHOS::MessageOption::TF_ASYNC };
        cellularRadio_->SendRequest(HREQ_NETWORK_SET_DEVICE_STATE, data, reply, option);
        TELEPHONY_LOGI("TelRilNetwork::SetDeviceState deviceStateType:%{public}d, deviceState:%{public}d",
            deviceStateType, deviceStateOn);
        return TELEPHONY_ERR_SUCCESS;
    } else {
        TELEPHONY_LOGE("%{public}s cellularRadio_ == nullptr", __func__);
        return ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
    }
}

int32_t TelRilNetwork::GetSignalStrengthResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork GetSignalStrengthResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest.get() != nullptr && telRilRequest->pointer_ != nullptr) {
        const size_t readSize = sizeof(struct Rssi);
        const uint8_t *buffer = data.ReadBuffer(readSize);
        if (buffer == nullptr) {
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        const struct Rssi *rssi = reinterpret_cast<const struct Rssi *>(buffer);
        TELEPHONY_LOGI("TelRilNetwork GetSignalStrengthResponse lte.rxlev:%{public}d, lte.rsrp%{public}d",
            rssi->lte.rxlev, rssi->lte.rsrp);
        std::shared_ptr<Rssi> signalIntensity = std::make_shared<Rssi>();
        if (signalIntensity == nullptr) {
            TELEPHONY_LOGE("ERROR : GetSignalStrengthResponse --> signalIntensity == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        if (memcpy_s(signalIntensity.get(), readSize, rssi, readSize) != 0) {
            TELEPHONY_LOGE("fail to copy memory");
            return TELEPHONY_ERR_MEMCPY_FAIL;
        }
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler.get() == nullptr) {
                TELEPHONY_LOGE("ERROR : GetSignalStrengthResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetSignalStrengthResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, signalIntensity);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetCsRegStatusResponse(MessageParcel &data)
{
    const uint8_t *spBuffer = data.ReadUnpadBuffer(sizeof(HRilRadioResponseInfo));
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetCsRegStatusResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<CsRegStatusInfo> regStatusInfo = std::make_shared<CsRegStatusInfo>();
    if (regStatusInfo == nullptr) {
        TELEPHONY_LOGE("GetCsRegStatusResponse regStatusInfo  == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    regStatusInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("GetCsRegStatusResponse radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetCsRegStatusResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetCsRegStatusResponse eventId:%{public}d", eventId);
            regStatusInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, regStatusInfo);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetPsRegStatusResponse(MessageParcel &data)
{
    const uint8_t *spBuffer = data.ReadUnpadBuffer(sizeof(HRilRadioResponseInfo));
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetPsRegStatusResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<PsRegStatusResultInfo> regStatusInfo = std::make_shared<PsRegStatusResultInfo>();
    if (regStatusInfo == nullptr) {
        TELEPHONY_LOGE("GetPsRegStatusResponse regStatusInfo  == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    regStatusInfo->ReadFromParcel(data);
    TELEPHONY_LOGI("GetPsRegStatusResponse notifyType:%{public}d,regStatus:%{public}d,lacCode:%{public}d,"
                   "cellId:%{public}d,radioTechnology:%{public}d",
        regStatusInfo->notifyType, regStatusInfo->regStatus, regStatusInfo->lacCode, regStatusInfo->cellId,
        regStatusInfo->radioTechnology);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("GetPsRegStatusResponse radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetPsRegStatusResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetPsRegStatusResponse eventId:%{public}d", eventId);
            regStatusInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, regStatusInfo);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetOperatorInfoResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetOperatorInfoResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<OperatorInfoResult> operatorInfo = std::make_shared<OperatorInfoResult>();
    if (operatorInfo == nullptr) {
        TELEPHONY_LOGE("operatorInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    operatorInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetOperatorInfoResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetOperatorInfoResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, operatorInfo);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetNetworkSearchInformationResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetNetworkSearchInformationResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<AvailableNetworkList> availableNetworkList = std::make_shared<AvailableNetworkList>();
    if (availableNetworkList == nullptr) {
        TELEPHONY_LOGE("operatorInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    availableNetworkList->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetNetworkSearchInformationResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetNetworkSearchInformationResponse eventId:%{public}d, itemNum:%{public}d",
                eventId, availableNetworkList->itemNum);
            availableNetworkList->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, availableNetworkList);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetNetworkSelectionModeResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetNetworkSelectionModeResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<SetNetworkModeInfo> setNetworkModeInfo = std::make_shared<SetNetworkModeInfo>();
    if (setNetworkModeInfo.get() == nullptr) {
        TELEPHONY_LOGE("operatorInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    setNetworkModeInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetNetworkSelectionModeResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetNetworkSelectionModeResponse eventId:%{public}d", eventId);
            setNetworkModeInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, setNetworkModeInfo);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::SetNetworkSelectionModeResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork:: SetNetworkSelectionModeResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SetNetworkSelectionModeResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            handler->SendEvent(telRilRequest->pointer_);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::SetPreferredNetworkResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork:: SetPreferredNetworkResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetPreferredNetworkResponse --> radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("SetPreferredNetworkResponse --> radioResponseInfo->serial:%{public}d,"
                   " radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SetPreferredNetworkResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            handler->SendEvent(telRilRequest->pointer_);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetPreferredNetworkResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetPreferredNetworkResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<PreferredNetworkTypeInfo> preferredNetworkTypeInfo = std::make_shared<PreferredNetworkTypeInfo>();
    if (preferredNetworkTypeInfo == nullptr) {
        TELEPHONY_LOGE("preferredNetworkTypeInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    preferredNetworkTypeInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetPreferredNetworkResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetPreferredNetworkResponse eventId:%{public}d", eventId);
            preferredNetworkTypeInfo->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, preferredNetworkTypeInfo);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetRadioCapabilityResponse(MessageParcel &data)
{
    const uint8_t *spBuffer = data.ReadUnpadBuffer(sizeof(HRilRadioResponseInfo));
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetRadioCapabilityResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<RadioCapabilityInfo> radioCapabilityInfo = std::make_shared<RadioCapabilityInfo>();
    if (radioCapabilityInfo == nullptr) {
        TELEPHONY_LOGE("GetRadioCapabilityResponse radioCapabilityInfo  == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    radioCapabilityInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("GetRadioCapabilityResponse radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetRadioCapabilityResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("TelRilNetwork::GetRadioCapabilityResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId, radioCapabilityInfo);
            TELEPHONY_LOGI("GetRadioCapaResp ratFamily:%{public}d", radioCapabilityInfo->ratFamily);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            TELEPHONY_LOGE("GetRadioCapabilityResponse handler fail");
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::GetPhysicalChannelConfigResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("GetPhysicalChannelConfigResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<ChannelConfigInfoList> channelConfigInfoList = std::make_shared<ChannelConfigInfoList>();
    if (channelConfigInfoList == nullptr) {
        TELEPHONY_LOGE("channelConfigInfoList == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    channelConfigInfoList->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("radioResponseInfo == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : GetPhysicalChannelConfigResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_LOGI("GetPhysicalChannelConfigResponse eventId:%{public}d", eventId);
            channelConfigInfoList->flag = telRilRequest->pointer_->GetParam();
            handler->SendEvent(eventId, channelConfigInfoList);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::SetLocateUpdatesResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork:: SetLocateUpdatesResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetLocateUpdatesResponse --> radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("ERROR : SetLocateUpdatesResponse --> handler == nullptr !!!");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            handler->SendEvent(telRilRequest->pointer_);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::SetNotificationFilterResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork::SetNotificationFilterResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetNotificationFilterResponse --> radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("SetNotificationFilterResponse handler is nullptr: this is the expected result");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            handler->SendEvent(telRilRequest->pointer_);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}

int32_t TelRilNetwork::SetDeviceStateResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("TelRilNetwork::SetDeviceStateResponse read spBuffer failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : SetDeviceStateResponse --> radioResponseInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_LOGE("SetDeviceStateResponse handler is nullptr: this is the expected result");
                return TELEPHONY_ERR_LOCAL_PTR_NULL;
            }
            handler->SendEvent(telRilRequest->pointer_);
            return TELEPHONY_ERR_SUCCESS;
        } else {
            return ErrorResponse(telRilRequest, *radioResponseInfo);
        }
    } else {
        TELEPHONY_LOGE("telRilRequest or pointer_ == nullptr !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
}
} // namespace Telephony
} // namespace OHOS
