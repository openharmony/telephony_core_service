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

#include "tel_ril_data.h"

#include "core_service_hisysevent.h"
#include "hril_modem_parcel.h"
#include "hril_notification.h"
#include "hril_request.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
void TelRilData::AddHandlerToMap()
{
    // Notification
    memberFuncMap_[HNOTI_DATA_PDP_CONTEXT_LIST_UPDATED] = &TelRilData::PdpContextListUpdated;
    // response
    memberFuncMap_[HREQ_DATA_SET_INIT_APN_INFO] = &TelRilData::SetInitApnInfoResponse;
    memberFuncMap_[HREQ_DATA_ACTIVATE_PDP_CONTEXT] = &TelRilData::ActivatePdpContextResponse;
    memberFuncMap_[HREQ_DATA_DEACTIVATE_PDP_CONTEXT] = &TelRilData::DeactivatePdpContextResponse;
    memberFuncMap_[HREQ_DATA_GET_PDP_CONTEXT_LIST] = &TelRilData::GetPdpContextListResponse;
    memberFuncMap_[HREQ_DATA_GET_LINK_BANDWIDTH_INFO] = &TelRilData::GetLinkBandwidthInfoResponse;
    memberFuncMap_[HREQ_DATA_SET_LINK_BANDWIDTH_REPORTING_RULE] = &TelRilData::SetLinkBandwidthReportingRuleResponse;
}

TelRilData::TelRilData(int32_t slotId, sptr<IRemoteObject> cellularRadio,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, observerHandler, handler)
{
    AddHandlerToMap();
}

bool TelRilData::IsDataResponse(uint32_t code)
{
    return ((code >= HREQ_DATA_BASE) && (code < HREQ_NETWORK_BASE));
}

bool TelRilData::IsDataNotification(uint32_t code)
{
    return ((code >= HNOTI_DATA_BASE) && (code < HNOTI_NETWORK_BASE));
}

bool TelRilData::IsDataRespOrNotify(uint32_t code)
{
    return IsDataResponse(code) || IsDataNotification(code);
}

void TelRilData::DataResponseError(HRilErrType errCode, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::lock_guard<std::mutex> lockRequest(responseErrorLock_);
    uint32_t eventId = response->GetInnerEventId();
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = response->GetOwner();
    std::shared_ptr<HRilRadioResponseInfo> respInfo = std::make_shared<HRilRadioResponseInfo>();
    respInfo->flag = response->GetParam();
    respInfo->error = errCode;
    if (!handler->SendEvent(eventId, respInfo)) {
        TELEPHONY_LOGE("Send eventId:%{public}d is failed!", eventId);
    }
}

DataProfileDataInfo TelRilData::ChangeDPToHalDataProfile(DataProfile dataProfile)
{
    DataProfileDataInfo dataProfileInfo;
    dataProfileInfo.profileId = dataProfile.profileId;
    dataProfileInfo.password = dataProfile.password;
    dataProfileInfo.verType = dataProfile.verType;
    dataProfileInfo.userName = dataProfile.userName;
    dataProfileInfo.apn = dataProfile.apn;
    dataProfileInfo.protocol = dataProfile.protocol;
    dataProfileInfo.roamingProtocol = dataProfile.roamingProtocol;
    return dataProfileInfo;
}

int32_t TelRilData::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        CoreServiceHiSysEvent::WriteDataActivateFaultEvent(slotId_, SWITCH_OFF,
            CellularDataErrorCode::DATA_ERROR_PDP_DEACTIVATE_FAIL,
            "Create HREQ_DATA_DEACTIVATE_PDP_CONTEXT request fail");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    UniInfo uniInfo;
    uniInfo.serial = telRilRequest->serialId_;
    uniInfo.gsmIndex = cid;
    uniInfo.arg1 = reason;
    int32_t ret = SendBufferEvent(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, uniInfo);
    if (ret != 0) {
        TELEPHONY_LOGE("Send HREQ_DATA_DEACTIVATE_PDP_CONTEXT return: %{public}d", ret);
        CoreServiceHiSysEvent::WriteDataActivateFaultEvent(slotId_, SWITCH_OFF,
            CellularDataErrorCode::DATA_ERROR_PDP_DEACTIVATE_FAIL, "Send HREQ_DATA_DEACTIVATE_PDP_CONTEXT event fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::DeactivatePdpContextResponse(MessageParcel &data)
{
    return TelRilOnlyReportResponseInfo(data);
}

int32_t TelRilData::ActivatePdpContext(int32_t radioTechnology, DataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_DATA_ACTIVATE_PDP_CONTEXT, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        CoreServiceHiSysEvent::WriteDataActivateFaultEvent(slotId_, SWITCH_ON,
            CellularDataErrorCode::DATA_ERROR_PDP_ACTIVATE_FAIL, "Create HREQ_DATA_ACTIVATE_PDP_CONTEXT request fail");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DataCallInfo dataCallInfo;
    dataCallInfo.serial = telRilRequest->serialId_;
    dataCallInfo.radioTechnology = radioTechnology;
    dataCallInfo.dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
    dataCallInfo.roamingAllowed = allowRoaming;
    dataCallInfo.isRoaming = isRoaming;
    int32_t ret = SendBufferEvent(HREQ_DATA_ACTIVATE_PDP_CONTEXT, dataCallInfo);
    if (ret != 0) {
        TELEPHONY_LOGE("Send HREQ_DATA_ACTIVATE_PDP_CONTEXT return: %{public}d", ret);
        CoreServiceHiSysEvent::WriteDataActivateFaultEvent(slotId_, SWITCH_ON,
            CellularDataErrorCode::DATA_ERROR_PDP_ACTIVATE_FAIL, "Send HREQ_DATA_ACTIVATE_PDP_CONTEXT event fail");
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::ActivatePdpContextResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<SetupDataCallResultInfo> setupDataCallResultInfo = std::make_shared<SetupDataCallResultInfo>();
    setupDataCallResultInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error != HRilErrType::NONE) {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    } else {
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        setupDataCallResultInfo->flag = telRilRequest->pointer_->GetParam();
        handler->SendEvent(eventId, setupDataCallResultInfo);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_DATA_GET_PDP_CONTEXT_LIST, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    UniInfo uniInfo;
    uniInfo.serial = telRilRequest->serialId_;
    int32_t ret = SendBufferEvent(HREQ_DATA_GET_PDP_CONTEXT_LIST, uniInfo);
    if (ret != 0) {
        TELEPHONY_LOGE("HREQ_DATA_GET_PDP_CONTEXT_LIST return: %{public}d", ret);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::GetPdpContextListResponse(MessageParcel &data)
{
    size_t readSpSize = 0;
    const uint8_t *spBuffer = nullptr;
    const struct HRilRadioResponseInfo *radioResponseInfo = nullptr;
    std::shared_ptr<TelRilRequest> telRilRequest;
    std::shared_ptr<DataCallResultList> dataCallResultList;

    readSpSize = sizeof(struct HRilRadioResponseInfo);
    spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    dataCallResultList = std::make_shared<DataCallResultList>();
    if (dataCallResultList == nullptr) {
        TELEPHONY_LOGE("dataCallResultList is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    dataCallResultList->ReadFromParcel(data);

    radioResponseInfo = reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error != HRilErrType::NONE) {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    } else {
        int32_t param = telRilRequest->pointer_->GetParam();
        for (auto &setupDataCallResultInfo : dataCallResultList->dcList) {
            setupDataCallResultInfo.flag = param;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, dataCallResultList);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::SetInitApnInfo(const DataProfile &dataProfile, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_DATA_SET_INIT_APN_INFO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI(" telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    DataProfileDataInfo dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
    dataProfileInfo.serial = telRilRequest->serialId_;

    int32_t ret = SendBufferEvent(HREQ_DATA_SET_INIT_APN_INFO, dataProfileInfo);
    if (ret != 0) {
        TELEPHONY_LOGE("Send HREQ_DATA_ACTIVATE_PDP_CONTEXT return: %{public}d", ret);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::SetInitApnInfoResponse(MessageParcel &data)
{
    return TelRilOnlyReportResponseInfo(data);
}

int32_t TelRilData::PdpContextListUpdated(MessageParcel &data)
{
    std::shared_ptr<DataCallResultList> dataCallResultList = std::make_shared<DataCallResultList>();
    dataCallResultList->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("NotifyObserver RADIO_DATA_CALL_LIST_CHANGED");
        observerHandler_->NotifyObserver(RadioEvent::RADIO_DATA_CALL_LIST_CHANGED, dataCallResultList);
        return TELEPHONY_ERR_SUCCESS;
    }
    return TELEPHONY_ERR_LOCAL_PTR_NULL;
}

int32_t TelRilData::GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_DATA_GET_LINK_BANDWIDTH_INFO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("ERROR : cellularRadio_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t ret =
        SendInt32sEvent(HREQ_DATA_GET_LINK_BANDWIDTH_INFO, HRIL_EVENT_COUNT_2, telRilRequest->serialId_, cid);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::GetLinkBandwidthInfoResponse(MessageParcel &data)
{
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DataLinkBandwidthInfo> dataLinkBandwidthInfo = std::make_shared<DataLinkBandwidthInfo>();
    if (dataLinkBandwidthInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : dataLinkBandwidthInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    dataLinkBandwidthInfo->ReadFromParcel(data);

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo is nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, dataLinkBandwidthInfo);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::SetLinkBandwidthReportingRule(
    LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_DATA_SET_INIT_APN_INFO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    TELEPHONY_LOGI(" telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    DataLinkBandwidthReportingRule dLinkBandwidth;
    dLinkBandwidth.serial = telRilRequest->serialId_;
    dLinkBandwidth.rat = linkBandwidth.rat;
    dLinkBandwidth.delayMs = linkBandwidth.delayMs;
    dLinkBandwidth.delayUplinkKbps = linkBandwidth.delayUplinkKbps;
    dLinkBandwidth.delayDownlinkKbps = linkBandwidth.delayDownlinkKbps;
    dLinkBandwidth.maximumUplinkKbpsSize = static_cast<int32_t>(linkBandwidth.maximumUplinkKbps.size());
    dLinkBandwidth.maximumDownlinkKbpsSize = static_cast<int32_t>(linkBandwidth.maximumDownlinkKbps.size());
    dLinkBandwidth.maximumUplinkKbps = linkBandwidth.maximumUplinkKbps;
    dLinkBandwidth.maximumDownlinkKbps = linkBandwidth.maximumDownlinkKbps;
    TELEPHONY_LOGI("maximumUplinkKbpsSize:%{public}d, maximumDownlinkKbpsSize:%{public}d",
        dLinkBandwidth.maximumUplinkKbpsSize, dLinkBandwidth.maximumDownlinkKbpsSize);
    int32_t ret = SendBufferEvent(HREQ_DATA_SET_LINK_BANDWIDTH_REPORTING_RULE, dLinkBandwidth);
    if (ret != 0) {
        TELEPHONY_LOGE("HREQ_DATA_SET_LINK_BANDWIDTH_REPORTING_RULE return: %{public}d", ret);
        return TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilData::SetLinkBandwidthReportingRuleResponse(MessageParcel &data)
{
    return TelRilOnlyReportResponseInfo(data);
}
} // namespace Telephony
} // namespace OHOS