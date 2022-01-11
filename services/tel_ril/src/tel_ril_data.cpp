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

#include "hril_modem_parcel.h"
#include "hril_notification.h"
#include "hril_request.h"

#include "telephony_errors.h"

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

TelRilData::TelRilData(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
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

void TelRilData::ProcessDataRespOrNotify(uint32_t code, MessageParcel &data)
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

DataProfileDataInfo TelRilData::ChangeDPToHalDataProfile(ITelRilManager::CellularDataProfile dataProfile)
{
    DataProfileDataInfo dataProfileInfo;
    dataProfileInfo.profileId = dataProfile.profileId_;
    dataProfileInfo.password = dataProfile.password_;
    dataProfileInfo.verType = dataProfile.verType_;
    dataProfileInfo.userName = dataProfile.userName_;
    dataProfileInfo.apn = dataProfile.apn_;
    dataProfileInfo.protocol = dataProfile.protocol_;
    dataProfileInfo.roamingProtocol = dataProfile.roamingProtocol_;
    return dataProfileInfo;
}

void TelRilData::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    UniInfo uniInfo;
    uniInfo.serial = telRilRequest->serialId_;
    uniInfo.gsmIndex = cid;
    uniInfo.arg1 = reason;
    MessageParcel wData = {};
    uniInfo.Marshalling(wData);
    int ret = SendBufferEvent(HREQ_DATA_DEACTIVATE_PDP_CONTEXT, wData);
    if (ret != HDF_SUCCESS) {
        TELEPHONY_LOGE("SendBufferEvent HREQ_DATA_DEACTIVATE_PDP_CONTEXT return: %{public}d", ret);
        DataResponseError(HRilErrType::HRIL_ERR_HDF_IPC_FAILURE, response);
    }
}

void TelRilData::DeactivatePdpContextResponse(MessageParcel &data)
{
    if (!TelRilOnlyReportResponseInfo(data)) {
        TELEPHONY_LOGE("Telril report responseInfo is fail!");
    }
}

void TelRilData::ActivatePdpContext(int32_t radioTechnology, ITelRilManager::CellularDataProfile dataProfile,
    bool isRoaming, bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_DATA_ACTIVATE_PDP_CONTEXT, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    DataCallInfo dataCallInfo;
    dataCallInfo.serial = telRilRequest->serialId_;
    dataCallInfo.radioTechnology = radioTechnology;
    dataCallInfo.dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
    dataCallInfo.roamingAllowed = allowRoaming;
    dataCallInfo.isRoaming = isRoaming;
    MessageParcel wData = {};
    MessageParcel reply = {};
    dataCallInfo.Marshalling(wData);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_DATA_ACTIVATE_PDP_CONTEXT, wData, reply, option);
    if (ret != HDF_SUCCESS) {
        TELEPHONY_LOGE("SendBufferEvent HREQ_DATA_ACTIVATE_PDP_CONTEXT return: %{public}d", ret);
        DataResponseError(HRilErrType::HRIL_ERR_HDF_IPC_FAILURE, response);
    }
}

void TelRilData::ActivatePdpContextResponse(MessageParcel &data)
{
    std::shared_ptr<SetupDataCallResultInfo> setupDataCallResultInfo = std::make_shared<SetupDataCallResultInfo>();
    setupDataCallResultInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
        return;
    }
    if (radioResponseInfo->error != HRilErrType::NONE) {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    } else {
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        setupDataCallResultInfo->flag = telRilRequest->pointer_->GetParam();
        handler->SendEvent(eventId, setupDataCallResultInfo);
    }
}

void TelRilData::GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_DATA_GET_PDP_CONTEXT_LIST, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    TELEPHONY_LOGI("telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    UniInfo uniInfo;
    uniInfo.serial = telRilRequest->serialId_;
    MessageParcel wData = {};
    uniInfo.Marshalling(wData);
    int ret = SendBufferEvent(HREQ_DATA_GET_PDP_CONTEXT_LIST, wData);
    if (ret != HDF_SUCCESS) {
        TELEPHONY_LOGE("SendBufferEvent HREQ_DATA_GET_PDP_CONTEXT_LIST return: %{public}d", ret);
        DataResponseError(HRilErrType::HRIL_ERR_HDF_IPC_FAILURE, response);
    }
}

void TelRilData::GetPdpContextListResponse(MessageParcel &data)
{
    size_t readSpSize = 0;
    const uint8_t *spBuffer = nullptr;
    const struct HRilRadioResponseInfo *radioResponseInfo = nullptr;
    std::shared_ptr<TelRilRequest> telRilRequest;
    std::shared_ptr<DataCallResultList> dataCallResultList;

    dataCallResultList = std::make_shared<DataCallResultList>();
    if (dataCallResultList == nullptr) {
        TELEPHONY_LOGE("dataCallResultList is nullptr");
        return;
    }
    dataCallResultList->ReadFromParcel(data);
    readSpSize = sizeof(struct HRilRadioResponseInfo);
    spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
    }
    radioResponseInfo = reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo is nullptr !!!");
        return;
    }
    TELEPHONY_LOGI("radioResponseInfo->serial:%{public}d, radioResponseInfo->error:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error);
    telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest is nullptr || radioResponseInfo error !");
        return;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    if (handler == nullptr) {
        TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
        return;
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
}

void TelRilData::SetInitApnInfo(
    ITelRilManager::CellularDataProfile dataProfile, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_DATA_SET_INIT_APN_INFO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    TELEPHONY_LOGI(" telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    DataProfileDataInfo dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
    dataProfileInfo.serial = telRilRequest->serialId_;
    MessageParcel wData = {};
    MessageParcel reply = {};
    dataProfileInfo.Marshalling(wData);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_DATA_SET_INIT_APN_INFO, wData, reply, option);
    if (ret != HDF_SUCCESS) {
        TELEPHONY_LOGE("SendBufferEvent HREQ_DATA_SET_INIT_APN_INFO return: %{public}d", ret);
        DataResponseError(HRilErrType::HRIL_ERR_HDF_IPC_FAILURE, response);
    }
}

void TelRilData::SetInitApnInfoResponse(MessageParcel &data)
{
    if (!TelRilOnlyReportResponseInfo(data)) {
        TELEPHONY_LOGE("Telril report responseInfo is fail!");
    }
}

void TelRilData::PdpContextListUpdated(MessageParcel &data)
{
    std::shared_ptr<DataCallResultList> dataCallResultList = std::make_shared<DataCallResultList>();
    dataCallResultList->ReadFromParcel(data);
    if (observerHandler_ != nullptr) {
        TELEPHONY_LOGI("NotifyObserver RADIO_DATA_CALL_LIST_CHANGED");
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_DATA_CALL_LIST_CHANGED, dataCallResultList);
    }
}

void TelRilData::GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response)
{
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_DATA_GET_LINK_BANDWIDTH_INFO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        return;
    }
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("ERROR : cellularRadio_ is nullptr");
        ErrorResponse(telRilRequest->serialId_, HRilErrType::HRIL_ERR_INVALID_RESPONSE);
        return;
    }
    MessageParcel wData = {};
    MessageParcel reply = {};
    wData.WriteInt32(telRilRequest->serialId_);
    wData.WriteInt32(cid);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int32_t ret = cellularRadio_->SendRequest(HREQ_DATA_GET_LINK_BANDWIDTH_INFO, wData, reply, option);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("function is failed, error: %{public}d", ret);
    }
}

void TelRilData::GetLinkBandwidthInfoResponse(MessageParcel &data)
{
    std::shared_ptr<DataLinkBandwidthInfo> dataLinkBandwidthInfo =
        std::make_shared<DataLinkBandwidthInfo>();
    if (dataLinkBandwidthInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : dataLinkBandwidthInfo == nullptr !!!");
        return;
    }

    dataLinkBandwidthInfo->ReadFromParcel(data);
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_LOGE("ERROR : spBuffer is nullptr !!!");
        return;
    }

    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : radioResponseInfo is nullptr !!!");
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR : telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return;
    }
    if (radioResponseInfo->error == HRilErrType::NONE) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR : handler is nullptr !!!");
            return;
        }
        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        handler->SendEvent(eventId, dataLinkBandwidthInfo);
    } else {
        ErrorResponse(telRilRequest, *radioResponseInfo);
    }
}

void TelRilData::SetLinkBandwidthReportingRule(
    LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response)
{
    if (cellularRadio_ == nullptr) {
        TELEPHONY_LOGE("cellularRadio_ is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    std::shared_ptr<TelRilRequest> telRilRequest =
        CreateTelRilRequest(HREQ_DATA_SET_INIT_APN_INFO, response);
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("telRilRequest is nullptr");
        DataResponseError(HRilErrType::HRIL_ERR_NULL_POINT, response);
        return;
    }
    TELEPHONY_LOGI(" telRilRequest->serialId_:%{public}d", telRilRequest->serialId_);
    DataLinkBandwidthReportingRule dLinkBandwidth;
    dLinkBandwidth.serial = telRilRequest->serialId_;
    dLinkBandwidth.rat = linkBandwidth.rat;
    dLinkBandwidth.delayMs = linkBandwidth.delayMs;
    dLinkBandwidth.delayUplinkKbps = linkBandwidth.delayUplinkKbps;
    dLinkBandwidth.delayDownlinkKbps = linkBandwidth.delayDownlinkKbps;
    dLinkBandwidth.maximumUplinkKbpsSize = linkBandwidth.maximumUplinkKbps.size();
    dLinkBandwidth.maximumDownlinkKbpsSize = linkBandwidth.maximumDownlinkKbps.size();
    dLinkBandwidth.maximumUplinkKbps = linkBandwidth.maximumUplinkKbps;
    dLinkBandwidth.maximumDownlinkKbps = linkBandwidth.maximumDownlinkKbps;
    TELEPHONY_LOGI("maximumUplinkKbpsSize:%{public}d, maximumDownlinkKbpsSize:%{public}d",
        dLinkBandwidth.maximumUplinkKbpsSize, dLinkBandwidth.maximumDownlinkKbpsSize);
    MessageParcel wData = {};
    MessageParcel reply = {};
    dLinkBandwidth.Marshalling(wData);
    OHOS::MessageOption option = {OHOS::MessageOption::TF_ASYNC};
    int ret = cellularRadio_->SendRequest(HREQ_DATA_SET_LINK_BANDWIDTH_REPORTING_RULE, wData, reply, option);
    if (ret != HDF_SUCCESS) {
        TELEPHONY_LOGE("SendBufferEvent HREQ_DATA_SET_LINK_BANDWIDTH_REPORTING_RULE return: %{public}d", ret);
        DataResponseError(HRilErrType::HRIL_ERR_HDF_IPC_FAILURE, response);
    }
}

void TelRilData::SetLinkBandwidthReportingRuleResponse(MessageParcel &data)
{
    if (!TelRilOnlyReportResponseInfo(data)) {
        TELEPHONY_LOGE("Telril report responseInfo is fail!");
    }
}
} // namespace Telephony
} // namespace OHOS