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
TelRilData::TelRilData(int32_t slotId, sptr<IRemoteObject> cellularRadio, sptr<HDI::Ril::V1_0::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, rilInterface, observerHandler, handler)
{}

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

HDI::Ril::V1_0::DataProfileDataInfo TelRilData::ChangeDPToHalDataProfile(DataProfile dataProfile)
{
    HDI::Ril::V1_0::DataProfileDataInfo dataProfileInfo;
    dataProfileInfo.profileId = dataProfile.profileId;
    dataProfileInfo.password = dataProfile.password;
    dataProfileInfo.authenticationType = dataProfile.verType;
    dataProfileInfo.userName = dataProfile.userName;
    dataProfileInfo.apn = dataProfile.apn;
    dataProfileInfo.protocol = dataProfile.protocol;
    dataProfileInfo.roamingProtocol = dataProfile.roamingProtocol;
    return dataProfileInfo;
}

int32_t TelRilData::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_0::UniInfo uniInfo;
    uniInfo.gsmIndex = cid;
    uniInfo.arg1 = reason;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_DATA_DEACTIVATE_PDP_CONTEXT,
        &HDI::Ril::V1_0::IRil::DeactivatePdpContext, uniInfo);
}

int32_t TelRilData::DeactivatePdpContextResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilData::ActivatePdpContext(int32_t radioTechnology, DataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_0::DataCallInfo dataCallInfo;
    dataCallInfo.radioTechnology = radioTechnology;
    dataCallInfo.dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
    dataCallInfo.roamingAllowed = allowRoaming;
    dataCallInfo.isRoaming = isRoaming;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_DATA_ACTIVATE_PDP_CONTEXT,
        &HDI::Ril::V1_0::IRil::ActivatePdpContext, dataCallInfo);
}

int32_t TelRilData::ActivatePdpContextResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::SetupDataCallResultInfo &iSetupDataCallResultInfo)
{
    auto getDataFunc = [&iSetupDataCallResultInfo, this](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::shared_ptr<SetupDataCallResultInfo> setupDataCallResultInfo = std::make_shared<SetupDataCallResultInfo>();
        this->BuildDataCallResultInfo(setupDataCallResultInfo, iSetupDataCallResultInfo);
        setupDataCallResultInfo->flag = telRilRequest->pointer_->GetParam();
        return setupDataCallResultInfo;
    };
    return Response<SetupDataCallResultInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, getDataFunc);
}

int32_t TelRilData::GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_0::UniInfo uniInfo;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_DATA_GET_PDP_CONTEXT_LIST,
        &HDI::Ril::V1_0::IRil::GetPdpContextList, uniInfo);
}

int32_t TelRilData::GetPdpContextListResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::DataCallResultList &iDataCallResultList)
{
    if (iDataCallResultList.size != (int32_t)iDataCallResultList.dcList.size()) {
        TELEPHONY_LOGE("Slot%{public}d iDataCallResultList.size is invalid", slotId_);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    auto getDataFunc = [&iDataCallResultList, this](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::shared_ptr<DataCallResultList> dataCallResultList = std::make_shared<DataCallResultList>();
        this->BuildDataCallResultList(dataCallResultList, iDataCallResultList);
        int32_t param = telRilRequest->pointer_->GetParam();
        for (auto &setupDataCallResultInfo : dataCallResultList->dcList) {
            setupDataCallResultInfo.flag = param;
        }
        return dataCallResultList;
    };
    return Response<DataCallResultList>(TELEPHONY_LOG_FUNC_NAME, responseInfo, getDataFunc);
}

int32_t TelRilData::SetInitApnInfo(const DataProfile &dataProfile, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_0::DataProfileDataInfo dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_DATA_SET_INIT_APN_INFO,
        &HDI::Ril::V1_0::IRil::SetInitApnInfo, dataProfileInfo);
}

int32_t TelRilData::SetInitApnInfoResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilData::PdpContextListUpdated(const HDI::Ril::V1_0::DataCallResultList &iDataCallResultList)
{
    std::shared_ptr<DataCallResultList> dataCallResultList = std::make_shared<DataCallResultList>();
    if (dataCallResultList == nullptr) {
        TELEPHONY_LOGE("Slot%{public}d dataCallResultList is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (iDataCallResultList.size != (int32_t)iDataCallResultList.dcList.size()) {
        TELEPHONY_LOGE("Slot%{public}d iDataCallResultList.size is invalid", slotId_);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    BuildDataCallResultList(dataCallResultList, iDataCallResultList);
    return Notify<DataCallResultList>(
        TELEPHONY_LOG_FUNC_NAME, dataCallResultList, RadioEvent::RADIO_DATA_CALL_LIST_CHANGED);
}

int32_t TelRilData::GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_DATA_GET_LINK_BANDWIDTH_INFO,
        &HDI::Ril::V1_0::IRil::GetLinkBandwidthInfo, cid);
}

int32_t TelRilData::GetLinkBandwidthInfoResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::DataLinkBandwidthInfo &iDataLinkBandwidthInfo)
{
    std::shared_ptr<DataLinkBandwidthInfo> dataLinkBandwidthInfo = std::make_shared<DataLinkBandwidthInfo>();
    if (dataLinkBandwidthInfo == nullptr) {
        TELEPHONY_LOGE("ERROR : dataLinkBandwidthInfo == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    BuildDataLinkBandwidthInfo(dataLinkBandwidthInfo, iDataLinkBandwidthInfo);
    return Response<DataLinkBandwidthInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, dataLinkBandwidthInfo);
}

int32_t TelRilData::SetLinkBandwidthReportingRule(
    LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_0::DataLinkBandwidthReportingRule dLinkBandwidth;
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
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_DATA_SET_LINK_BANDWIDTH_REPORTING_RULE,
        &HDI::Ril::V1_0::IRil::SetLinkBandwidthReportingRule, dLinkBandwidth);
}

int32_t TelRilData::SetLinkBandwidthReportingRuleResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilData::SetDataPermitted(const int32_t dataPermitted, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_DATA_SET_DATA_PERMITTED,
        &HDI::Ril::V1_0::IRil::SetDataPermitted, dataPermitted);
}

int32_t TelRilData::SetDataPermittedResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

void TelRilData::BuildDataCallResultList(std::shared_ptr<DataCallResultList> dataCallResultList,
    const HDI::Ril::V1_0::DataCallResultList &iDataCallResultList)
{
    dataCallResultList->size = iDataCallResultList.size;
    for (auto dc : iDataCallResultList.dcList) {
        SetupDataCallResultInfo dataCallResultInfo;
        dataCallResultInfo.flag = dc.flag;
        dataCallResultInfo.reason = dc.reason;
        dataCallResultInfo.retryTime = dc.retryTime;
        dataCallResultInfo.cid = dc.cid;
        dataCallResultInfo.active = dc.active;
        dataCallResultInfo.type = dc.type;
        dataCallResultInfo.netPortName = dc.netPortName;
        dataCallResultInfo.address = dc.address;
        dataCallResultInfo.dns = dc.dns;
        dataCallResultInfo.dnsSec = dc.dnsSec;
        dataCallResultInfo.gateway = dc.gateway;
        dataCallResultInfo.maxTransferUnit = dc.maxTransferUnit;
        dataCallResultInfo.pCscfPrimAddr = dc.pCscfPrimAddr;
        dataCallResultInfo.pCscfSecAddr = dc.pCscfSecAddr;
        dataCallResultInfo.pduSessionId = dc.pduSessionId;
        dataCallResultList->dcList.push_back(dataCallResultInfo);
    }
}

void TelRilData::BuildDataCallResultInfo(std::shared_ptr<SetupDataCallResultInfo> dataCallResult,
    const HDI::Ril::V1_0::SetupDataCallResultInfo &iSetupDataCallResultInfo)
{
    dataCallResult->flag = iSetupDataCallResultInfo.flag;
    dataCallResult->reason = iSetupDataCallResultInfo.reason;
    dataCallResult->retryTime = iSetupDataCallResultInfo.retryTime;
    dataCallResult->cid = iSetupDataCallResultInfo.cid;
    dataCallResult->active = iSetupDataCallResultInfo.active;
    dataCallResult->type = iSetupDataCallResultInfo.type;
    dataCallResult->netPortName = iSetupDataCallResultInfo.netPortName;
    dataCallResult->address = iSetupDataCallResultInfo.address;
    dataCallResult->dns = iSetupDataCallResultInfo.dns;
    dataCallResult->dnsSec = iSetupDataCallResultInfo.dnsSec;
    dataCallResult->gateway = iSetupDataCallResultInfo.gateway;
    dataCallResult->maxTransferUnit = iSetupDataCallResultInfo.maxTransferUnit;
    dataCallResult->pCscfPrimAddr = iSetupDataCallResultInfo.pCscfPrimAddr;
    dataCallResult->pCscfSecAddr = iSetupDataCallResultInfo.pCscfSecAddr;
    dataCallResult->pduSessionId = iSetupDataCallResultInfo.pduSessionId;
}

void TelRilData::BuildDataLinkBandwidthInfo(std::shared_ptr<DataLinkBandwidthInfo> dataLinkBandwidthInfo,
    const HDI::Ril::V1_0::DataLinkBandwidthInfo &iDataLinkBandwidthInfo)
{
    dataLinkBandwidthInfo->serial = iDataLinkBandwidthInfo.serial;
    dataLinkBandwidthInfo->cid = iDataLinkBandwidthInfo.cid;
    dataLinkBandwidthInfo->qi = iDataLinkBandwidthInfo.qi;
    dataLinkBandwidthInfo->dlGfbr = iDataLinkBandwidthInfo.dlGfbr;
    dataLinkBandwidthInfo->ulGfbr = iDataLinkBandwidthInfo.ulGfbr;
    dataLinkBandwidthInfo->dlMfbr = iDataLinkBandwidthInfo.dlMfbr;
    dataLinkBandwidthInfo->ulMfbr = iDataLinkBandwidthInfo.ulMfbr;
    dataLinkBandwidthInfo->ulSambr = iDataLinkBandwidthInfo.ulSambr;
    dataLinkBandwidthInfo->dlSambr = iDataLinkBandwidthInfo.dlSambr;
    dataLinkBandwidthInfo->averagingWindow = iDataLinkBandwidthInfo.averagingWindow;
}
} // namespace Telephony
} // namespace OHOS
