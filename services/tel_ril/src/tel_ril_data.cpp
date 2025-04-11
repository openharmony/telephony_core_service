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
#include "radio_event.h"
#include "tel_ril_modem_parcel.h"

namespace OHOS {
namespace Telephony {
TelRilData::TelRilData(int32_t slotId, sptr<HDI::Ril::V1_4::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, rilInterface, observerHandler, handler)
{}

HDI::Ril::V1_1::DataProfileDataInfo TelRilData::ChangeDPToHalDataProfile(DataProfile dataProfile)
{
    HDI::Ril::V1_1::DataProfileDataInfo dataProfileInfo;
    dataProfileInfo.profileId = dataProfile.profileId;
    dataProfileInfo.password = dataProfile.password;
    dataProfileInfo.authenticationType = dataProfile.verType;
    dataProfileInfo.userName = dataProfile.userName;
    dataProfileInfo.apn = dataProfile.apn;
    dataProfileInfo.protocol = dataProfile.protocol;
    dataProfileInfo.roamingProtocol = dataProfile.roamingProtocol;
    return dataProfileInfo;
}

HDI::Ril::V1_3::DataProfileDataInfoWithApnTypes TelRilData::ChangeDPToHalDataProfileWithApnTypes(
    DataProfile dataProfile)
{
    HDI::Ril::V1_3::DataProfileDataInfoWithApnTypes dataProfileInfoWithApnTypes;
    dataProfileInfoWithApnTypes.profileId = dataProfile.profileId;
    dataProfileInfoWithApnTypes.password = dataProfile.password;
    dataProfileInfoWithApnTypes.authenticationType = dataProfile.verType;
    dataProfileInfoWithApnTypes.userName = dataProfile.userName;
    dataProfileInfoWithApnTypes.apn = dataProfile.apn;
    dataProfileInfoWithApnTypes.protocol = dataProfile.protocol;
    dataProfileInfoWithApnTypes.roamingProtocol = dataProfile.roamingProtocol;
    dataProfileInfoWithApnTypes.supportedApnTypesBitmap = static_cast<uint64_t>(dataProfile.supportedApnTypesBitmap);
    return dataProfileInfoWithApnTypes;
}

int32_t TelRilData::DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::UniInfo uniInfo;
    uniInfo.gsmIndex = cid;
    uniInfo.arg1 = reason;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::DeactivatePdpContext, uniInfo);
}

int32_t TelRilData::DeactivatePdpContextResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilData::ActivatePdpContext(int32_t radioTechnology, DataProfile dataProfile, bool isRoaming,
    bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_3::DataCallInfoWithApnTypes dataCallInfoWithApnTypes;
    dataCallInfoWithApnTypes.radioTechnology = radioTechnology;
    dataCallInfoWithApnTypes.dataProfileInfo = ChangeDPToHalDataProfileWithApnTypes(dataProfile);
    dataCallInfoWithApnTypes.roamingAllowed = allowRoaming;
    dataCallInfoWithApnTypes.isRoaming = isRoaming;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_3::IRil::ActivatePdpContextWithApnTypes,
        dataCallInfoWithApnTypes);
}

int32_t TelRilData::ActivatePdpContextResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::SetupDataCallResultInfo &iSetupDataCallResultInfo)
{
    auto getDataFunc = [&iSetupDataCallResultInfo, this](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::shared_ptr<SetupDataCallResultInfo> setupDataCallResultInfo = std::make_shared<SetupDataCallResultInfo>();
        this->BuildDataCallResultInfo(setupDataCallResultInfo, iSetupDataCallResultInfo);
        setupDataCallResultInfo->flag = telRilRequest->pointer_->GetParam();
        return setupDataCallResultInfo;
    };
    return Response<SetupDataCallResultInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, iSetupDataCallResultInfo,
        getDataFunc);
}

int32_t TelRilData::GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::UniInfo uniInfo;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetPdpContextList, uniInfo);
}

int32_t TelRilData::GetPdpContextListResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::DataCallResultList &iDataCallResultList)
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
    HDI::Ril::V1_1::DataProfileDataInfo dataProfileInfo = ChangeDPToHalDataProfile(dataProfile);
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SetInitApnInfo, dataProfileInfo);
}

int32_t TelRilData::SetInitApnInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilData::PdpContextListUpdated(const HDI::Ril::V1_1::DataCallResultList &iDataCallResultList)
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

int32_t TelRilData::DataLinkCapabilityUpdated(const HDI::Ril::V1_1::DataLinkCapability &dataLinkCapability)
{
    std::shared_ptr<DataLinkCapability> linkCapability = std::make_shared<DataLinkCapability>();
    if (linkCapability == nullptr) {
        TELEPHONY_LOGE("Slot%{public}d linkCapability is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    linkCapability->primaryDownlinkKbps = dataLinkCapability.primaryDownlinkKbps;
    linkCapability->primaryUplinkKbps = dataLinkCapability.primaryUplinkKbps;
    linkCapability->secondaryDownlinkKbps = dataLinkCapability.secondaryDownlinkKbps;
    linkCapability->secondaryUplinkKbps = dataLinkCapability.secondaryUplinkKbps;
    return Notify<DataLinkCapability>(
        TELEPHONY_LOG_FUNC_NAME, linkCapability, RadioEvent::RADIO_LINK_CAPABILITY_CHANGED);
}

int32_t TelRilData::GetLinkCapability(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetLinkCapability);
}

int32_t TelRilData::GetLinkCapabilityResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::DataLinkCapability &dataLinkCapability)
{
    std::shared_ptr<DataLinkCapability> linkCapability = std::make_shared<DataLinkCapability>();
    if (linkCapability == nullptr) {
        TELEPHONY_LOGE("ERROR : linkCapability == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    linkCapability->primaryDownlinkKbps = dataLinkCapability.primaryDownlinkKbps;
    linkCapability->primaryUplinkKbps = dataLinkCapability.primaryUplinkKbps;
    linkCapability->secondaryDownlinkKbps = dataLinkCapability.secondaryDownlinkKbps;
    linkCapability->secondaryUplinkKbps = dataLinkCapability.secondaryUplinkKbps;
    return Response<DataLinkCapability>(TELEPHONY_LOG_FUNC_NAME, responseInfo, linkCapability);
}

int32_t TelRilData::GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetLinkBandwidthInfo, cid);
}

int32_t TelRilData::GetLinkBandwidthInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::DataLinkBandwidthInfo &iDataLinkBandwidthInfo)
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
    HDI::Ril::V1_1::DataLinkBandwidthReportingRule dLinkBandwidth;
    dLinkBandwidth.rat = linkBandwidth.rat;
    dLinkBandwidth.delayMs = linkBandwidth.delayMs;
    dLinkBandwidth.delayUplinkKbps = linkBandwidth.delayUplinkKbps;
    dLinkBandwidth.delayDownlinkKbps = linkBandwidth.delayDownlinkKbps;
    dLinkBandwidth.maximumUplinkKbpsSize = static_cast<int32_t>(linkBandwidth.maximumUplinkKbps.size());
    dLinkBandwidth.maximumDownlinkKbpsSize = static_cast<int32_t>(linkBandwidth.maximumDownlinkKbps.size());
    dLinkBandwidth.maximumUplinkKbps = linkBandwidth.maximumUplinkKbps;
    dLinkBandwidth.maximumDownlinkKbps = linkBandwidth.maximumDownlinkKbps;
    TELEPHONY_LOGD("maximumUplinkKbpsSize:%{public}d, maximumDownlinkKbpsSize:%{public}d",
        dLinkBandwidth.maximumUplinkKbpsSize, dLinkBandwidth.maximumDownlinkKbpsSize);
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SetLinkBandwidthReportingRule, dLinkBandwidth);
}

int32_t TelRilData::SetLinkBandwidthReportingRuleResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilData::SetDataPermitted(const int32_t dataPermitted, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SetDataPermitted, dataPermitted);
}

int32_t TelRilData::SetDataPermittedResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilData::CleanAllConnections(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_2::IRil::CleanAllConnections);
}

int32_t TelRilData::CleanAllConnectionsResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

void TelRilData::BuildDataCallResultList(std::shared_ptr<DataCallResultList> dataCallResultList,
    const HDI::Ril::V1_1::DataCallResultList &iDataCallResultList)
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
    const HDI::Ril::V1_1::SetupDataCallResultInfo &iSetupDataCallResultInfo)
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
    const HDI::Ril::V1_1::DataLinkBandwidthInfo &iDataLinkBandwidthInfo)
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

int32_t TelRilData::NetworkSliceUrspRpt(const HDI::Ril::V1_4::NetworkSliceUrspInfo &networksliceUrspInfo)
{
    std::shared_ptr<NetworkSliceUrspInfo> urspinfo = std::make_shared<NetworkSliceUrspInfo>();
    if (urspinfo == nullptr) {
        TELEPHONY_LOGE("Slot%{public}d urspinfo is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    urspinfo->urspInfo = networksliceUrspInfo.urspInfo;
    return Notify<NetworkSliceUrspInfo>(TELEPHONY_LOG_FUNC_NAME, urspinfo, RadioEvent::RADIO_NETWORKSLICE_URSP_RPT);
}

int32_t TelRilData::NetworkSliceAllowedNssaiRpt(
    const HDI::Ril::V1_4::NetworkSliceAllowedNssaiInfo &networksliceAllowedNssaiInfo)
{
    std::shared_ptr<NetworkSliceAllowedNssaiInfo> allowednssaiinfo = std::make_shared<NetworkSliceAllowedNssaiInfo>();
    if (allowednssaiinfo == nullptr) {
        TELEPHONY_LOGE("Slot%{public}d nssniinfo is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    allowednssaiinfo->allowednssaiInfo = networksliceAllowedNssaiInfo.allowednssaiInfo;
    return Notify<NetworkSliceAllowedNssaiInfo>(
        TELEPHONY_LOG_FUNC_NAME, allowednssaiinfo, RadioEvent::RADIO_NETWORKSLICE_ALLOWEDNSSAI_RPT);
}

int32_t TelRilData::NetworkSliceEhplmnRpt(const HDI::Ril::V1_4::NetworkSliceEhplmnInfo &networksliceEhplmnInfo)
{
    std::shared_ptr<NetworkSliceEhplmnInfo> ehplmninfo = std::make_shared<NetworkSliceEhplmnInfo>();
    if (ehplmninfo == nullptr) {
        TELEPHONY_LOGE("Slot%{public}d Ehplmninfo is nullptr", slotId_);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    ehplmninfo->ehplmnInfo = networksliceEhplmnInfo.ehplmnInfo;
    return Notify<NetworkSliceEhplmnInfo>(TELEPHONY_LOG_FUNC_NAME, ehplmninfo,
        RadioEvent::RADIO_NETWORKSLICE_EHPLMN_RPT);
}
} // namespace Telephony
} // namespace OHOS
