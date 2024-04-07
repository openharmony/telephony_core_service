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

#ifndef TEL_RIL_DATA_H
#define TEL_RIL_DATA_H

#include "hril_data_parcel.h"
#include "tel_ril_base.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class TelRilData : public TelRilBase {
public:
    TelRilData(int32_t slotId, sptr<HDI::Ril::V1_3::IRil> rilInterface,
        std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler);
    ~TelRilData() = default;

    HDI::Ril::V1_1::DataProfileDataInfo ChangeDPToHalDataProfile(DataProfile dataProfile);
    int32_t DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t DeactivatePdpContextResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SetInitApnInfo(const DataProfile &dataProfile, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetInitApnInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t ActivatePdpContext(int32_t radioTechnology, DataProfile dataProfile, bool isRoaming, bool allowRoaming,
        const AppExecFwk::InnerEvent::Pointer &response);
    int32_t ActivatePdpContextResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::SetupDataCallResultInfo &iSetupDataCallResultInfo);
    int32_t GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetPdpContextListResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::DataCallResultList &iDataCallResultList);
    int32_t PdpContextListUpdated(const HDI::Ril::V1_1::DataCallResultList &iDataCallResultList);
    int32_t DataLinkCapabilityUpdated(const HDI::Ril::V1_1::DataLinkCapability &dataLinkCapability);
    bool IsDataRespOrNotify(uint32_t code);
    int32_t GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetLinkBandwidthInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::DataLinkBandwidthInfo &iDataLinkBandwidthInfo);
    int32_t SetLinkBandwidthReportingRule(
        LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetLinkBandwidthReportingRuleResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SetDataPermitted(const int32_t dataPermitted, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetDataPermittedResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetLinkCapability(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetLinkCapabilityResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::DataLinkCapability &dataLinkCapability);
    int32_t CleanAllConnections(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t CleanAllConnectionsResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);

private:
    bool IsDataResponse(uint32_t code);
    bool IsDataNotification(uint32_t code);
    void BuildDataCallResultList(std::shared_ptr<DataCallResultList> dataCallResultList,
        const HDI::Ril::V1_1::DataCallResultList &iDataCallResultList);
    void BuildDataCallResultInfo(std::shared_ptr<SetupDataCallResultInfo> dataCallResult,
        const HDI::Ril::V1_1::SetupDataCallResultInfo &iSetupDataCallResultInfo);
    void BuildDataLinkBandwidthInfo(std::shared_ptr<DataLinkBandwidthInfo> dataLinkBandwidthInfo,
        const HDI::Ril::V1_1::DataLinkBandwidthInfo &iDataLinkBandwidthInfo);

private:
    std::mutex responseErrorLock_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_DATA_H
