/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "tel_ril_callback.h"

namespace OHOS {
namespace Telephony {
TelRilCallback::TelRilCallback(std::shared_ptr<TelRilManager> telRilManager) : telRilManager_(telRilManager) {}
int32_t TelRilCallback::SetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilCall(responseInfo.slotId).SetEmergencyCallListResponse(responseInfo);
}

int32_t TelRilCallback::GetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilCall(responseInfo.slotId)
        .GetEmergencyCallListResponse(responseInfo, emergencyInfoList);
}

int32_t TelRilCallback::CallEmergencyNotice(int32_t slotId, const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilCall(slotId).CallEmergencyNotice(emergencyInfoList);
}

int32_t TelRilCallback::PdpContextListUpdated(
    int32_t slotId, const HDI::Ril::V1_0::IDataCallResultList &dataCallResultList)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilData(slotId).PdpContextListUpdated(dataCallResultList);
}

int32_t TelRilCallback::ActivatePdpContextResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ISetupDataCallResultInfo &setupDataCallResultInfo)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilData(responseInfo.slotId)
        .ActivatePdpContextResponse(responseInfo, setupDataCallResultInfo);
}

int32_t TelRilCallback::DeactivatePdpContextResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilData(responseInfo.slotId).DeactivatePdpContextResponse(responseInfo);
}

int32_t TelRilCallback::GetPdpContextListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IDataCallResultList &dataCallResultList)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilData(responseInfo.slotId)
        .GetPdpContextListResponse(responseInfo, dataCallResultList);
}

int32_t TelRilCallback::SetInitApnInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilData(responseInfo.slotId).SetInitApnInfoResponse(responseInfo);
}

int32_t TelRilCallback::SetLinkBandwidthReportingRuleResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilData(responseInfo.slotId).SetLinkBandwidthReportingRuleResponse(responseInfo);
}

int32_t TelRilCallback::GetLinkBandwidthInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IDataLinkBandwidthInfo &dataLinkBandwidthInfo)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilData(responseInfo.slotId)
        .GetLinkBandwidthInfoResponse(responseInfo, dataLinkBandwidthInfo);
}

int32_t TelRilCallback::SetDataPermittedResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR :telRilManager_ is nullptr ");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return telRilManager_->GetTelRilData(responseInfo.slotId).SetDataPermittedResponse(responseInfo);
}
} // namespace Telephony
} // namespace OHOS
