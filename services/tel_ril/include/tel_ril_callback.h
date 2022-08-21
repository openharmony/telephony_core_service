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

#ifndef TEL_RIL_CALLBACK_H
#define TEL_RIL_CALLBACK_H

#include <v1_0/iril_interface.h>

#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
class TelRilCallback : public HDI::Ril::V1_0::IRilCallback {
public:
    explicit TelRilCallback(std::shared_ptr<TelRilManager> telRilManager);
    ~TelRilCallback() = default;

    int32_t SetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList) override;
    int32_t CallEmergencyNotice(int32_t slotId, const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList) override;

    int32_t PdpContextListUpdated(
        int32_t slotId, const HDI::Ril::V1_0::IDataCallResultList &dataCallResultList) override;
    int32_t ActivatePdpContextResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISetupDataCallResultInfo &setupDataCallResultInfo) override;
    int32_t DeactivatePdpContextResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetPdpContextListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IDataCallResultList &dataCallResultList) override;
    int32_t SetInitApnInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t SetLinkBandwidthReportingRuleResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;
    int32_t GetLinkBandwidthInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IDataLinkBandwidthInfo &dataLinkBandwidthInfo) override;
    int32_t SetDataPermittedResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo) override;

private:
    std::shared_ptr<TelRilManager> telRilManager_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_CALLBACK_H
