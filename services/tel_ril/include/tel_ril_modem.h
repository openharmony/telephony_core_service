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

#ifndef TEL_RIL_MODEM_H
#define TEL_RIL_MODEM_H

#include "hril_modem_parcel.h"
#include "tel_ril_base.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class TelRilModem : public TelRilBase {
public:
    TelRilModem(int32_t slotId, sptr<HDI::Ril::V1_3::IRil> rilInterface,
        std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler);
    ~TelRilModem() = default;

    int32_t SetRadioStateResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetRadioStateResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t state);
    int32_t ShutDown(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t ShutDownResponse(const HDI::Ril::V1_1::RilRadioResponseInfo responseInfo);
    int32_t RadioStateUpdated(int32_t state);
    int32_t VoiceRadioTechUpdated(const HDI::Ril::V1_1::VoiceRadioTechnology &voiceRadioTechnology);
    int32_t DsdsModeUpdated(int32_t mode);
    int32_t SetRadioState(int32_t fun, int32_t rst, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetRadioState(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetImei(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetImeiSv(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetMeid(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetBasebandVersion(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetImeiResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &imei);
    int32_t GetImeiSvResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &imeiSv);
    int32_t GetMeidResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &meid);
    int32_t GetVoiceRadioTechnologyResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::VoiceRadioTechnology &voiceRadioTechnology);
    int32_t GetBasebandVersionResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &basebandVersion);
    int32_t OnRilAdapterHostDied();

public:
    ModemPowerState radioState_ = ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE;

private:
    void BuildVoiceRadioTechnology(const HDI::Ril::V1_1::VoiceRadioTechnology &voiceRadioTechnology,
        std::shared_ptr<VoiceRadioTechnology> &mVoiceRadioTechnology);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_MODEM_H
